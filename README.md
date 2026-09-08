# seppd

A Linux implementation of a 3GPP TS 29.573 Security Edge Protection Proxy (SEPP).

Current status:

Phase 0
Project skeleton.

## Listener trust boundaries

`seppd` requires two inbound TLS listeners.  The listener that accepts a
connection establishes its initial trust class; request paths and HTTP
headers are not used to guess whether an unknown client is internal.

- `internal_sbi` accepts trusted same-PLMN NF or SCP traffic.  Connections
  accepted here are immediately classified as `internal-nf`.  NF and SCP
  share this inbound class because they use the same forwarding path.
- `external_n32` accepts peer-SEPP traffic.  Connections remain `unknown`
  until an N32-c request path classifies them as N32-c or the existing TLS
  certificate/N32-c-context correlation classifies them as N32-f.

Each listener has an independent certificate, private key, client-certificate
requirement, CA bundle, and optional external-certificate-verification flag.
The external N32 listener must require a client certificate.  Certificate
policy validation is delegated to the external certificate-verifier process
after the TLS handshake; production deployments must enable that verifier.

The top-level `tls` object is retained for outbound connections.  Listener TLS
settings inherit from it and can be overridden in each listener's `tls`
object.  The sample uses one CA bundle for test convenience; deployments may
configure different listener CA bundles when required by local PKI policy.

For deployments where internal authentication is implicit through NDS/IP or
physical isolation, `require_client_certificate` may be disabled only on the
`internal_sbi` listener.  In that case the listener address and surrounding
network controls become the security boundary.

## Live object counters

`seppd` maintains an atomic live counter for each independently allocated
SEPP runtime object type. Send `SIGUSR2` to the daemon to write all counters
to the normal log without stopping the process:

```sh
kill -USR2 $(pidof seppd)
```

The report includes peer contexts, connections, stream transactions, TLS
channels, HTTP/2 sessions, HTTP/2 streams, outgoing HTTP/2 bodies, and HTTP/2
headers, MIME parts, and MIME part headers. Configured peer contexts remain
live for the daemon lifetime; the other counters should return to their
expected steady-state values after traffic and connection teardown.

The counters cover objects allocated and owned by `seppd`. They do not count
internal allocations made by OpenSSL, nghttp2, or cJSON.

## N32-f target routing

`3gpp-Sbi-Target-apiRoot` identifies the ultimate NF or NRF, not the peer
SEPP used as the next hop.  Each `peer_sepp` target therefore has an explicit
`served_domains` list.  Internal requests are routed to the single peer whose
configured exact or `*.` suffix pattern matches the target-apiRoot FQDN; MCC
and MNC are not inferred from the name.

Inbound N32-f delivery is selected by `internal_routing.mode`.  In `direct`
mode, the target-apiRoot must exactly match a configured `nf` target and the
header is consumed before direct delivery.  In `scp` mode, `scp_target` names
the configured SCP next hop, the target-apiRoot header is preserved, and its
FQDN must first match `internal_routing.served_domains`.  This prevents the
SEPP from becoming an unintended relay to foreign destinations.

For TLS N32-f, the N32-c `3GppSbiTargetApiRootSupported` negotiation selects
the wire representation.  If both SEPPs support it, the request URI addresses
the receiving SEPP and the ultimate NF remains in `3gpp-Sbi-Target-apiRoot`.
Otherwise, the header is removed and the request URI authority identifies the
ultimate NF.  On receipt, the reverse rule is enforced from the peer context;
a header is rejected when it was not negotiated, and a missing header is
rejected when it was negotiated.

API roots in this release are limited to HTTPS authorities without an
operator-specific path prefix.  The resource path is forwarded unchanged.

## N32-f HTTP header forwarding

N32-f request and response forwarding preserves end-to-end HTTP fields,
including repeated fields.  `seppd` regenerates HTTP/2 pseudo-headers,
`content-length`, and the routing-controlled `3gpp-sbi-target-apiroot` field.
The existing content handling regenerates `content-type` and preserves
`content-encoding` together with the original representation.

Hop-by-hop and HTTP/2-incompatible fields are removed, as are fields named by
the `connection` header.  Proxy authentication fields are not propagated
across the SEPP.  `te` and `trailer` are reserved for a later commit that
implements HTTP trailer forwarding explicitly.

Received Via fields are preserved outside the generic forwarding filter and
the local SEPP appends `2.0 SEPP-<local_fqdn>` to every relayed N32-f request
and response.  An N32-f request that already contains the local SEPP FQDN in
Via is rejected with `400 MSG_LOOP_DETECTED`.  Locally originated N32-c
messages and locally generated error responses do not receive a Via field.

## Multipart inspection

After an HTTP message body is complete, `seppd` first decodes a top-level
gzip content coding and then parses `multipart/*` representations for local
inspection.  The original body and Content-Type are still forwarded without
MIME reserialization.  `struct sepp_msg` exposes `mime_parts` and
`mime_part_count`; each part provides copied MIME headers plus a binary-safe,
non-owning body span into the uncompressed inspection representation.

`sepp_mime_part_is_json()` recognizes `application/json` and application
media types with a `+json` structured syntax suffix.  MIME metadata and body
spans remain valid only during the message callback, matching the lifetime of
the HTTP/2 stream.  Multipart is accepted for N32-f and internal SBI traffic;
N32-c rejects multipart because the handshake operations use JSON bodies.

The parser requires canonical CRLF delimiters, rejects obsolete folded MIME
headers, and enforces limits of 64 parts, 64 headers per part, 64 KiB of
header text per part, and a 70-byte boundary.  Nested multipart and MIME
Content-Transfer-Encoding decoding are intentionally not performed.
