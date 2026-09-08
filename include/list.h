#ifndef LIST_H
#define LIST_H

#include <stddef.h>

struct sepp_list {
    struct sepp_list *next;
    struct sepp_list *prev;
};

#define SEPP_LIST_HEAD_INIT(name) { &(name), &(name) }

#define SEPP_LIST_HEAD(name) \
    struct sepp_list name = SEPP_LIST_HEAD_INIT(name)

static inline void sepp_list_init(struct sepp_list *list)
{
    list->next = list;
    list->prev = list;
}

static inline int sepp_list_empty(const struct sepp_list *head)
{
    return head->next == head;
}

static inline void sepp_list_add_between(struct sepp_list *node,
                                         struct sepp_list *prev,
                                         struct sepp_list *next)
{
    next->prev = node;
    node->next = next;
    node->prev = prev;
    prev->next = node;
}

static inline void sepp_list_add(struct sepp_list *node,
                                 struct sepp_list *head)
{
    sepp_list_add_between(node, head, head->next);
}

static inline void sepp_list_add_tail(struct sepp_list *node,
                                      struct sepp_list *head)
{
    sepp_list_add_between(node, head->prev, head);
}

static inline void sepp_list_del(struct sepp_list *node)
{
    node->next->prev = node->prev;
    node->prev->next = node->next;
    sepp_list_init(node);
}

#define sepp_container_of(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof(type, member)))

#define sepp_list_entry(ptr, type, member) \
    sepp_container_of(ptr, type, member)

#define sepp_list_first_entry(ptr, type, member) \
    sepp_list_entry((ptr)->next, type, member)

#define sepp_list_for_each(pos, head) \
    for (pos = (head)->next; pos != (head); pos = pos->next)

#define sepp_list_for_each_safe(pos, n, head) \
    for (pos = (head)->next, n = pos->next; pos != (head); \
         pos = n, n = pos->next)

#endif
