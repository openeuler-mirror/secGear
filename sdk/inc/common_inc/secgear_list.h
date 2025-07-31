/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * secGear is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef __SECGEAR_LIST_H__
#define __SECGEAR_LIST_H__

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _list_node_t {
    struct _list_node_t *prev;
    struct _list_node_t *next;
} list_node_t;

typedef list_node_t list_head_t;

/*
 * Initialize the linked list.
 */
static inline void list_init(list_node_t *head)
{
    head->prev = head;
    head->next = head;
}

/*
 * Add a new node to the front of the current node.
 */
static inline void list_add_before(list_node_t *new_node, list_node_t *cur_node)
{
    new_node->prev = cur_node->prev;
    new_node->next = cur_node;
    cur_node->prev->next = new_node;
    cur_node->prev = new_node;
}

/*
 * Add a new node after the current node
 */
static inline void list_add_after(list_node_t *new_node, list_node_t *cur_node)
{
    new_node->prev = cur_node;
    new_node->next = cur_node->next;
    cur_node->next = new_node;
    new_node->next->prev = new_node;
}

/*
 * Remove a node from list.
 */
static inline void list_remove(list_node_t *node)
{
    node->prev->next = node->next;
    node->next->prev = node->prev;
}

/*
 * Whether the linked list is empty.
 */
static inline bool list_is_empty(const list_head_t *head)
{
    return (head->prev == head) && (head->next == head);
}

#define list_entry(ptr, type, member) \
    ((type *)((unsigned long)(ptr) - (unsigned long)&((type *)0)->member))

#define list_for_each(cur, head) \
    for ((cur) = (head)->next; (cur) != (head); (cur) = (cur)->next)

#define list_for_each_safe(cur, tmp, head) \
    for ((cur) = (head)->next, (tmp) = (cur)->next; (cur) != (head); (cur) = (tmp), (tmp) = (cur)->next)


#ifdef __cplusplus
}
#endif

#endif
