/* distcache, Distributed Session Caching technology
 * Copyright (C) 2000-2002  Geoff Thorpe, and Cryptographic Appliances, Inc.
 *
 * This library is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; using version 2.1 of the License. The copyright holders
 * may elect to allow the application of later versions of the License to this
 * software, please contact the author (geoff@distcache.org) if you wish us to
 * review any later version released by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include <libnal/common.h>
#include <libnal/nal.h>
#include <distcache/dc_enc.h>

#include "private.h"

#define MULTIPLEXER_MAX_ITEMS 512

/* An internal-only type used to represent a multiplexer item */
typedef struct st_item_t {
	/* The multiplexer's uid (also the server's translated request_uid) */
	unsigned long m_uid;
	/* The client uid */
	unsigned long c_uid;
	/* The server uid */
	unsigned long s_uid;
	enum {
		ITEM_NORMAL,
		ITEM_CLIENT_DEAD,
		ITEM_SERVER_DEAD
	} state;
} item_t;

struct st_multiplexer_t {
	item_t items[MULTIPLEXER_MAX_ITEMS];
	unsigned int used;
	unsigned long uid_seed;
};

/***************************/
/* Internal-only functions */

static void int_remove(multiplexer_t *m, unsigned int idx)
{
	assert(idx < m->used);
	if(idx + 1 < m->used)
		/* We have to scroll items */
		SYS_memmove_n(item_t, m->items + idx, m->items + (idx + 1),
				m->used - (idx + 1));
	m->used--;
}

/**********************************/
/* Exported functions (private.h) */

multiplexer_t *multiplexer_new(void)
{
	multiplexer_t *m = SYS_malloc(multiplexer_t, 1);
	if(!m)
		return NULL;
	m->used = 0;
	m->uid_seed = 1;
	return m;
}

void multiplexer_free(multiplexer_t *m)
{
	SYS_free(multiplexer_t, m);
}

int multiplexer_run(multiplexer_t *m, clients_t *c, server_t *s,
			const struct timeval *now)
{
	if(server_is_active(s) && !server_to_clients(s, c, m, now))
		return 0;
	if(!clients_to_server(c, s, m, now))
		return 0;
	return 1;
}

void multiplexer_mark_dead_client(multiplexer_t *m, unsigned long client_uid)
{
	unsigned int loop = 0;
	item_t *item = m->items;
	while(loop < m->used) {
		if(item->state == ITEM_SERVER_DEAD)
			/* The item already had an orphaned server, now the
			 * client too! Just remove it. */
			int_remove(m, loop);
		else {
			item->state = ITEM_CLIENT_DEAD;
			loop++;
			item++;
		}
	}
}

void multiplexer_mark_dead_server(multiplexer_t *m, unsigned long server_uid,
			clients_t *c)
{
	unsigned int loop = 0;
	item_t *item = m->items;
	while(loop < m->used) {
		if(item->s_uid == server_uid) {
			if(item->state != ITEM_CLIENT_DEAD)
				/* So the client's waiting for a response it
				 * will never get. Give it one. */
				clients_digest_error(c, item->c_uid);
			/* Either way, the multiplexer item should now be
			 * removed. */
			int_remove(m, loop);
		} else {
			/* This item is unaffected, move to the next one */
			loop++;
			item++;
		}
	}
}

int multiplexer_has_space(multiplexer_t *m)
{
	return (m->used < MULTIPLEXER_MAX_ITEMS);
}

unsigned long multiplexer_add(multiplexer_t *m, unsigned long client_uid,
			unsigned long server_uid)
{
	item_t *item = m->items + m->used;

	assert(m->used < MULTIPLEXER_MAX_ITEMS);
	item->m_uid = m->uid_seed++;
	item->c_uid = client_uid;
	item->s_uid = server_uid;
	item->state = ITEM_NORMAL;
	m->used++;
	return item->m_uid;
}

void multiplexer_delete_item(multiplexer_t *m, unsigned long m_uid)
{
	/* Search in reverse because this is most commonly used to remove a
	 * just-added item because the server couldn't accept it (after the
	 * m_uid had been chosen). */
	unsigned int loop = m->used;
	item_t *item = m->items + loop;
	while(loop--) {
		item--;
		if(item->m_uid == m_uid) {
			int_remove(m, loop);
			return;
		}
	}
	assert(NULL == "shouldn't happen!");
}

void multiplexer_finish(multiplexer_t *m, clients_t *c, unsigned long uid,
			DC_CMD cmd, const unsigned char *data,
			unsigned int data_len)
{
	/* Find the matching item */
	unsigned int loop = 0;
	item_t *item = m->items;
	while(loop < m->used) {
		if(item->m_uid == uid)
			goto found;
		loop++;
		item++;
	}
	assert(NULL == "shouldn't happen!");
	return;
found:
	/* If the client had disappeared since having its request forwarded,
	 * just silently absorb the response. */
	if(item->state != ITEM_CLIENT_DEAD)
		clients_digest_response(c, item->c_uid, cmd, data, data_len);
	int_remove(m, loop);
}
