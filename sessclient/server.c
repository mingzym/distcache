/* distcache, Distributed Session Caching technology
 * Copyright (C) 2000-2004  Geoff Thorpe, and Cryptographic Appliances, Inc.
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

#include "private.h"

#define SERVER_BUFFER_SIZE	(sizeof(DC_MSG) * 8)

static unsigned long uid_seed = 1;

struct st_server_t {
	/* The unique ID we use w.r.t. multiplexing. This is set from an
	 * incremented counter each time we (re)connect. */
	unsigned long uid;
	/* The "plug" communicating with the server */
	DC_PLUG *plug;
	/* The prepared address for (re-)connecting to */
	NAL_ADDRESS *address;
	/* A timestamp for when the server last disconnected */
	struct timeval last_fail;
	/* How many milliseconds should pass before a reconnect is attempted */
	unsigned long retry_msecs;
};

/* Returns non-zero if a new plug was created (used for select logic) */
static int server_retry_util(server_t *s, const struct timeval *now)
{
	NAL_CONNECTION *conn;
	if(s->plug) return 0;
	if(!SYS_expirycheck(&s->last_fail, s->retry_msecs, now))
		return 0;
	/* OK, we try to reconnect */
	conn = NAL_CONNECTION_new();
	if(!conn) return 0;
	/* No matter what fails from here on, we'll update the timestamp */
	SYS_timecpy(&s->last_fail, now);
	if(!NAL_CONNECTION_create(conn, s->address) ||
			((s->plug = DC_PLUG_new(conn,
				DC_PLUG_FLAG_TO_SERVER)) == NULL)) {
		NAL_CONNECTION_free(conn);
		return 0;
	}
	s->uid = uid_seed++;
	return 1;
}

static void server_dead_util(server_t *s, multiplexer_t *m, clients_t *c,
			const struct timeval *now)
{
	DC_PLUG_free(s->plug);
	s->plug = NULL;
	SYS_timecpy(&s->last_fail, now);
	multiplexer_mark_dead_server(m, s->uid, c);
}

int server_is_active(server_t *s)
{
	return (s->plug ? 1 : 0);
}

unsigned long server_get_uid(server_t *s)
{
	return s->uid;
}

server_t *server_new(const char *address, unsigned long retry_msecs,
			const struct timeval *now)
{
	server_t *s = NULL;
	NAL_ADDRESS *a = NAL_ADDRESS_new();

	if(!a || !NAL_ADDRESS_create(a, address, SERVER_BUFFER_SIZE) ||
			!NAL_ADDRESS_can_connect(a))
		goto err;
	s = SYS_malloc(server_t, 1);
	if(!s)
		goto err;
	s->plug = NULL;
	s->address = a;
	s->retry_msecs = retry_msecs;
	/* Ensure the "last_fail" is set so that we'll attempt a connect on the
	 * very first attempt */
	SYS_timesub(&s->last_fail, now, retry_msecs + 1);
	/* We leave 's' unconnected, the first 'server_selector_hook' handles
	 * this and avoids duplication of code. */
	return s;
err:
	if(a)
		NAL_ADDRESS_free(a);
	return NULL;
}

void server_free(server_t *s)
{
	NAL_ADDRESS_free(s->address);
	if(s->plug)
		DC_PLUG_free(s->plug);
	SYS_free(server_t, s);
}

int server_selector_hook(server_t *s, NAL_SELECTOR *sel, const struct timeval *now)
{
	if(server_retry_util(s, now))
		return DC_PLUG_to_select(s->plug, sel);
	return 1;
}

int server_io(server_t *s, multiplexer_t *m, clients_t *c,
			const struct timeval *now)
{
	if(server_is_active(s) && !DC_PLUG_io(s->plug))
		server_dead_util(s, m, c, now);
	return 1;
}

int server_to_clients(server_t *s, clients_t *c, multiplexer_t *m,
			const struct timeval *now)
{
	unsigned long uid;
	DC_CMD cmd;
	const unsigned char *data;
	unsigned int len;
	assert(server_is_active(s)); /* shouldn't call this function otherwise */
	while(DC_PLUG_read(s->plug, 0, &uid, &cmd, &data, &len)) {
		multiplexer_finish(m, c, uid, cmd, data, len);
		DC_PLUG_consume(s->plug);
	}
	return 1;
}

int server_place_request(server_t *s, unsigned long uid, DC_CMD cmd,
			const unsigned char *data, unsigned int data_len)
{
	assert(server_is_active(s)); /* shouldn't call this function otherwise */
	if(!DC_PLUG_write(s->plug, 0, uid, cmd, data, data_len))
		return 0;
	if(!DC_PLUG_commit(s->plug)) {
		assert(NULL == "shouldn't happen!");
		/* Try the only thing we can */
		DC_PLUG_rollback(s->plug);
		return 0;
	}
	return 1;
}
