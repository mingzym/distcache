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
#ifndef HEADER_PRIVATE_SESSCLIENT_H
#define HEADER_PRIVATE_SESSCLIENT_H

/* All this code is for building/linking an executable */
#define SYS_GENERATING_EXE

/* Save space in the C files... */
#include <libsys/pre.h>
#include <libnal/nal.h>
#include <distcache/dc_plug.h>
#include <distcache/dc_internal.h>
#include <libsys/post.h>

/* Some debugging symbols ... */

/* Define this symbol if you want client connections and disconnections
 * (together with the number of total client connections that leaves) to be
 * printed to stdout. */
/* #define CLIENTS_PRINT_CONNECTS */

/* Predeclare "black-box" structures */
typedef struct st_clients_t	clients_t;
typedef struct st_server_t	server_t;
typedef struct st_multiplexer_t	multiplexer_t;

/* client functions */
clients_t *clients_new(void);
void clients_free(clients_t *c);
void clients_to_selector(clients_t *c, NAL_SELECTOR *sel);
int clients_io(clients_t *c, NAL_SELECTOR *sel, multiplexer_t *m,
			const struct timeval *now,
			unsigned long idle_timeout);
int clients_new_client(clients_t *c, NAL_CONNECTION *conn,
			const struct timeval *now);
int clients_to_server(clients_t *c, server_t *s, multiplexer_t *m,
			const struct timeval *now);
/* semi-static client functions - not called from sclient.c */
void clients_digest_response(clients_t *c, unsigned long client_uid,
				DC_CMD cmd,
				const unsigned char *data,
				unsigned int data_len);
void clients_digest_error(clients_t *c, unsigned long client_uid);

/* server functions */
server_t *server_new(const char *address, unsigned long retry_msecs,
			const struct timeval *now);
void server_free(server_t *s);
void server_to_selector(server_t *s, NAL_SELECTOR *sel, multiplexer_t *m,
			clients_t *c, const struct timeval *now);
int server_io(server_t *s, NAL_SELECTOR *sel, multiplexer_t *m,
			clients_t *c, const struct timeval *now);
int server_to_clients(server_t *s, clients_t *c, multiplexer_t *m,
			const struct timeval *now);
int server_place_request(server_t *s, unsigned long uid, DC_CMD cmd,
			const unsigned char *data, unsigned int data_len);
int server_is_active(server_t *s);
unsigned long server_get_uid(server_t *s);

/* multiplexer functions */
multiplexer_t *multiplexer_new(void);
void multiplexer_free(multiplexer_t *m);
int multiplexer_run(multiplexer_t *m, clients_t *c, server_t *s,
			const struct timeval *now);
void multiplexer_mark_dead_client(multiplexer_t *m, unsigned long client_uid);
void multiplexer_mark_dead_server(multiplexer_t *m, unsigned long server_uid,
			clients_t *c);
int multiplexer_has_space(multiplexer_t *m);
unsigned long multiplexer_add(multiplexer_t *m, unsigned long client_uid,
			unsigned long server_uid);
void multiplexer_delete_item(multiplexer_t *m, unsigned long m_uid);
void multiplexer_finish(multiplexer_t *m, clients_t *c, unsigned long uid,
			DC_CMD cmd, const unsigned char *data,
			unsigned int data_len);

#endif /* !defined(HEADER_PRIVATE_SESSCLIENT_H) */
