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
#ifndef HEADER_LIBDISTCACHE_DC_CLIENT_H
#define HEADER_LIBDISTCACHE_DC_CLIENT_H

/* This is an "API" version - it will be bumped each time an API change is
 * introduced to this header. NB: This version number does not track changes to
 * the implementation of these functions that might affect binary or behavioural
 * compatibility. It merely provides a way for dependant source code to provide
 * pre-processing rules that ensure that source code is being compiled using an
 * acceptable version of the distcache API. */
#define DISTCACHE_CLIENT_API	0x0001

/* This is an "implementation" version - it will be bumped each time a change is
 * made that could affect binary compatibility with dependant libraries or a
 * behavioural change takes place that could affect interoperation. */
#define DISTCACHE_CLIENT_BINARY	0x0001

/* Our black-box type */
typedef struct st_DC_CTX DC_CTX;

/* Flags for use in DC_CTX_new() */
#define DC_CTX_FLAG_PERSISTENT		(unsigned int)0x0001
#define DC_CTX_FLAG_PERSISTENT_PIDCHECK	(unsigned int)0x0002
#define DC_CTX_FLAG_PERSISTENT_RETRY	(unsigned int)0x0004
#define DC_CTX_FLAG_PERSISTENT_LATE	(unsigned int)0x0008

/* The minimum allowable "timeout" (in milliseconds) of new sessions */
#define DC_MIN_TIMEOUT			500

/*****************/
/* API functions */

/* Create a new DC_CTX */
DC_CTX *DC_CTX_new(const char *target, unsigned int flags);
/* Destroy a DC_CTX */
void DC_CTX_free(DC_CTX *ctx);
/* Add (send) a new session object and its corresponding id to the cache */
int DC_CTX_add_session(DC_CTX *ctx,
			const unsigned char *id_data,
			unsigned int id_len,
			const unsigned char *sess_data,
			unsigned int sess_len,
			unsigned long timeout_msecs);
/* Remove a session from the cache given an id */
int DC_CTX_remove_session(DC_CTX *ctx,
			const unsigned char *id_data,
			unsigned int id_len);
/* Get (receive) a session from the cache given an id. */
int DC_CTX_get_session(DC_CTX *ctx,
			const unsigned char *id_data,
			unsigned int id_len,
			unsigned char *result_storage,
			unsigned int result_size,
			unsigned int *result_used);

/* Re"get"s a session immediately after a previous call to DC_CTX_get_session().
 * Used when DC_CTX_get_session() did not provide a sufficiently big 'result'
 * buffer. */
int DC_CTX_reget_session(DC_CTX *ctx,
			const unsigned char *id_data,
			unsigned int id_len,
			unsigned char *result_storage,
			unsigned int result_size,
			unsigned int *result_used);

/* Tests whether the cache has a session corresponding to a given id. */
int DC_CTX_has_session(DC_CTX *ctx,
			const unsigned char *id_data,
			unsigned int id_len);

#endif /* !defined(HEADER_LIBDISTCACHE_DC_CLIENT_H) */
