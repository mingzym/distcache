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
#ifndef HEADER_DISTCACHE_DC_SERVER_H
#define HEADER_DISTCACHE_DC_SERVER_H

/* Boundaries on input. Function callers should observe these limits as the
 * functions often test these with assert() statements (so they disapper in
 * non-debug builds, and in debug builds they blow up error situations rather
 * suddenly). */

/* The minimum/maximum size of a cache (in terms of sessions). NB: the maximum
 * allows for a cache that will be over 8Mb, even if filled with small sessions.
 * If filled with large sessions, this could be much larger still. */
#define DC_CACHE_MIN_SIZE		64
#define DC_CACHE_MAX_SIZE		60000
/* The maximum number of milli-seconds we let sessions live for */
#define DC_MAX_EXPIRY			(unsigned long)604800000 /* 7 days */
/* The largest session object we allow. For SSL/TLS, if architectures encode
 * peer certificates raw into sessions (rather than clipping them to the
 * essentials) and client certs start containing photos or mpegs, this might be
 * a problem. Otherwise it should be more than enough! */
#define DC_MAX_DATA_LEN			32768

/* Our black-box types */
typedef struct st_DC_SERVER DC_SERVER;
typedef struct st_DC_CLIENT DC_CLIENT;
typedef struct st_DC_CACHE  DC_CACHE;

/* This structure holds the "cache" implementation. It allows callers to provide
 * their own form of cache storage (or otherwise, in the case of proxies). */
typedef struct st_DC_CACHE_cb {
	DC_CACHE *	(*cache_new)(unsigned int max_sessions);
	void		(*cache_free)(DC_CACHE *cache);
	int		(*cache_add)(DC_CACHE *cache,
				const struct timeval *now,
				unsigned long timeout_msecs,
				const unsigned char *session_id,
				unsigned int session_id_len,
				const unsigned char *data,
				unsigned int data_len);
	/* If 'store' is NULL, this returns the length of a session without
	 * copying it. */
	unsigned int	(*cache_get)(DC_CACHE *cache,
				const struct timeval *now,
				const unsigned char *session_id,
				unsigned int session_id_len,
				unsigned char *store,
				unsigned int store_size);
	int		(*cache_remove)(DC_CACHE *cache,
				const struct timeval *now,
				const unsigned char *session_id,
				unsigned int session_id_len);
	int		(*cache_have)(DC_CACHE *cache,
				const struct timeval *now,
				const unsigned char *session_id,
				unsigned int session_id_len);
	unsigned int	(*cache_num_items)(DC_CACHE *cache,
				const struct timeval *now);
} DC_CACHE_cb;

/* Flags for use in DC_SERVER_new_client() */
#define DC_CLIENT_FLAG_NOFREE_CONN		(unsigned int)0x0001
#define DC_CLIENT_FLAG_IN_SERVER		(unsigned int)0x0002

/* Create a new session cache server. NB: DC_SERVER_set_[default_]cache()
 * must have been called prior to creating a server with this function. */
DC_SERVER *DC_SERVER_new(unsigned int max_sessions);

/* Destroy a session cache server (NB: all clients that aren't created with
 * DC_CLIENT_FLAG_IN_SERVER should be destroyed in advance). */
void DC_SERVER_free(DC_SERVER *ctx);

/* This function causes the builtin session cache implementation to be used in
 * all "DC_SERVER"s created. Implemented in sess_serve_cache.c, so that if
 * the following function is used rather than this one, the builtin cache
 * implementation won't be linked into the application. */
int DC_SERVER_set_default_cache(void);

/* This function causes a custom cache implementation to be used in all
 * "DC_SERVER"s created. */
int DC_SERVER_set_cache(const DC_CACHE_cb *impl);

/* Find out the number of session items currently stored in the server.
 * Automatically flushes expired cache items before deciding the result. */
unsigned int DC_SERVER_items_stored(DC_SERVER *ctx,
				const struct timeval *now);

/* Reset the server's counter of cache operations to zero. */
void DC_SERVER_reset_operations(DC_SERVER *ctx);

/* Count the number of cache operations (successful or otherwise) since the last
 * call to 'DC_SERVER_reset_operations'. */
unsigned long DC_SERVER_num_operations(DC_SERVER *ctx);

/* Create a new client for a server */
DC_CLIENT *DC_SERVER_new_client(DC_SERVER *ctx,
				NAL_CONNECTION *conn,
				unsigned int flags);

/* Remove a client from a server */
int DC_SERVER_del_client(DC_CLIENT *clnt);

/* Do logical processing of a client. A zero return value indicates a fatal
 * error (eg. data corruption) and that the client should be destroyed by the
 * caller. */
int DC_SERVER_process_client(DC_CLIENT *clnt,
				const struct timeval *now);

/* These functions are only useful for clients created with the
 * DC_CLIENT_FLAG_IN_SERVER flag. They handle networking operations on the list
 * of such clients, including closing and destroying dead client connections,
 * etc. */
int DC_SERVER_clients_to_sel(DC_SERVER *ctx, NAL_SELECTOR *sel);
int DC_SERVER_clients_io(DC_SERVER *ctx, NAL_SELECTOR *sel,
				const struct timeval *now);

#endif /* !defined(HEADER_DISTCACHE_DC_SERVER_H) */
