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
#include <libdistcache/dc_enc.h>
#include <libdistcacheserver/dc_server.h>

/* If you define DC_CACHE_DEBUG, the cached-lookup code in this default
 * implementation will have extra debugging; it will print to stdout each time
 * either "cached_removes", "cached_hits", or "cached_misses" hits a multiple of
 * DC_CACHE_DEBUG_INTERVAL. */
/* #define DC_CACHE_DEBUG */
/* #define DC_CACHE_DEBUG_INTERVAL	100 */

/******************************************/
/* The "DC_CACHE" structure details */

/* stores a single cache item */
typedef struct st_DC_ITEM {
	/* The time at which we will expire this session (calculated locally -
	 * the client sends us a number of milli-seconds, and the server adds
	 * that to the local time when the "add" operation is processed). */
	struct timeval expiry;
	/* The length of the session_id and the encoded session respectively */
	unsigned int id_len, data_len;
	/* A block of memory containing the session_id followed by the encoded
	 * session. */
	unsigned char *ptr;
} DC_ITEM;

struct st_DC_CACHE {
	/* Our session storage */
	DC_ITEM *items;
	unsigned int items_used, items_size;
	unsigned int expire_delta;
	/* Cached lookups. Mostly used so that a call to "DC_CACHE_get" with a
	 * NULL 'store' (to find the size of the session to be copied before
	 * finding room to copy it to) followed by another call with a non-NULL
	 * 'store' doesn't do two searches. It also helps if an "add" operation
	 * is followed immediately by a "get" or "remove". */
	unsigned char cached_id[DC_MAX_ID_LEN];
	unsigned int cached_id_len;
	int cached_idx; /* -1 means a cached lookup for a session that doesn't
			   exist (so, don't bother looking) */
};

/**********************************************************/
/* Internal functions to manage the "cached_lookup" stuff */

#ifdef DC_CACHE_DEBUG
#ifndef DC_CACHE_DEBUG_INTERVAL
#error "Error, must define DC_CACHE_DEBUG_INTERVAL when DC_CACHE_DEBUG is defined"
#endif
static unsigned int cached_removes = 0;
static unsigned int cached_misses = 0;
static unsigned int cached_hits = 0;

#define CACHED_REMOVE {if((++cached_removes % DC_CACHE_DEBUG_INTERVAL) == 0) \
		NAL_fprintf(NAL_stdout(), "DC_CACHE_DEBUG: cached_removes = %u\n", \
				cached_removes); }
#define CACHED_MISS {if((++cached_misses % DC_CACHE_DEBUG_INTERVAL) == 0) \
		NAL_fprintf(NAL_stdout(), "DC_CACHE_DEBUG: cached_misses = %u\n", \
				cached_misses); }
#define CACHED_HIT {if((++cached_hits % DC_CACHE_DEBUG_INTERVAL) == 0) \
		NAL_fprintf(NAL_stdout(), "DC_CACHE_DEBUG: cached_hits = %u\n", \
				cached_hits); }
#else
#define CACHED_REMOVE
#define CACHED_MISS
#define CACHED_HIT
#endif

/* 'num' entries have been scrolled off the front of the cache, take the
 * appropriate action with the cached-lookup */
static void int_lookup_expired(DC_CACHE *cache, unsigned int num)
{
	/* Was the cached index in the first 'num' items? */
	if(cache->cached_idx < num) {
		/* Yes, so cache the fact the session has gone */
		cache->cached_idx = -1;
		CACHED_REMOVE
	} else
		/* No, so it's still alive */
		cache->cached_idx -= num;
}

/* A specific index in the cache has been removed - check if this affects the
 * cached-lookup. */
static void int_lookup_removed(DC_CACHE *cache, unsigned int idx)
{
	if(cache->cached_idx == idx) {
		cache->cached_idx = -1;
		CACHED_REMOVE
	} else if(cache->cached_idx > idx)
		cache->cached_idx--;
}

/* This function is to use the cached-lookup prior to doing an actual search */
static int int_lookup_check(DC_CACHE *cache,
			const unsigned char *session_id,
			unsigned int session_id_len,
			unsigned int *idx)
{
	if((session_id_len != cache->cached_id_len) ||
			(memcmp(session_id, cache->cached_id,
				session_id_len) != 0)) {
		CACHED_MISS
		return 0;
	}
	*idx = cache->cached_idx;
	CACHED_HIT
	return 1;
}

/* An operation (eg. an 'add', a 'remove', or a 'find' for something that wasn't
 * already cached) wants to specify a session to cache (or to mark the absence
 * of any session corresponding to a given id). */
static void int_lookup_set(DC_CACHE *cache,
			const unsigned char *session_id,
			unsigned int session_id_len,
			unsigned int idx)
{
	cache->cached_id_len = session_id_len;
	if(session_id_len)
		NAL_memcpy_n(unsigned char, cache->cached_id,
				session_id, session_id_len);
	cache->cached_idx = idx;
}

/**************************************************************/
/* Internal functions to manage the session items in a server */

static void int_pre_remove_DC_ITEM(DC_ITEM *item)
{
	NAL_free(unsigned char, item->ptr);
	item->ptr = NULL;
}

static void int_force_expire(DC_CACHE *cache, unsigned int num)
{
	assert((num > 0) && (num <= cache->items_used));
	/* Only "memmove" if we're not expiring everything */
	if(num < cache->items_used)
		NAL_memmove_n(DC_ITEM, cache->items, cache->items + num,
				cache->items_used - num);
	cache->items_used -= num;
	/* How does this affect cached lookups? */
	int_lookup_expired(cache, num);
}

static void int_expire(DC_CACHE *cache, const struct timeval *now)
{
	unsigned int idx = 0, toexpire = 0;
	DC_ITEM *item = cache->items;
	while((idx < cache->items_used) && (NAL_timecmp(now,
				&(item->expiry)) > 0)) {
		/* Do pre-remove cleanup but don't do the remove, this is
		 * because we can do one giant scroll in int_force_expire()
		 * rather than lots of little ones by calling
		 * int_remove_DC_ITEM(), for example. */
		int_pre_remove_DC_ITEM(item);
		idx++;
		item++;
		toexpire++;
	}
	if(toexpire)
		int_force_expire(cache, toexpire);
}

static int int_find_DC_ITEM(DC_CACHE *cache, const unsigned char *ptr,
				unsigned int len, const struct timeval *now)
{
	unsigned int idx = 0;
	DC_ITEM *item = cache->items;
	/* First flush out expired entries */
	int_expire(cache, now);
	/* See if we have a lookup for this session cached */
	if(int_lookup_check(cache, ptr, len, &idx))
		/* Yes! */
		return idx;
	while(idx < cache->items_used) {
		if((item->id_len == len) && (memcmp(item->ptr, ptr, len) == 0))
			goto cache_and_return;
		idx++;
		item++;
	}
	idx = -1;
cache_and_return:
	int_lookup_set(cache, ptr, len, idx);
	return idx;
}

static int int_add_DC_ITEM(DC_CACHE *cache, unsigned int idx,
		const struct timeval *expiry,
		const unsigned char *session_id, unsigned int session_id_len,
		const unsigned char *data, unsigned int data_len)
{
	unsigned char *ptr;
	/* Use 'idx' to search for the insertion point based on 'expiry' */
	DC_ITEM *item;

	/* So we'll definitely insert - take care of the one remaining error
	 * possibility first, malloc. */
	ptr = NAL_malloc(unsigned char, session_id_len + data_len);
	if(!ptr)
		return 0;
	item = cache->items + idx;
	/* Do we need to shuffle existing items? */
	if(idx < cache->items_used)
		/* This is a genuine insertion rather than an append */
		NAL_memmove_n(DC_ITEM, item + 1, item,
				cache->items_used - idx);
	/* Populate the entry */
	NAL_timecpy(&item->expiry, expiry);
	item->ptr = ptr;
	item->id_len = session_id_len;
	item->data_len = data_len;
	NAL_memcpy_n(unsigned char, item->ptr, session_id, session_id_len);
	NAL_memcpy_n(unsigned char, item->ptr + item->id_len, data, data_len);
	cache->items_used++;
	/* Cache this item as a lookup */
	int_lookup_set(cache, session_id, session_id_len, idx);
	return 1;
}

static void int_remove_DC_ITEM(DC_CACHE *cache, unsigned int idx)
{
	DC_ITEM *item = cache->items + idx;
	int_pre_remove_DC_ITEM(item);
	if(idx + 1 < cache->items_used)
		NAL_memmove_n(DC_ITEM, cache->items + idx,
				cache->items + (idx + 1),
				cache->items_used - (idx + 1));
	cache->items_used--;
	int_lookup_removed(cache, idx);
}

/*********************************************************/
/* Our high-level cache implementation handler functions */

static DC_CACHE *cache_new(unsigned int max_sessions)
{
	DC_CACHE *toret;
	if((max_sessions < DC_CACHE_MIN_SIZE) ||
			(max_sessions > DC_CACHE_MAX_SIZE))
		return NULL;
	toret = NAL_malloc(DC_CACHE, 1);
	if(!toret)
		return NULL;
	toret->items = NAL_malloc(DC_ITEM, max_sessions);
	if(!toret->items) {
		NAL_free(DC_CACHE, toret);
		return NULL;
	}
	toret->items_used = 0;
	toret->items_size = max_sessions;
	/* Choose a "delta" for forced expiries. When making room for new
	 * sessions (ie. when full), how many do we force out at a time? */
	toret->expire_delta = max_sessions / 30;
	if(!toret->expire_delta)
		toret->expire_delta = 1;
	/* Make sure we have no weird cached-lookup state */
	int_lookup_set(toret, NULL, 0, -1);
	return toret;
}

static void cache_free(DC_CACHE *cache)
{
	while(cache->items_used)
		int_remove_DC_ITEM(cache, cache->items_used - 1);
	NAL_free(DC_ITEM, cache->items);
	NAL_free(DC_CACHE, cache);
}

static int cache_add_session(DC_CACHE *cache,
			const struct timeval *now,
			unsigned long timeout_msecs,
			const unsigned char *session_id,
			unsigned int session_id_len,
			const unsigned char *data,
			unsigned int data_len)
{
	/* Use 'idx' to search for the insertion point based on 'expiry' */
	DC_ITEM *item;
	int idx;
	struct timeval expiry;

	/* The caller should already be making these checks */
	assert(session_id_len && data_len &&
			(session_id_len <= DC_MAX_ID_LEN) &&
			(data_len <= DC_MAX_DATA_LEN));
	/* Check if we already have this session (NB: this also flushes expired
	 * sessions out automatically). */
	idx = int_find_DC_ITEM(cache, session_id, session_id_len, now);
	if(idx >= 0)
		return 0;
	/* Do we need to forcibly expire entries to make room? */
	if(cache->items_used == cache->items_size)
		/* Yes, make room. We clear out 'expire_delta' sessions from the
		 * front of the queue. If this value is one we get logical
		 * behaviour but it's inefficient (we keep scrolling the entire
		 * array to the left one space). If it's greater than one, it's
		 * a little unfair on some extra sessions (expiring them when
		 * it's not strictly necessary), but we don't do nearly as many
		 * memmove() operations. */
		int_force_expire(cache, cache->expire_delta);
	/* Set the time that the new session will expire */
	NAL_timeadd(&expiry, now, timeout_msecs);
	/* Find the insertion point based on expiry time */
	idx = cache->items_used;
	item = cache->items + idx;
	while(idx > 0)  {
		idx--;
		item--;
		/* So, if 'item' will expiry before or at the same time, we can
		 * insert immediately after it. */
		if(NAL_timecmp(&item->expiry, &expiry) <= 0) {
			idx++;
			item++;
			goto found;
		}
	}
	/* So, strangely, this item expires before all others (in reality, we're
	 * probably inserting into an empty list!). But because of the "idx++"
	 * logic, 'idx' and 'item' match the insertion/append point in all cases
	 * at this point. */
found:
	return int_add_DC_ITEM(cache, idx, &expiry, session_id,
					session_id_len, data, data_len);
}

static unsigned int cache_get_session(DC_CACHE *cache,
			const struct timeval *now,
			const unsigned char *session_id,
			unsigned int session_id_len,
			unsigned char *store,
			unsigned int store_len)
{
	DC_ITEM *item;
	unsigned int idx = int_find_DC_ITEM(cache,
			session_id, session_id_len, now);
	if(idx < 0)
		return 0;
	item = cache->items + idx;
	if(store) {
		unsigned int towrite = item->data_len;
		assert(store_len > 0); /* no reason to accept store_len == 0 */
		if(towrite > store_len)
			towrite = store_len;
		NAL_memcpy_n(unsigned char, store,
			item->ptr + item->id_len, towrite);
	}
	return item->data_len;
}

static int cache_remove_session(DC_CACHE *cache,
			const struct timeval *now,
			const unsigned char *session_id,
			unsigned int session_id_len)
{
	int idx = int_find_DC_ITEM(cache, session_id, session_id_len, now);
	if(idx < 0)
		return 0;
	int_remove_DC_ITEM(cache, idx);
	return 1;
}

static int cache_have_session(DC_CACHE *cache,
			const struct timeval *now,
			const unsigned char *session_id,
			unsigned int session_id_len)
{
	return (int_find_DC_ITEM(cache, session_id,
				session_id_len, now) < 0 ? 0 : 1);
}

static unsigned int cache_items_stored(DC_CACHE *cache,
			const struct timeval *now)
{
	/* sneak in a quick flush of expired items. This actually makes this API
	 * function a convenient (low-overhead) way for the application to flush
	 * the cache. */
	int_expire(cache, now);
	return cache->items_used;
}

/********************************************/
/* The only external function in this file! */

/* First the static structure used in this hook function */
static const DC_CACHE_cb our_implementation = {
	cache_new,
	cache_free,
	cache_add_session,
	cache_get_session,
	cache_remove_session,
	cache_have_session,
	cache_items_stored
};

int DC_SERVER_set_default_cache(void)
{
	return DC_SERVER_set_cache(&our_implementation);
}
