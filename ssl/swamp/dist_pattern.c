/* distcache, Distributed Session Caching technology
 * Copyright (C) 2000-2003  Geoff Thorpe, and Cryptographic Appliances, Inc.
 * Copyright (C) 2004       The Distcache.org project
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

#include "swamp.h"

/*************/
/* Constants */
/*************/

/* Do we do reference count debugging on dist_pattern? */
/* #define REF_DEBUG */

/* Maximum number of servers we store in a list */
#define MAX_SERVERS 1000 /* XXX arbitary */

/* Maximum number of server distribution patterns to allow. */
#define MAX_DISTRIBUTE_PATTERNS 1000 /* XXX arbitary */

/******************************/
/* Un-opaque our opaque types */
/******************************/

/* This type represents the pattern and order of servers to swamp */
struct st_dist_pattern {
	NAL_ADDRESS *items[MAX_SERVERS];
	unsigned int num;
	unsigned int idx[MAX_DISTRIBUTE_PATTERNS];
	unsigned int period;
	unsigned int references;
	unsigned int start_idx;
};

/**************************/
/* dist_pattern functions */
/**************************/

/* A function used in the distribute_cursor code to "get" a reference to an
 * existing pattern. */
void dist_pattern_up(dist_pattern *p)
{
	(p->references)++;
#ifdef REF_DEBUG
	printf("REF_DEBUG: dist_pattern_up(%08x), ref count now %u\n",
			(unsigned int)p, p->references);
#endif
}

/* Create/initialise a distribution_pattern structure ready for use */
dist_pattern *dist_pattern_new(void)
{
	dist_pattern *p = SYS_malloc(dist_pattern, 1);
	if(!p)
		return NULL;
	p->num = 0;
	p->period = 0;
	p->references = 1;
	p->start_idx = 0;
#ifdef REF_DEBUG
	printf("REF_DEBUG: dist_pattern_new(%08x), ref count now %u\n",
			(unsigned int)p, p->references);
#endif
	return p;
}

void dist_pattern_free(dist_pattern *p)
{
	(p->references)--;
#ifdef REF_DEBUG
	printf("REF_DEBUG: dist_pattern_free(%08x), ref count now %u\n",
			(unsigned int)p, p->references);
#endif
	if(p->references < 0) {
		assert(NULL == "shouldn't happen!");
		abort();
	} else if(p->references == 0)
		SYS_free(dist_pattern, p);
}

unsigned int dist_pattern_get_start_idx(dist_pattern *p)
{
	unsigned int toret = p->start_idx++;
	if(p->start_idx >= p->period)
		p->start_idx = 0;
	return toret;
}

/* Return the number of entires in the distribution pattern structure */
unsigned int dist_pattern_period(dist_pattern *dist)
{
	return dist->period;
}

/* Return the number of servers in the distribution pattern structure */
unsigned int dist_pattern_num(dist_pattern *dist)
{
	return dist->num;
}

/* Return the address of the server corresponding to the "idx"th entry in the
 * distribution pattern, or NULL for error */
const NAL_ADDRESS *dist_pattern_get(const dist_pattern *dist,
					unsigned int idx)
{
	if(idx >= dist->period)
		return NULL;
	return dist->items[dist->idx[idx]];
}

/* Parses an "<hostname>:<port>" string address and places it on the top of a
 * server_list stack */
int dist_pattern_push_address(dist_pattern *dist, const char *address)
{
	NAL_ADDRESS *sa;

	if((dist->num >= MAX_SERVERS) || ((sa = NAL_ADDRESS_new()) == NULL))
		return 0;
	if(!NAL_ADDRESS_create(sa, address, SWAMP_BUFFER_SIZE)) {
		NAL_ADDRESS_free(sa);
		return 0;
	}
	/* Parsing went OK, add this server address to our list */
	dist->items[dist->num++] = sa;
	return 1;
}

static dist_pattern_error_t dist_pattern_push(dist_pattern *dist,
					unsigned int val)
{
	/* Is there room in the array? */
	if(dist->period >= MAX_DISTRIBUTE_PATTERNS)
		return ERR_DIST_PAT_ARRAY_FULL;

	/* 'val' must between 1 and (dist->num) */
	if(!val || (val > dist->num))
		return ERR_DIST_PAT_VALUE_OUT_OF_RANGE;

	/* Everything checks out - place the server number at the end of the
	 * array. Note that we reduce the value by one as internally, servers
	 * are numbered from 0 onwards. */
	dist->idx[dist->period++] = val - 1;

	return ERR_DIST_PAT_OKAY;
}
		
/* Parse a distribution pattern string. The format is a bunch of values
 * representing server numbers delimited by spaces and/or commas. e.g.
 *     "1, 2, 3, 4,5 6 7 8,"
 *
 * Values are expected to between "1" and the number of servers. If something
 * fails, a suitable error code is returned (see also
 * dist_pattern_error_string()).
 *
 * An empty string is valid - a canonical pattern is generated from the server
 * list (if there 5 servers, a pattern of "1,2,3,4,5" is assumed). */
dist_pattern_error_t dist_pattern_parse(dist_pattern *dist,
				const char *dist_str)
{
	char *res;
	unsigned long val;
	tokeniser_t tok;
	dist_pattern_error_t ret = ERR_DIST_PAT_OKAY;

	assert(dist);

	/* If 'dist_str' is NULL, generate a canonical pattern */
	if(!dist_str) {
		unsigned int loop = 0;
		while(loop < dist->num) {
			ret = dist_pattern_push(dist, ++loop);
			if(ret != ERR_DIST_PAT_OKAY)
				return ret;
		}
		return ret;
	}

	/* Now process the (non-NULL) 'dist_str' */
	init_tokeniser(&tok, dist_str, ", ");
	while((res = do_tokenising(&tok)) != NULL) {
		if(!int_substrtoul(res, &val, ", ")) {
			ret = ERR_DIST_PAT_INVALID_SYNTAX;
			break;
		}
		ret = dist_pattern_push(dist, val);
		if(ret != ERR_DIST_PAT_OKAY)
			break;
	}
	free_tokeniser(&tok);
	return ret;
}

/* Return a string briefly describing the problem reported by "err". N.B.
 * this will also return something for "ERR_DIST_PAT_OKAY" which could confuse
 * people; e.g. "error with distribute pattern: no error".
 *
 * This function is guaranteed to return a valid string (even if it is empty).
 */
const char *dist_pattern_error_string(dist_pattern_error_t err)
{
	switch(err) {
	case ERR_DIST_PAT_OKAY:
		return "no error";
	case ERR_DIST_PAT_VALUE_OUT_OF_RANGE:
		return "value out of range";
	case ERR_DIST_PAT_INVALID_SYNTAX:
		return "invalid syntax";
	case ERR_DIST_PAT_ARRAY_FULL:
		return "distribute pattern array is full";
	case ERR_DIST_PAT_INTERNAL_PROBLEM:
		return "internal error (a bug?)";
	}
	/* Return something */
	return "";
}
