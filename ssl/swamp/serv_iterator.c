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

#include "swamp.h"

/* This type represents a "cursor" to iterate over a dist_pattern */
struct st_server_iterator {
	dist_pattern *p;
	unsigned int idx;
};

/*****************************/
/* server_iterator functions */
/*****************************/

server_iterator *server_iterator_new(dist_pattern *p)
{
	server_iterator *c = SYS_malloc(server_iterator, 1);
	if(!c)
		return NULL;

	/* Grab a reference to the dist_pattern */
	dist_pattern_up(p);

	c->p = p;
	c->idx = dist_pattern_get_start_idx(p);

	return c;
}

void server_iterator_free(server_iterator *c)
{
	/* Drop our reference to the pattern */
	dist_pattern_free(c->p);
	SYS_free(server_iterator, c);
}

const NAL_ADDRESS *server_iterator_next(server_iterator *c)
{
	/* Get the index of the item in the pattern we want */
	unsigned int idx = c->idx;

	/* Adjust the index so next time it points to the next item in the
	 * pattern */
	if(++(c->idx) >= dist_pattern_period(c->p))
		c->idx = 0;

	/* Return the 'idx'th server in the pattern to the caller. */
	return dist_pattern_get(c->p, idx);
}

