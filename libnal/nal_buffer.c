/* distcache, Distributed Session Caching technology
 * Copyright (C) 2000-2003  Geoff Thorpe, and Cryptographic Appliances, Inc.
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

#define SYS_GENERATING_LIB

#include <libsys/pre.h>
#include <libnal/nal.h>
#include "nal_internal.h"
#include <libsys/post.h>

/* Define the NAL_BUFFER structure */

struct st_NAL_BUFFER {
	unsigned char *data;
	unsigned int used, size;
};

/********************/
/* BUFFER FUNCTIONS */
/********************/

NAL_BUFFER *NAL_BUFFER_new(void)
{
	NAL_BUFFER *b = SYS_malloc(NAL_BUFFER, 1);
	if(b) {
		b->data = NULL;
		b->used = b->size = 0;
	}
	return b;
}

void NAL_BUFFER_free(NAL_BUFFER *b)
{
	if(b->data) SYS_free(unsigned char, b->data);
	SYS_free(NAL_BUFFER, b);
}

void NAL_BUFFER_reset(NAL_BUFFER *b)
{
	b->used = 0;
}

int NAL_BUFFER_set_size(NAL_BUFFER *buf, unsigned int size)
{
	unsigned char *next;

	/* Saves time, and avoids the degenerate case that fails realloc -
	 * namely when ptr is NULL (realloc becomes malloc) *and* size is 0
	 * (realloc becomes free). */
	if(size == buf->size)
		return 1;
	if(!nal_check_buffer_size(size)) {
#if SYS_DEBUG_LEVEL > 1
		SYS_fprintf(SYS_stderr, "Error, NAL_BUFFER_set_size() called with too "
				"large a size\n");
#endif
		return 0;
	}
	next = SYS_realloc(unsigned char, buf->data, size);
	if(size && !next)
		return 0;
	buf->data = next;
	buf->size = size;
	buf->used = 0;
	return 1;
}

int NAL_BUFFER_empty(const NAL_BUFFER *buf)
{
	return (buf->used == 0);
}

int NAL_BUFFER_full(const NAL_BUFFER *buf)
{
	return (buf->used == buf->size);
}

int NAL_BUFFER_notempty(const NAL_BUFFER *buf)
{
	return (buf->used > 0);
}

int NAL_BUFFER_notfull(const NAL_BUFFER *buf)
{
	return (buf->used < buf->size);
}

unsigned int NAL_BUFFER_used(const NAL_BUFFER *buf)
{
	return buf->used;
}

unsigned int NAL_BUFFER_unused(const NAL_BUFFER *buf)
{
	return (buf->size - buf->used);
}

const unsigned char *NAL_BUFFER_data(const NAL_BUFFER *buf)
{
	return buf->data;
}

unsigned int NAL_BUFFER_size(const NAL_BUFFER *buf)
{
	return buf->size;
}

unsigned int NAL_BUFFER_write(NAL_BUFFER *buf, const unsigned char *ptr,
		                unsigned int size)
{
	unsigned int towrite = NAL_BUFFER_unused(buf);
	if(towrite > size)
		towrite = size;
	if(towrite == 0)
		return 0;
	SYS_memcpy_n(unsigned char, buf->data + buf->used, ptr, towrite);
	buf->used += towrite;
	return towrite;
}

unsigned int NAL_BUFFER_read(NAL_BUFFER *buf, unsigned char *ptr,
		                unsigned int size)
{
	unsigned int toread = NAL_BUFFER_used(buf);
	if(toread > size)
		toread = size;
	if(toread == 0)
		return 0;
	if(ptr)
		SYS_memcpy_n(unsigned char, ptr, buf->data, toread);
	buf->used -= toread;
	if(buf->used > 0)
		SYS_memmove_n(unsigned char, buf->data,
				buf->data + toread, buf->used);
	return toread;
}

unsigned char *NAL_BUFFER_write_ptr(NAL_BUFFER *buf)
{
	return (buf->data + buf->used);
}

void NAL_BUFFER_wrote(NAL_BUFFER *buf, unsigned int size)
{
	assert(size <= NAL_BUFFER_unused(buf));
	buf->used += size;
}
