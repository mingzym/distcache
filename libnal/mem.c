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
#define IN_MEM_C

#include <libnal/common.h>

#if SYS_DEBUG_LEVEL > 2

void *nal_malloc(size_t size)
{ return malloc(size); }

void *nal_realloc(void *ptr, size_t size)
{ return realloc(ptr, size); }

void nal_free(void *ptr)
{ free(ptr); }

void *nal_memset(void *s, int c, size_t n)
{ return memset(s, c, n); }

void *nal_memcpy(void *dest, const void *src, size_t n)
{ return memcpy(dest, src, n); }

void *nal_memmove(void *dest, const void *src, size_t n)
{ return memmove(dest, src, n); }

#endif
