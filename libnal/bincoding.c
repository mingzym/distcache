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

/*
 * ENCODED BINARY HANDLING
 *
 * These decode_*** functions are to extract different kinds of primitives from
 * a binary string. They alter the binary pointer and length counter as they go
 * from invocation to the next, so that in the event of there being too little
 * data, an error can be caught.
 */
int NAL_decode_uint32(const unsigned char **bin, unsigned int *bin_len,
		unsigned long *val)
{
	if(*bin_len < 4)
		return 0;
	*val =  (unsigned long)(*((*bin)++)) << 24;
	*val += (unsigned long)(*((*bin)++)) << 16;
	*val += (unsigned long)(*((*bin)++)) << 8;
	*val += (unsigned long)(*((*bin)++));
	*bin_len -= 4;
	return 1;
}

int NAL_decode_uint16(const unsigned char **bin, unsigned int *bin_len,
		unsigned int *val)
{
	if(*bin_len < 2)
		return 0;
	*val = (unsigned long)*((*bin)++) << 8;
	*val += (unsigned long)*((*bin)++);
	*bin_len -= 2;
	return 1;
}

int NAL_decode_char(const unsigned char **bin, unsigned int *bin_len,
		unsigned char *c)
{
	if(*bin_len < 1)
		return 0;
	*c = *((*bin)++);
	*bin_len -= 1;
	return 1;
}

int NAL_decode_bin(const unsigned char **bin, unsigned int *bin_len,
		unsigned char *val, unsigned int val_len)
{
	if(*bin_len < val_len)
		return 0;
	if(val_len == 0)
		return 1;
	NAL_memcpy_n(unsigned char, val, *bin, val_len);
	*bin += val_len;
	*bin_len -= val_len;
	return 1;
}

/*
 * These encode_*** functions deal with serialising primitive C types into a
 * contiguous binary stream.
 */
int NAL_encode_uint32(unsigned char **bin, unsigned int *cnt,
		const unsigned long val)
{
	if(*cnt < 4) {
#if NAL_DEBUG_LEVEL > 3
		if(NAL_stderr()) NAL_fprintf(NAL_stderr(), "encode_uint32: overflow\n");
#endif
		return 0;
	}
	*((*bin)++) = (unsigned char)((val >> 24) & 0x0FF);
	*((*bin)++) = (unsigned char)((val >> 16) & 0x0FF);
	*((*bin)++) = (unsigned char)((val >> 8) & 0x0FF);
	*((*bin)++) = (unsigned char)(val & 0x0FF);
	*cnt -= 4;
	return 1;
}

int NAL_encode_uint16(unsigned char **bin, unsigned int *cnt,
		const unsigned int val)
{
	if(*cnt < 2) {
#if NAL_DEBUG_LEVEL > 3
		if(NAL_stderr()) NAL_fprintf(NAL_stderr(), "encode_uint16: overflow\n");
#endif
		return 0;
	}
	*((*bin)++) = (unsigned char)((val >> 8) & 0x0FF);
	*((*bin)++) = (unsigned char)(val & 0x0FF);
	*cnt -= 2;
	return 1;
}

int NAL_encode_char(unsigned char **bin, unsigned int *cnt,
		const unsigned char c)
{
	if(*cnt < 1) {
#if NAL_DEBUG_LEVEL > 3
		if(NAL_stderr()) NAL_fprintf(NAL_stderr(), "encode_char: overflow\n");
#endif
		return 0;
	}
	*((*bin)++) = c;
	*cnt -= 1;
	return 1;
}

int NAL_encode_bin(unsigned char **bin, unsigned int *cnt,
		const unsigned char *data, const unsigned int len)
{
	if(*cnt < len) {
#if NAL_DEBUG_LEVEL > 3
		if(NAL_stderr()) NAL_fprintf(NAL_stderr(), "encode_bin: overflow\n");
#endif
		return 0;
	}
	NAL_memcpy_n(unsigned char, *bin, data, len);
	*bin += len;
	*cnt -= len;
	return 1;
}

