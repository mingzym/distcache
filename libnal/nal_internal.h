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
#ifndef HEADER_PRIVATE_NAL_INTERNAL_H
#define HEADER_PRIVATE_NAL_INTERNAL_H

#ifndef HEADER_LIBNAL_COMMON_H
#error "Must include libnal/common.h prior to libnal/nal.h"
#endif

#ifndef HEADER_LIBNAL_NAL_H
#error "Must include libnal/nal.h prior to libnal/nal_internal.h"
#endif


/*****************************************************/
/* NETWORK ABSTRACTION INTERNAL LIBRARY DECLARATIONS */
/*                                                   */
/* (1) data "buffer" type and functions              */
/* (2) network wrapper types and functions           */
/*****************************************************/

/* There's little point making data buffers bigger than this, but it can be
 * changed later if desired. To cut down latencies, buffers used for network IO
 * should only be big enough to ensure (a) "things fit", and (b) we can
 * aggregate as much data as possible into single "read"s and "sends" (rather
 * than sending multitudes of fragments. I strongly doubt it's possible to send
 * a IP packet as big as 32K, so why bother adding further to latency by letting
 * data-loops build up more than that before going back to the network code?
 * Anyway - it'll get changed if it's a problem ... for now it's a good check to
 * make sure the other code isn't too loose. */
#define NAL_BUFFER_MAX_SIZE  32768

struct st_NAL_BUFFER {
	unsigned char *_data;
	unsigned int _used, _size;
};

/* A dummy type used to ensure our "sockaddr" is big enough to store whatever. I
 * previously assumed it was, but it turns out that;
 * sizeof(struct sockaddr_un) > sizeof(struct sockaddr). Dammit. */
typedef union {
	struct sockaddr_in val_in;
#ifndef WIN32
	struct sockaddr_un val_un;
#endif
} sockaddr_safe;

#define NAL_LISTENER_BACKLOG	511
#define NAL_ADDRESS_MAX_STR_LEN	255
struct st_NAL_ADDRESS {
	/* This is the string we were parsed from. We don't change it, because
	 * if we decide to create a "canonical form", then, by definition, it
	 * could be generated on the fly. :-) */
	char str_form[NAL_ADDRESS_MAX_STR_LEN + 1];
	enum {
		NAL_ADDRESS_TYPE_NULL = 0,/* invalid */
		NAL_ADDRESS_TYPE_IP,	/* regular TCP/IP(v4) addressing */
		NAL_ADDRESS_TYPE_IPv4 = NAL_ADDRESS_TYPE_IP,
#if 0
		NAL_ADDRESS_TYPE_IPv6,	/* For the new IPv6 protocol family */
#endif
#ifndef WIN32
		NAL_ADDRESS_TYPE_UNIX,	/* For addressing in the file-system */
		NAL_ADDRESS_TYPE_PAIR,	/* For socket-pairs where there is no
					   real "address" as the end-points are
					   created together. */
#endif
		NAL_ADDRESS_TYPE_DUMMY, /* For connections that have no file-
					 * descriptors and just read and write
					 * to the same buffer. */
		NAL_ADDRESS_TYPE_LAST	/* so that "NAL_ADDRESS_TYPE_LAST-1" is the
					   last valid type */
	} family;
	/* The "caps" flag is a OR'd combination of the following; */
#define NAL_ADDRESS_CAN_LISTEN	(unsigned char)0x01
#define NAL_ADDRESS_CAN_CONNECT	(unsigned char)0x02
	unsigned char caps;
	/* If this is for a connect call, we can specify the default buffer size
	 * for the connection's read and send buffers here. If this is for a
	 * listen call, this setting will be used in connections created by
	 * "accepts" on the listener. */
	unsigned int def_buffer_size;
	/* The actual sockaddr, that should be interpreted as the correct
	 * sockaddr_something depending on "family". */
	sockaddr_safe addr;
};

struct st_NAL_LISTENER {
	/* The address we're listening on */
	NAL_ADDRESS addr;
	/* The underlying file-descriptor */
	int fd;
};

struct st_NAL_CONNECTION {
	/* The address we're connected to */
	NAL_ADDRESS addr;
	/* The underlying file-descriptor */
	int fd;
	/* A curious little entry. As most of the libnal code uses non-blocking
	 * sockets, there's no real way to determine if a "connect" really
	 * succeeded, or simply *started* successfully but is doomed because
	 * there's no server to connect to. This value gets set non-zero only
	 * when a real read or send on the file-descriptor has happened.
	 * However, if a connect *does* succed but the server sends no data and
	 * neither do we, then currently this value won't get set. It is used by
	 * the "NAL_CONNECTION_is_established()" function and should bear this
	 * quirk in mind. */
	int established;
	/* Read and send buffers */
	NAL_BUFFER read, send;
};

typedef struct _NAL_SELECTOR_item {
	fd_set reads;
	fd_set sends;
	fd_set excepts;
	int max;
} NAL_SELECTOR_item;

struct st_NAL_SELECTOR {
	/* The result of a select */
	NAL_SELECTOR_item last_selected;
	/* The list we're building up to select with next */
	NAL_SELECTOR_item to_select;
};

#endif /* !defined(HEADER_PRIVATE_NAL_INTERNAL_H) */
