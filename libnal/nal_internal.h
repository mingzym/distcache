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
#ifndef HEADER_PRIVATE_NAL_INTERNAL_H
#define HEADER_PRIVATE_NAL_INTERNAL_H

#ifndef HEADER_LIBSYS_PRE_H
	#error "Must include libsys/pre.h prior to libnal/nal.h"
#endif

#ifndef HEADER_LIBNAL_NAL_H
	#error "Must include libnal/nal.h prior to libnal/nal_internal.h"
#endif

/*****************************************************/
/* NETWORK ABSTRACTION INTERNAL LIBRARY DECLARATIONS */
/*                                                   */
/* (1) internal utility functions                    */
/* (2) data "buffer" type and functions              */
/* (3) network wrapper types and functions           */
/*****************************************************/

/* Utility functions and types used inside libnal. Eventually these should be
 * hidden from API functions (only protocol implementations should require
 * them) but until that's organised, I'm putting everything here. */

/* Some platforms don't get socklen_t ... use int */
#ifndef socklen_t
#define socklen_t int
#endif

/* This is a dummy type used to ensure our "sockaddr" is big enough to store
 * whatever. I previously assumed "struct sockaddr" already was, but it turns
 * out (dammit) that;
 *     sizeof(struct sockaddr_un) > sizeof(struct sockaddr)
 */
typedef union {
	struct sockaddr_in val_in;
#ifndef WIN32
	struct sockaddr_un val_un;
#endif
} nal_sockaddr;

/***********/
/* util_fd */
/***********/

int nal_fd_make_non_blocking(int fd, int non_blocking);
int nal_fd_buffer_to_fd(NAL_BUFFER *buf, int fd, unsigned int max_send);
int nal_fd_buffer_from_fd(NAL_BUFFER *buf, int fd, unsigned int max_read);
void nal_fd_close(int *fd);

/***************/
/* util_socket */
/***************/

int nal_sock_set_nagle(int fd, int use_nagle);
void nal_sock_sockaddr_from_ipv4(nal_sockaddr *addr, unsigned char *ip,
			unsigned short port);
void nal_sock_sockaddr_from_unix(nal_sockaddr *addr, const char *start_ptr);
int nal_sock_create_socket(int *fd, int type);
int nal_sock_create_unix_pair(int sv[2]);
int nal_sock_set_reuse(int fd);
int nal_sock_bind(int fd, const nal_sockaddr *addr, int address_type);
int nal_sock_connect(int fd, const nal_sockaddr *addr, int address_type,
			int *established);
int nal_sock_listen(int fd);
int nal_sock_accept(int listen_fd, int *conn);

/****************************************/
/* NAL_BUFFER - implemented in buffer.c */
/****************************************/

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
#define nal_check_buffer_size(sz) (((sz) > NAL_BUFFER_MAX_SIZE) ? 0 : 1)

/* Builtin transport types */
typedef enum {
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
				   descriptors and just read and write
				   to the same buffer. */
	NAL_ADDRESS_TYPE_LAST	/* so that "NAL_ADDRESS_TYPE_LAST-1" is the
				   last valid type */
} NAL_PROTOCOL_TYPE;

#define NAL_LISTENER_BACKLOG	511
#define NAL_ADDRESS_MAX_STR_LEN	255
struct st_NAL_ADDRESS {
	/* This is the string we were parsed from. We don't change it, because
	 * if we decide to create a "canonical form", then, by definition, it
	 * could be generated on the fly. :-) */
	char str_form[NAL_ADDRESS_MAX_STR_LEN + 1];
	NAL_PROTOCOL_TYPE family;
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
	nal_sockaddr addr;
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
	/* Read and send buffers. */
	NAL_BUFFER *read, *send;
};

/********************************************/
/* NAL_SELECTOR - implemented in selector.c */
/********************************************/

#define SELECTOR_FLAG_READ	0x01
#define SELECTOR_FLAG_SEND	0x02
#define SELECTOR_FLAG_EXCEPT	0x04

/* set/unset operate on "to_select */
void nal_selector_fd_set(NAL_SELECTOR *sel, int fd, unsigned char flags);
void nal_selector_fd_unset(NAL_SELECTOR *sel, int fd);
/* test/clear operate on "last_selected" */
unsigned char nal_selector_fd_test(const NAL_SELECTOR *sel, int fd);
void nal_selector_fd_clear(NAL_SELECTOR *sel, int fd);

#endif /* !defined(HEADER_PRIVATE_NAL_INTERNAL_H) */
