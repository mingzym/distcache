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

/* All our internal code will require the nal_devel.h header anyway, so include
 * it here. */
#include <libnal/nal_devel.h>

/* Utility functions and types used inside libnal. Eventually these should be
 * hidden from API functions (only protocol implementations should require
 * them) but until that's organised, I'm putting everything here. */

/* Some platforms don't get socklen_t ... use int */
#ifndef socklen_t
#define socklen_t int
#endif

/* Flags used in determining what "kind" of address has been created */
#define NAL_ADDRESS_CAN_LISTEN	(unsigned char)0x01
#define NAL_ADDRESS_CAN_CONNECT	(unsigned char)0x02

/* nal_sock code will use this as a default in its call to listen(2) */
#define NAL_LISTENER_BACKLOG	511

/* An upper limit on the size of address strings that will be allowable */
#define NAL_ADDRESS_MAX_STR_LEN	255

/* This nal_sockaddr stuff is to encapsulate unix domain and ipv4 socket
 * code. */
typedef enum {
	nal_sockaddr_type_ip,
	nal_sockaddr_type_unix
} nal_sockaddr_type;
typedef struct st_nal_sockaddr {
	union {
		struct sockaddr_in val_in;
#ifndef WIN32
		struct sockaddr_un val_un;
#endif
	} val;
	nal_sockaddr_type type;
	unsigned char caps;
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

int nal_sock_set_nagle(int fd, int use_nagle, nal_sockaddr_type type);
int nal_sock_sockaddr_from_ipv4(nal_sockaddr *addr, const char *start_ptr);
int nal_sock_sockaddr_from_unix(nal_sockaddr *addr, const char *start_ptr);
int nal_sock_create_socket(int *fd, const nal_sockaddr *addr);
int nal_sock_create_unix_pair(int sv[2]);
int nal_sock_connect(int fd, const nal_sockaddr *addr, int *established);
int nal_sock_listen(int fd, const nal_sockaddr *addr);
int nal_sock_accept(int listen_fd, int *conn);
int nal_sock_is_connected(int fd);
int nal_sockaddr_get(nal_sockaddr *addr, int fd);
int nal_sockaddr_chown(const nal_sockaddr *addr, const char *username,
			const char *groupname);
int nal_sockaddr_chmod(const nal_sockaddr *addr, const char *octal_string);

/****************/
/* NAL_SELECTOR */
/****************/

extern const NAL_SELECTOR_vtable sel_fdselect_vtable;

/****************/
/* NAL_LISTENER */
/****************/

unsigned int nal_listener_get_def_buffer_size(const NAL_LISTENER *l);
int nal_listener_set_def_buffer_size(NAL_LISTENER *l, unsigned int def_buffer_size);

/**************/
/* NAL_BUFFER */
/**************/

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

#endif /* !defined(HEADER_PRIVATE_NAL_INTERNAL_H) */
