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

static int int_always_one = 1; /* used in setsockopt() */
/* Solaris (among possibly many platforms) doesn't know what SOL_TCP is, we need
 * to use getprotobyname() to find it. The result is stored here. */
static int sol_tcp = -1;

/*****************************/
/* Internal socket functions */
/*****************************/

static int int_sockaddr_size(const nal_sockaddr *addr)
{
	switch(addr->type) {
	case nal_sockaddr_type_ip:
		return sizeof(struct sockaddr_in);
#ifndef WIN32
	case nal_sockaddr_type_unix:
		return sizeof(struct sockaddr_un);
#endif
	default:
		break;
	}
	/* for now at least, should *never* happen */
	abort();
	/* return 0; */
}

static int int_sock_set_reuse(int fd, const nal_sockaddr *addr)
{
	int reuseVal = 1;
	if(addr->type != nal_sockaddr_type_ip)
		return 1;
	if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
			(char *)(&reuseVal), sizeof(reuseVal)) != 0)
		return 0;
	return 1;
}

static int int_sock_bind(int fd, const nal_sockaddr *addr)
{
	socklen_t addr_size = int_sockaddr_size(addr);
	nal_sockaddr tmp;

	if(addr->type == nal_sockaddr_type_unix)
		/* Stevens' book says do it, so I do. Unfortunately - this
		 * actually needs additional file-locking to prevent one
		 * application stealing another's listener (without him
		 * noticing it's gone even!). */
		unlink(addr->val.val_un.sun_path);
	SYS_memcpy(nal_sockaddr, &tmp, addr);
	if(bind(fd, (struct sockaddr *)&tmp, addr_size) != 0)
		return 0;
	return 1;
}

/**********************/
/* nal_sock functions */
/**********************/

int nal_sock_set_nagle(int fd, int use_nagle, nal_sockaddr_type type)
{
#ifndef WIN32
	if(use_nagle || (type != nal_sockaddr_type_ip))
		return 1;

	if(sol_tcp == -1) {
		struct protoent *p = getprotobyname("tcp");
		if(!p) {
#if SYS_DEBUG_LEVEL > 1
			SYS_fprintf(SYS_stderr, "Error, couldn't obtain SOL_TCP\n");
#endif
			return 0;
		}
		sol_tcp = p->p_proto;
	}

	if(setsockopt(fd, sol_tcp, TCP_NODELAY, &int_always_one,
			sizeof(int_always_one)) != 0) {
#if SYS_DEBUG_LEVEL > 1
		SYS_fprintf(SYS_stderr, "Error, couldn't disable Nagle algorithm\n");
#endif
		return 0;
	}
#endif
	return 1;
}

int nal_sock_sockaddr_from_ipv4(nal_sockaddr *addr, const char *start_ptr)
{
	char *tmp_ptr;
	char *fini_ptr;
	struct hostent *ip_lookup;
	/* struct sockaddr_in in_addr; */
	unsigned long in_ip_piece;
	unsigned char in_ip[4];
	int no_ip = 0;

	addr->caps = 0;
	/* We're an IPv4 address, and start_ptr points to the first character
	 * of the address part */
	if(strlen(start_ptr) < 1) return 0;
	/* Logic: if our string contains another ":" we assume it's of the form
	 * nnn.nnn.nnn.nnn:nnn, otherwise assume IP[v4]:nnn. Exception,
	 * if it's of the form IP[v4]::nnn, we treat it as equivalent to one
	 * colon. */
	if(((fini_ptr = strstr(start_ptr, ":")) == NULL) ||
			(start_ptr == fini_ptr)) {
		/* No colon, skip the IP address - this is listen-only */
		no_ip = 1;
		/* If it's a double colon, we need to increment start_ptr */
		if(fini_ptr)
			start_ptr++;
		goto ipv4_port;
	}
	/* Create a temporary string for the isolated hostname/ip-address */
	tmp_ptr = SYS_malloc(char, (int)(fini_ptr - start_ptr) + 1);
	if(!tmp_ptr)
		return 0;
	SYS_memcpy_n(char, tmp_ptr, start_ptr,
		(int)(fini_ptr - start_ptr));
	tmp_ptr[(int)(fini_ptr - start_ptr)] = '\0';
	ip_lookup = gethostbyname(tmp_ptr);
	SYS_free(char, tmp_ptr);
	if(!ip_lookup)
		/* Host not understood or recognised */
		return 0;
	/* Grab the IP address and move on (h_addr_list[0] is signed char?!) */
	SYS_memcpy_n(char, (char *)in_ip, ip_lookup->h_addr_list[0], 4);
	/* Align start_ptr to the start of the "port" number. */
	start_ptr = fini_ptr + 1;
	/* Ok, this is an address that could be used for connecting */
	addr->caps |= NAL_ADDRESS_CAN_CONNECT;

ipv4_port:
	if(strlen(start_ptr) < 1)
		return 0;
	/* start_ptr points to the first character of the port part */
	in_ip_piece = strtoul(start_ptr, &fini_ptr, 10);
	if((in_ip_piece > 65535) || (*fini_ptr != '\0'))
		return 0;
	/* populate the sockaddr_in structure */
	addr->val.val_in.sin_family = AF_INET;
	if(no_ip)
		addr->val.val_in.sin_addr.s_addr = INADDR_ANY;
	else
		SYS_memcpy_n(unsigned char,
			(unsigned char *)&addr->val.val_in.sin_addr.s_addr, in_ip, 4);
	addr->val.val_in.sin_port = htons((unsigned short)in_ip_piece);
	/* ipv4 addresses are always good for listening */
	addr->caps |= NAL_ADDRESS_CAN_LISTEN;
	addr->type = nal_sockaddr_type_ip;
	return 1;
}

#ifndef WIN32
int nal_sock_sockaddr_from_unix(nal_sockaddr *addr, const char *start_ptr)
{
	struct sockaddr_un un_addr;

	un_addr.sun_family = AF_UNIX;
	SYS_strncpy(un_addr.sun_path, start_ptr, UNIX_PATH_MAX);
	/* Now sandblast the sockaddr_un structure onto the sockaddr structure
	 * (which one hopes is greater than or equal to it in size :-). */
	SYS_zero(nal_sockaddr, addr);
	SYS_memcpy(struct sockaddr_un, &addr->val.val_un, &un_addr);
	addr->type = nal_sockaddr_type_unix;
	addr->caps = NAL_ADDRESS_CAN_LISTEN | NAL_ADDRESS_CAN_CONNECT;
	return 1;
}
#endif

int nal_sock_create_socket(int *fd, const nal_sockaddr *addr)
{
	int tmp_fd = -1;
	switch(addr->type) {
	case nal_sockaddr_type_ip:
		tmp_fd = socket(PF_INET, SOCK_STREAM, 0);
		break;
#ifndef WIN32
	case nal_sockaddr_type_unix:
		tmp_fd = socket(PF_UNIX, SOCK_STREAM, 0);
		break;
#endif
	default:
		/* Should never happen */
		abort();
	}
	if(tmp_fd < 0) {
#if SYS_DEBUG_LEVEL > 1
		SYS_fprintf(SYS_stderr, "Error, can't create socket\n\n");
#endif
		return 0;
	}
	*fd = tmp_fd;
	return 1;
}

#ifndef WIN32
int nal_sock_create_unix_pair(int sv[2])
{
	if(socketpair(PF_UNIX, SOCK_STREAM, 0, sv) != 0) {
#if SYS_DEBUG_LEVEL > 1
		SYS_fprintf(SYS_stderr, "Error, can't create socketpair\n\n");
#endif
		return 0;
	}
	return 1;
}
#endif

int nal_sock_connect(int fd, const nal_sockaddr *addr,
			int *established)
{
	socklen_t addr_size = int_sockaddr_size(addr);
	nal_sockaddr tmp;

	SYS_memcpy(nal_sockaddr, &tmp, addr);
	if(connect(fd, (struct sockaddr *)&tmp, addr_size) != 0) {
#ifdef WIN32
		if(WSAGetLastError() != WSAEWOULDBLOCK)
#else
		if(errno != EINPROGRESS)
#endif
		{
#if SYS_DEBUG_LEVEL > 1
			SYS_fprintf(SYS_stderr, "Error, couldn't connect\n\n");
#endif
			return 0;
		}
		/* non-blocking connect ... connect() succeeded, but it may yet
		 * fail without a single byte going anywhere. */
		*established = 0;
	} else
		*established = 1;
	return 1;
}

int nal_sock_listen(int fd, const nal_sockaddr *addr)
{
	if(!int_sock_set_reuse(fd, addr) || !int_sock_bind(fd, addr))
		return 0;
	if(listen(fd, NAL_LISTENER_BACKLOG) != 0)
		return 0;
	return 1;
}

int nal_sock_accept(int listen_fd, int *conn)
{
	if((*conn = accept(listen_fd, NULL, NULL)) == -1) {
#if SYS_DEBUG_LEVEL > 1
		SYS_fprintf(SYS_stderr, "Error, accept failed\n\n");
#endif
		return 0;
	}
	return 1;
}

int nal_sock_is_connected(int fd)
{
	int t;
	socklen_t t_len = sizeof(t);
	/* the ugly cast is necessary with my system headers to avoid warnings,
	 * but there's probably a reason and/or autoconf things to do with
	 * this. */
	if((getsockopt(fd, SOL_SOCKET, SO_ERROR, &t,
			(unsigned int *)&t_len) != 0) || (t != 0))
		return 0;
	return 1;
}

