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

static int int_sockaddr_size(int address_type)
{
	switch(address_type) {
	case NAL_ADDRESS_TYPE_IP:
		return sizeof(struct sockaddr_in);
#ifndef WIN32
	case NAL_ADDRESS_TYPE_UNIX:
		return sizeof(struct sockaddr_un);
#endif
	default:
		break;
	}
	/* for now at least, should *never* happen */
	abort();
	/* return 0; */
}

/**********************/
/* nal_sock functions */
/**********************/

int nal_sock_set_nagle(int fd, int use_nagle)
{
#ifndef WIN32
	if(use_nagle)
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

void nal_sock_sockaddr_from_ipv4(nal_sockaddr *addr, unsigned char *ip,
				unsigned short port)
{
	struct sockaddr_in in_addr;

	in_addr.sin_family = AF_INET;
	if(ip == NULL)
		in_addr.sin_addr.s_addr = INADDR_ANY;
	else
		SYS_memcpy_n(unsigned char,
			(unsigned char *)&in_addr.sin_addr.s_addr, ip, 4);
	in_addr.sin_port = htons(port);
	/* Now sandblast the sockaddr_in structure onto the sockaddr structure
	 * (which one hopes is greater than or equal to it in size :-). */
	SYS_zero(nal_sockaddr, addr);
	SYS_memcpy(struct sockaddr_in, &addr->val_in, &in_addr);
}

#ifndef WIN32
void nal_sock_sockaddr_from_unix(nal_sockaddr *addr, const char *start_ptr)
{
	struct sockaddr_un un_addr;

	un_addr.sun_family = AF_UNIX;
	SYS_strncpy(un_addr.sun_path, start_ptr, UNIX_PATH_MAX);
	/* Now sandblast the sockaddr_un structure onto the sockaddr structure
	 * (which one hopes is greater than or equal to it in size :-). */
	SYS_zero(nal_sockaddr, addr);
	SYS_memcpy(struct sockaddr_un, &addr->val_un, &un_addr);
}
#endif

int nal_sock_create_socket(int *fd, int type)
{
	switch(type) {
	case NAL_ADDRESS_TYPE_IP:
		*fd = socket(PF_INET, SOCK_STREAM, 0);
		break;
#ifndef WIN32
	case NAL_ADDRESS_TYPE_UNIX:
		*fd = socket(PF_UNIX, SOCK_STREAM, 0);
		break;
#endif
	default:
		/* Should never happen */
		abort();
	}
	if(*fd  == -1) {
#if SYS_DEBUG_LEVEL > 1
		SYS_fprintf(SYS_stderr, "Error, can't create socket\n\n");
#endif
		return 0;
	}
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

int nal_sock_set_reuse(int fd)
{
	int reuseVal = 1;

	if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
			(char *)(&reuseVal), sizeof(reuseVal)) != 0) {
#if SYS_DEBUG_LEVEL > 1
		SYS_fprintf(SYS_stderr, "Error, couldn't set SO_REUSEADDR\n\n");
#endif
		return 0;
	}
	return 1;
}

int nal_sock_bind(int fd, const nal_sockaddr *addr, int address_type)
{
	socklen_t addr_size = int_sockaddr_size(address_type);
	nal_sockaddr tmp;

	SYS_memcpy(nal_sockaddr, &tmp, addr);
	if(bind(fd, (struct sockaddr *)&tmp, addr_size) != 0) {
#if SYS_DEBUG_LEVEL > 1
		SYS_fprintf(SYS_stderr, "Error, couldn't bind to the IP/Port\n\n");
#endif
		return 0;
	}
	return 1;
}

int nal_sock_connect(int fd, const nal_sockaddr *addr, int address_type,
			int *established)
{
	socklen_t addr_size = int_sockaddr_size(address_type);
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

int nal_sock_listen(int fd)
{
	if(listen(fd, NAL_LISTENER_BACKLOG) != 0) {
#if SYS_DEBUG_LEVEL > 1
		SYS_fprintf(SYS_stderr, "Error, couldn't listen on that IP/Port\n\n");
#endif
		return 0;
        }
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

