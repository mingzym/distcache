/* distcache, Distributed Session Caching technology
 * Copyright (C) 2000-2004  Geoff Thorpe, and Cryptographic Appliances, Inc.
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

int nal_fd_make_non_blocking(int fd, int non_blocking)
{
#ifdef WIN32
	u_long dummy = 1;
	if(ioctlsocket(fd, FIONBIO, &dummy) != 0)
		return 0;
	return 1;
#else
	int flags;

	if(((flags = fcntl(fd, F_GETFL, 0)) < 0) ||
			(fcntl(fd, F_SETFL, (non_blocking ?
			(flags | O_NONBLOCK) : (flags & ~O_NONBLOCK))) < 0)) {
#if SYS_DEBUG_LEVEL > 1
		SYS_fprintf(SYS_stderr, "Error, couldn't make socket non-blocking.\n");
#endif
		return 0;
	}
	return 1;
#endif
}

int nal_fd_buffer_to_fd(NAL_BUFFER *buf, int fd, unsigned int max_send)
{
	ssize_t ret;
	unsigned int buf_used = NAL_BUFFER_used(buf);

	/* Decide the maximum we should send */
	if((max_send == 0) || (max_send > buf_used))
		max_send = buf_used;
	/* If there's nothing to send, don't waste a system call. This catches
	 * the case of a non-blocking connect that completed, without adding
	 * NAL_BUFFER_*** calls one level up. */
	if(!max_send)
		return 0;
#ifdef WIN32
	ret = send(fd, NAL_BUFFER_data(buf), max_send, 0);
#else
	ret = write(fd, NAL_BUFFER_data(buf), max_send);
#endif
#if 0
	ret = send(fd, NAL_BUFFER_data(buf), max_send,
		MSG_DONTWAIT | MSG_NOSIGNAL);
#endif
	/* There's a couple of "soft errors" we don't consider fatal */
	if(ret < 0) {
		switch(errno) {
		case EAGAIN:
		case EINTR:
			return 0;
		default:
			break;
		}
		return -1;
	}
	if(ret > 0) {
		unsigned int uret = (unsigned int)ret;
		/* Scroll the buffer forward */
		NAL_BUFFER_read(buf, NULL, uret);
#if SYS_DEBUG_LEVEL > 1
		SYS_fprintf(SYS_stderr, "Debug: net.c (fd=%d) sent %lu bytes\n",
			fd, (unsigned long)uret);
#endif
	}
	return ret;
}

int nal_fd_buffer_from_fd(NAL_BUFFER *buf, int fd, unsigned int max_read)
{
	ssize_t ret;
	unsigned int buf_avail = NAL_BUFFER_unused(buf);

	/* Decide the maximum we should read */
	if((max_read == 0) || (max_read > buf_avail))
		max_read = buf_avail;
	/* If there's no room for reading, don't waste a system call */
	if(!max_read)
		return 0;
#ifdef WIN32
	ret = recv(fd, NAL_BUFFER_write_ptr(buf), max_read, 0);
#else
	ret = read(fd, NAL_BUFFER_write_ptr(buf), max_read);
#endif
#if 0
	ret = recv(fd, NAL_BUFFER_write_ptr(buf), max_read, MSG_NOSIGNAL);
#endif
	/* There's a couple of "soft errors" we don't consider fatal */
	if(ret < 0) {
		switch(errno) {
		case EINTR:
		case EAGAIN:
			return 0;
		default:
			break;
		}
		return -1;
	}
	if(ret > 0) {
		unsigned int uret = (unsigned int)ret;
		NAL_BUFFER_wrote(buf, uret);
#if SYS_DEBUG_LEVEL > 1
		SYS_fprintf(SYS_stderr, "Debug: net.c (fd=%d) received %lu bytes\n",
			fd, (unsigned long)uret);
#endif
	}
	return ret;
}

/* A handy little simple function that removes loads of lines of code from
 * elsewhere. */
void nal_fd_close(int *fd)
{
	if(*fd > -1)
#ifdef WIN32
		closesocket(*fd);
#else
		close(*fd);
#endif
	*fd = -1;
}
