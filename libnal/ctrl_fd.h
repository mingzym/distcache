/* distcache, Distributed Session Caching technology
 * Copyright (C) 2000-2003  Geoff Thorpe, and Cryptographic Appliances, Inc.
 * Copyright (C) 2004       The Distcache.org project
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
#ifndef HEADER_PRIVATE_CTRL_FD_H
#define HEADER_PRIVATE_CTRL_FD_H

#ifndef HEADER_LIBSYS_PRE_H
	#error "Must include libsys/pre.h prior to ctrl_fd.h"
#endif

/* Bitwise flags for fdset criteria */
#define SELECTOR_FLAG_READ	0x01
#define SELECTOR_FLAG_SEND	0x02
#define SELECTOR_FLAG_EXCEPT	0x04

/* The select/poll-specific selector "ctrl" commands are enumerated here */
typedef enum {
	NAL_FD_CTRL_FDSET = NAL_SELECTOR_CTRL_FD,
	NAL_FD_CTRL_FDTEST
} NAL_FD_CTRL_TYPE;

/* These are the corresponding structures passed to nal_selector_ctrl */
typedef struct st_nal_fd_fdset {
	/* Input value - token of listener/connection object */
	NAL_SELECTOR_TOKEN token;
	/* Input value - file-descriptor */
	int fd;
	/* Input value - critieria */
	unsigned char flags;
} NAL_FD_FDSET;
typedef struct st_nal_fd_fdtest {
	/* Return value - critieria */
	unsigned char flags;
	/* Input value - token of listener/connection object */
	NAL_SELECTOR_TOKEN token;
	/* Input value - file-descriptor */
	int fd;
} NAL_FD_FDTEST;

#define nal_selector_fd_set(_sel, _tok, _fd, _flags) \
	do { \
		NAL_FD_FDSET args; \
		args.token = (_tok); \
		args.fd = (_fd); \
		args.flags = (_flags); \
		nal_selector_ctrl((_sel), NAL_FD_CTRL_FDSET, &args); \
	} while(0)
#define nal_selector_fd_test(_flags, _sel, _tok, _fd) \
	do { \
		NAL_FD_FDTEST args; \
		args.token = (_tok); \
		args.fd = (_fd); \
		nal_selector_ctrl((_sel), NAL_FD_CTRL_FDTEST, &args); \
		*(_flags) = args.flags; \
	} while(0)

#endif /* !defined(HEADER_PRIVATE_CTRL_FD_H) */
