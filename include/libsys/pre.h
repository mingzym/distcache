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
#ifndef HEADER_LIBSYS_PRE_H
#define HEADER_LIBSYS_PRE_H

#ifdef WIN32

/* We're windows, include the headers we want explicitly */

#if _MSC_VER > 1000
	#pragma once
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#else

/* We're a less disabled system - use autoconf results */
#include "config.h"

#if !defined(HAVE_SELECT)
	#error "'select()' must be supported on your system, sorry"
#endif
#if !defined(HAVE_SOCKET)
	#error "'socket()' must be supported on your system, sorry"
#endif
#if !defined(HAVE_GETTIMEOFDAY)
	#error "'gettimeofday()' must be supported on your system, sorry"
#endif

#if defined(STDC_HEADERS)
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif

#if defined(HAVE_DIRENT_H)
#include <dirent.h>
#endif
#if defined(HAVE_DLFCN_H)
#include <dlfcn.h>
#endif
#if defined(HAVE_FCNTL_H)
#include <fcntl.h>
#endif
#if defined(HAVE_NETDB_H)
#include <netdb.h>
#endif
#if defined(HAVE_TIME_H)
#include <time.h>
#endif
#if defined(HAVE_UNISTD_H)
#include <unistd.h>
#endif
#if defined(HAVE_NETINET_IN_H)
#include <netinet/in.h>
#endif
#if defined(HAVE_NETINET_TCP_H)
#include <netinet/tcp.h>
#endif
#if defined(HAVE_SYS_SOCKET_H)
#include <sys/socket.h>
#endif
#if defined(HAVE_SYS_STAT_H)
#include <sys/stat.h>
#endif
#if defined(HAVE_SYS_TIME_H)
#include <sys/time.h>
#endif
#if defined(HAVE_SYS_TYPES_H)
#include <sys/types.h>
#endif
#if defined(HAVE_SYS_UN_H)
#include <sys/un.h>
#endif
#if defined(HAVE_SYS_WAIT_H)
#include <sys/wait.h>
#endif

#endif

/*****************/
/* SYSTEM FIXING */
/*****************/
#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108 /* "man 4 unix" on Linux - perhaps should be less? */
#endif /* !defined(UNIX_PATH_MAX) */
#ifndef ssize_t
#define ssize_t int
#endif /* !defined(ssize_t) */

#endif /* !defined(HEADER_LIBSYS_PRE_H) */

