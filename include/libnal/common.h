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
#ifndef HEADER_LIBNAL_COMMON_H
#define HEADER_LIBNAL_COMMON_H

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


/**************************/
/* DEBUGGING DECLARATIONS */
/**************************/

/* You can set this value to one of five settings; 0, 1, 2, 3, or 4. At
 * run-time, logging can be turned off anyway - however this level controls the
 * content that will be output if it is not disabled.
 *
 * 0 = output nothing (ie. silent operation)
 * 1 = output what a normal release-build should output.
 * 2 = output warnings too. Output interesting information that isn't otherwise
 *     produced in a release build.
 * 3 = output program flow information too, and minor warnings of more interest
 *     to peer program debugging (ie. "no problem here, but maybe your other
 *     program is not doing what you think it is?").
 * 4 = output trace-level debugging information (verbose).
 */
#ifndef NAL_DEBUG_LEVEL
#define NAL_DEBUG_LEVEL 1
#endif

/*******************************/
/* OUTPUT CONTROL DECLARATIONS */
/*******************************/

#ifndef LEAVE_STREAMS_ALONE

/* These functions provide a unified way of controlling application output.
 * Internal (FILE*) pointers are maintained for "NAL_stdin, NAL_stdout, NAL_stderr"
 * which may or may not equal stdin, stdout, stderr. These can also be NULLed
 * out, and if the NAL_fprintf macro is used then no computation time is wasted
 * on the format string processing. Unless IN_STREAMS_C is defined (which should
 * only be done in streams.c of course) the regular stdin, stdout, and stderr
 * symbols are undefined, as are the functions that often use them, ie. printf,
 * and fprintf. */

/* Return the file pointer (or NULL) for a particular stream */
FILE *NAL_stdin(void);
FILE *NAL_stdout(void);
FILE *NAL_stderr(void);
/* Close and NULL-out a stream. */
int NAL_stdin_close(void);
int NAL_stdout_close(void);
int NAL_stderr_close(void);
/* Create file-based streams for std[in|out|err]. */
int NAL_stdin_set(const char *path);
int NAL_stdout_set(const char *path);
int NAL_stderr_set(const char *path);
/* Special - if stdout and stderr should be the same file, set stdout and call
 * this function to have stderr use the same output stream. */
int NAL_stderr_to_stdout(void);
int NAL_fprintf(FILE *fp, const char *fmt, ...);
#ifndef IN_STREAMS_C
#undef stdin
#undef stdout
#undef stderr
#undef printf
#undef fprintf
#define stdin dont_use_stdin_use_NAL_stdin_instead
#define stdout dont_use_stdout_use_NAL_stdout_instead
#define stderr dont_use_stderr_use_NAL_stderr_instead
#define printf dont_use_printf_use_NAL_fprintf_with_NAL_stdout
#define fprintf dont_use_fprintf_use_NAL_fprintf_instead
#endif

#endif /* !LEAVE_STREAMS_ALONE */

#ifndef LEAVE_PROCESSES_ALONE

#ifndef IN_SYS_C
#define daemon dont_use_daemon_but_use_NAL_daemon_instead
#endif

#endif /* !LEAVE_PROCESSES_ALONE */

/******************************************/
/* MEMORY MANAGEMENT FUNCTIONS AND MACROS */
/******************************************/

/* All code except mem.c should use the NAL_[malloc|realloc|free] wrapper macros
 * to improve type-safety. This logic prevents direct use of malloc, etc. */
#ifndef IN_MEM_C
#undef malloc
#undef realloc
#undef free
#define malloc dont_use_malloc_use_NAL_malloc_instead
#define realloc dont_use_realloc_use_NAL_realloc_instead
#define free dont_use_free_use_NAL_free_instead
#endif

/* These functions are implemented in libnal but should not be called directly
 * (hence the lower-case naming). Use the NAL_[malloc|realloc|free] macros
 * instead. */
void *nal_malloc_int(size_t size);
void *nal_realloc_int(void *ptr, size_t size);
void nal_free_int(void *ptr);

/* The return value provides type-safety matching with the allocation size */
#define NAL_malloc(t,n)		(t *)nal_malloc_int((n) * sizeof(t))
/* The return value is type-safe, but no checking of 'p' seems possible */
#define NAL_realloc(t,p,n)	(t *)nal_realloc_int((p), (n) * sizeof(t))
/* Ensures 'p' is of type 't' */
#define NAL_free(t,p)		do { \
					t *tmp_nal_free_4765 = (p); \
					nal_free_int(tmp_nal_free_4765); \
				} while(0)

/*********************/
/* TYPESAFE WRAPPERS */
/*********************/

/* We always (for now) use type-safe macro wrappers for memset, memcpy, and
 * memmove. However to verify that the original versions aren't being used as
 * well, define NAL_DEBUG_LEVEL to something greater than 2; */

#if NAL_DEBUG_LEVEL > 2

/* Declare replacement functions for those we will #undef. */
void *NAL_MEMSET(void *s, int c, size_t n);
void *NAL_MEMCPY(void *dest, const void *src, size_t n);
void *NAL_MEMMOVE(void *dest, const void *src, size_t n);
#ifndef IN_MEM_C /* and #undef the versions we want * code to avoid. */
#undef memset
#undef memcpy
#undef memmove
#define memset dont_use_memset
#define memcpy dont_use_memcpy
#define memmove dont_use_memmove
#endif

#else

/* We use the system functions directly from our macros */
#define NAL_MEMSET	memset
#define NAL_MEMCPY	memcpy
#define NAL_MEMMOVE	memmove

#endif

/* We use our type-safe macro wrappers always for now, but if we notice any
 * speed differences we can put these back. Note, a decent compiler should boil
 * the type-safe wrappers down to these forms anyway after type-checking. */
#if 0
#define NAL_cover(c,t,p)	memset((p), (c), sizeof(t))
#define NAL_cover_n(c,t,p,n)	memset((p), (c), (n) * sizeof(t))
#define NAL_memcpy(t,d,s)	memcpy((d), (s), sizeof(t))
#define NAL_memcpy_n(t,d,s,n)	memcpy((d), (s), (n) * sizeof(t))
#define NAL_memmove(t,d,s)	memmove((d), (s), sizeof(t))
#define NAL_memmove_n(t,d,s,n)	memmove((d), (s), (n) * sizeof(t))
#else

/* Type-safe macro wrappers */
#define NAL_cover(c,t,p)	do { \
				t *temp_NAL_cover_ptr = (p); \
				NAL_MEMSET(temp_NAL_cover_ptr, (c), \
						sizeof(t)); \
				} while(0)
#define NAL_cover_n(c,t,p,n)	do { \
				t *temp_NAL_cover_n_ptr = (p); \
				NAL_MEMSET(temp_NAL_cover_n_ptr, (c), \
						(n) * sizeof(t)); \
				} while(0)
#define NAL_memcpy(t,d,s)	do { \
				t *temp_NAL_memcpy_ptr1 = (d); \
				const t *temp_NAL_memcpy_ptr2 = (s); \
				NAL_MEMCPY(temp_NAL_memcpy_ptr1, \
					temp_NAL_memcpy_ptr2, \
					sizeof(t)); \
				} while(0)
#define NAL_memcpy_n(t,d,s,n)	do { \
				t *temp_NAL_memcpy_ptr1 = (d); \
				const t *temp_NAL_memcpy_ptr2 = (s); \
				NAL_MEMCPY(temp_NAL_memcpy_ptr1, \
					temp_NAL_memcpy_ptr2, \
					(n) * sizeof(t)); \
				} while(0)
#define NAL_memmove(t,d,s)	do { \
				t *temp_NAL_memmove_ptr1 = (d); \
				const t *temp_NAL_memmove_ptr2 = (s); \
				NAL_MEMMOVE(temp_NAL_memmove_ptr1, \
					temp_NAL_memmove_ptr2, \
					sizeof(t)); \
				} while(0)
#define NAL_memmove_n(t,d,s,n)	do { \
				t *temp_NAL_memmove_ptr1 = (d); \
				const t *temp_NAL_memmove_ptr2 = (s); \
				NAL_MEMMOVE(temp_NAL_memmove_ptr1, \
					temp_NAL_memmove_ptr2, \
					(n) * sizeof(t)); \
				} while(0)
#endif

#define NAL_zero(t,p)		NAL_cover(0,t,(p))
#define NAL_zero_n(t,p,n)	NAL_cover_n(0,t,(p),(n))

/* Now a structure version that is useful for example with fixed size char
 * arrays ... eg. char v[20]; NAL_zero_s(v); Because you'd either need to use
 * "20" inside NAL_zero_n, or risk strangeness with NAL_zero (do you pass "v" or
 * "&v"? and what to pass for "t"??). */
#define NAL_cover_s(c,s)	memset(&(s), (c), sizeof(s))
#define NAL_zero_s(s)		NAL_cover_s(0,(s))

/***************************/
/* SYSTEM HELPER FUNCTIONS */
/***************************/

#ifdef WIN32
int NAL_sockets_init(void);
#else
int NAL_sigpipe_ignore(void);
pid_t NAL_getpid(void);
int NAL_daemon(int nochdir);
#endif
void NAL_gettime(struct timeval *tv);
int NAL_timecmp(const struct timeval *a, const struct timeval *b);
void NAL_timecpy(struct timeval *dest, const struct timeval *src);
/* Arithmetic on timevals. 'res' can be the same as 'I' if desired. */
void NAL_timeadd(struct timeval *res, const struct timeval *I,
		unsigned long msecs);
void NAL_timesub(struct timeval *res, const struct timeval *I,
		unsigned long msecs);
int NAL_expirycheck(const struct timeval *timeitem, unsigned long msec_expiry,
		const struct timeval *timenow);
unsigned long NAL_msecs_between(const struct timeval *a, const struct timeval *b);

#endif /* !defined(HEADER_LIBNAL_COMMON_H) */

