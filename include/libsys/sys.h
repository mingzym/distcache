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
#ifndef HEADER_LIBSYS_SYS_H
#define HEADER_LIBSYS_SYS_H

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
#ifndef SYS_DEBUG_LEVEL
#define SYS_DEBUG_LEVEL 1
#endif

/*******************************/
/* OUTPUT CONTROL DECLARATIONS */
/*******************************/

#if SYS_DEBUG_LEVEL > 2

/* We define SYS_*** symbols to replace streams and fprintf symbols so that we
 * can hook these later on if we wish. However, as this currently serves no
 * purpose, the implementations are only used if the debugging level is high as
 * this lets us undefine the stdio.h symbols and verify no code is accidently
 * using them. At other times however, the SYS_*** symbols are defined directly
 * to their stdio.h counterparts. */

/* Return the file pointer (or NULL) for a particular stream */
FILE *sys_stdin(void);
FILE *sys_stdout(void);
FILE *sys_stderr(void);
int sys_fprintf(FILE *fp, const char *fmt, ...);
#define SYS_stdin	sys_stdin()
#define SYS_stdout	sys_stdout()
#define SYS_stderr	sys_stderr()
#define SYS_fprintf	sys_fprintf
#ifndef IN_STREAMS_C
#undef stdin
#undef stdout
#undef stderr
#undef printf
#undef fprintf
#define stdin dont_use_stdin_use_SYS_stdin_instead
#define stdout dont_use_stdout_use_SYS_stdout_instead
#define stderr dont_use_stderr_use_SYS_stderr_instead
#define printf dont_use_printf_use_SYS_fprintf_with_SYS_stdout
#define fprintf dont_use_fprintf_use_SYS_fprintf_instead
#endif

#else

/* We use the system functions directly from our macros */
#define SYS_stdin	stdin
#define SYS_stdout	stdout
#define SYS_stderr	stderr
#define SYS_fprintf	fprintf

#endif

#ifndef LEAVE_PROCESSES_ALONE

#ifndef IN_SYS_C
#define daemon dont_use_daemon_but_use_SYS_daemon_instead
#endif

#endif /* !LEAVE_PROCESSES_ALONE */

/*********************/
/* TYPESAFE WRAPPERS */
/*********************/

/* We always (for now) use type-safe macro wrappers for malloc, realloc, free,
 * memset, memcpy, and memmove. However to verify that the origisys versions
 * aren't being used as well, define SYS_DEBUG_LEVEL to something greater than
 * 2; */

#if SYS_DEBUG_LEVEL > 2

/* Declare replacement functions for those we will #undef. */
void *sys_malloc(size_t size);
void *sys_realloc(void *ptr, size_t size);
void sys_free(void *ptr);
void *sys_memset(void *s, int c, size_t n);
void *sys_memcpy(void *dest, const void *src, size_t n);
void *sys_memmove(void *dest, const void *src, size_t n);
#ifndef IN_MEM_C /* and #undef the versions we want * code to avoid. */
#undef malloc
#undef realloc
#undef free
#undef memset
#undef memcpy
#undef memmove
#undef strncpy
#undef strdup
#define malloc dont_use_malloc
#define realloc dont_use_realloc
#define free dont_use_free
#define memset dont_use_memset
#define memcpy dont_use_memcpy
#define memmove dont_use_memmove
#define strncpy dont_use_strncpy
#define strdup dont_use_strdup
#endif

#else

/* We use the system functions directly from our macros */
#define sys_malloc	malloc
#define sys_realloc	realloc
#define sys_free	free
#define sys_memset	memset
#define sys_memcpy	memcpy
#define sys_memmove	memmove

#endif

/* We use our type-safe macro wrappers always for now, but if we notice any
 * speed differences we can put these back. Note, a decent compiler should boil
 * the type-safe wrappers down to these forms anyway after type-checking. */
#if 0
#define SYS_malloc(t,n)		(t *)malloc((n) * sizeof(t))
#define SYS_realloc(t,p,n)	(t *)realloc((p), (n) * sizeof(t))
#define SYS_free(t,p)		free((p))
#define SYS_cover(c,t,p)	memset((p), (c), sizeof(t))
#define SYS_cover_n(c,t,p,n)	memset((p), (c), (n) * sizeof(t))
#define SYS_memcpy(t,d,s)	memcpy((d), (s), sizeof(t))
#define SYS_memcpy_n(t,d,s,n)	memcpy((d), (s), (n) * sizeof(t))
#define SYS_memmove(t,d,s)	memmove((d), (s), sizeof(t))
#define SYS_memmove_n(t,d,s,n)	memmove((d), (s), (n) * sizeof(t))
#else

/* Type-safe macro wrappers */
#define SYS_malloc(t,n)		(t *)sys_malloc((n) * sizeof(t))
#define SYS_realloc(t,p,n)	(t *)sys_realloc((p), (n) * sizeof(t))
#define SYS_free(t,p)		do { \
				t *tmp_sys_free_4765 = (p); \
				sys_free(tmp_sys_free_4765); \
				} while(0)
#define SYS_cover(c,t,p)	do { \
				t *temp_SYS_cover_ptr = (p); \
				sys_memset(temp_SYS_cover_ptr, (c), \
						sizeof(t)); \
				} while(0)
#define SYS_cover_n(c,t,p,n)	do { \
				t *temp_SYS_cover_n_ptr = (p); \
				sys_memset(temp_SYS_cover_n_ptr, (c), \
						(n) * sizeof(t)); \
				} while(0)
#define SYS_memcpy(t,d,s)	do { \
				t *temp_SYS_memcpy_ptr1 = (d); \
				const t *temp_SYS_memcpy_ptr2 = (s); \
				sys_memcpy(temp_SYS_memcpy_ptr1, \
					temp_SYS_memcpy_ptr2, \
					sizeof(t)); \
				} while(0)
#define SYS_memcpy_n(t,d,s,n)	do { \
				t *temp_SYS_memcpy_ptr1 = (d); \
				const t *temp_SYS_memcpy_ptr2 = (s); \
				sys_memcpy(temp_SYS_memcpy_ptr1, \
					temp_SYS_memcpy_ptr2, \
					(n) * sizeof(t)); \
				} while(0)
#define SYS_memmove(t,d,s)	do { \
				t *temp_SYS_memmove_ptr1 = (d); \
				const t *temp_SYS_memmove_ptr2 = (s); \
				sys_memmove(temp_SYS_memmove_ptr1, \
					temp_SYS_memmove_ptr2, \
					sizeof(t)); \
				} while(0)
#define SYS_memmove_n(t,d,s,n)	do { \
				t *temp_SYS_memmove_ptr1 = (d); \
				const t *temp_SYS_memmove_ptr2 = (s); \
				sys_memmove(temp_SYS_memmove_ptr1, \
					temp_SYS_memmove_ptr2, \
					(n) * sizeof(t)); \
				} while(0)
#endif

#define SYS_zero(t,p)		SYS_cover(0,t,(p))
#define SYS_zero_n(t,p,n)	SYS_cover_n(0,t,(p),(n))
/* This wrapper always zero-terminates, unlike a normal strncpy which does not */
#define SYS_strncpy(d,s,n)	do { \
				char *tmp_SYS_strncpy1 = (d); \
				const char *tmp_SYS_strncpy2 = (s); \
				size_t tmp_SYS_strncpy3 = strlen(tmp_SYS_strncpy2), \
					tmp_SYS_strncpy4 = (n); \
				if(tmp_SYS_strncpy3 < tmp_SYS_strncpy4) \
					SYS_memcpy_n(char, (d), (s), tmp_SYS_strncpy3 + 1); \
				else { \
					SYS_memcpy_n(char, (d), (s), tmp_SYS_strncpy4); \
					tmp_SYS_strncpy1[tmp_SYS_strncpy4 - 1] = '\0'; \
				} \
				} while(0)
#define SYS_strdup(d,s)		do { \
				char **tmp_SYS_strdup1 = (d); \
				const char *tmp_SYS_strdup2 = (s); \
				size_t tmp_SYS_strdup3 = strlen(tmp_SYS_strdup2) + 1; \
				*tmp_SYS_strdup1 = SYS_malloc(char, tmp_SYS_strdup3); \
				if(*tmp_SYS_strdup1) \
					SYS_memcpy_n(char, *tmp_SYS_strdup1, \
						tmp_SYS_strdup2, tmp_SYS_strdup3); \
				} while(0)

/* Now a structure version that is useful for example with fixed size char
 * arrays ... eg. char v[20]; SYS_zero_s(v); Because you'd either need to use
 * "20" inside SYS_zero_n, or risk strangeness with SYS_zero (do you pass "v" or
 * "&v"? and what to pass for "t"??). */
#define SYS_cover_s(c,s)	memset(&(s), (c), sizeof(s))
#define SYS_zero_s(s)		SYS_cover_s(0,(s))

/***************************/
/* SYSTEM HELPER FUNCTIONS */
/***************************/

#ifdef WIN32
int SYS_sockets_init(void);
#else
int SYS_sigpipe_ignore(void);
pid_t SYS_getpid(void);
int SYS_daemon(int nochdir);
#endif
void SYS_gettime(struct timeval *tv);
int SYS_timecmp(const struct timeval *a, const struct timeval *b);
void SYS_timecpy(struct timeval *dest, const struct timeval *src);
/* Arithmetic on timevals. 'res' can be the same as 'I' if desired. */
void SYS_timeadd(struct timeval *res, const struct timeval *I,
		unsigned long msecs);
void SYS_timesub(struct timeval *res, const struct timeval *I,
		unsigned long msecs);
int SYS_expirycheck(const struct timeval *timeitem, unsigned long msec_expiry,
		const struct timeval *timenow);
unsigned long SYS_msecs_between(const struct timeval *a, const struct timeval *b);

#endif /* !defined(HEADER_LIBSYS_SYS_H) */

