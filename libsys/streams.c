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
/* We need to define this so that common.h doesn't throw away our ability to use
 * the *real* stdin, stdout, fprintf, etc. */
#define IN_STREAMS_C

#include <libsys/sys.h>

#if SYS_DEBUG_LEVEL > 2

typedef struct st_int_stream_t {
	/* null -> hasn't been set yet.
	 * disabled -> return NULL for file pointer, don't do I/O.
	 * regular -> hasn't been changed from system file pointer.
	 * user -> a file has been opened from a path. */
	enum {
		stream_null,
		stream_disabled,
		stream_regular,
		stream_user
	} mode;
	FILE *ptr;
	/* This allows stdout and stderr to share a "special" relationship. Eg.
	 * if they have the same FILE* pointer, then closing one of them will
	 * not actually close the FILE* pointer, just NULL it. Closing the
	 * second *will* close the pointer. */
	struct st_int_stream_t *possible_pair;
} int_stream_t;

static int_stream_t int_stdin = { stream_null, NULL, NULL };
static int_stream_t int_stdout = { stream_null, NULL, NULL };
static int_stream_t int_stderr = { stream_null, NULL, NULL };

#define int_stdout_check() \
	if(!int_stdout.possible_pair) \
		int_stdout.possible_pair = &int_stderr

#define int_stderr_check() \
	if(!int_stderr.possible_pair) \
		int_stderr.possible_pair = &int_stdout

/* Return the file pointer (or NULL) for a particular stream */

static FILE *int_get_stream(int_stream_t *s, FILE *normal)
{
	switch(s->mode) {
	case stream_disabled:
		return NULL;
	case stream_null:
		s->mode = stream_regular;
		s->ptr = normal;
	case stream_regular:
	case stream_user:
		return s->ptr;
	default:
		break;
	}
	/* This should never happen! */
	abort();
}

FILE *nal_stdin(void) {
	return int_get_stream(&int_stdin, stdin);
}
FILE *nal_stdout(void) {
	int_stdout_check();
	return int_get_stream(&int_stdout, stdout);
}
FILE *nal_stderr(void) {
	int_stderr_check();
	return int_get_stream(&int_stderr, stderr);
}

int SYS_fprintf(FILE *fp, const char *fmt, ...)
{
	va_list ap;
	int res;

	if(fp == NULL)
		return 0;
	va_start(ap, fmt);
	res = vfprintf(fp, fmt, ap);
	va_end(ap);
	fflush(fp);
	return res;
}

#endif
