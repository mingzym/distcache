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

#include <libnal/common.h>

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
#if NAL_DEBUG_LEVEL > 1
	/* This should never happen! */
	abort();
#else
	return NULL;
#endif
}

FILE *NAL_stdin(void) {
	return int_get_stream(&int_stdin, stdin);
}
FILE *NAL_stdout(void) {
	int_stdout_check();
	return int_get_stream(&int_stdout, stdout);
}
FILE *NAL_stderr(void) {
	int_stderr_check();
	return int_get_stream(&int_stderr, stderr);
}


/* Close and NULL-out a stream. */

static int int_close_stream(int_stream_t *s)
{
	switch(s->mode) {
	case stream_regular:
	case stream_user:
		if(s->ptr) {
			if(!s->possible_pair || (s->possible_pair->ptr !=
								s->ptr))
				fclose(s->ptr);
			s->ptr = NULL;
		}
	case stream_null:
		s->mode = stream_disabled;
	case stream_disabled:
		return 1;
	default:
		break;
	}
#if NAL_DEBUG_LEVEL > 1
	/* This should never happen! */
	abort();
#else
	return 0;
#endif
}

int NAL_stdin_close(void) {
	return int_close_stream(&int_stdin);
}
int NAL_stdout_close(void) {
	int_stdout_check();
	return int_close_stream(&int_stdout);
}
int NAL_stderr_close(void) {
	int_stderr_check();
	return int_close_stream(&int_stderr);
}


/* Create file-based streams for std[in|out|err]. */

static int int_open_stream(int_stream_t *s, const char *path, const char *m)
{
	FILE *new_stream = fopen(path, m);
	if(!new_stream)
		return 0;
	if(!int_close_stream(s)) {
		fclose(new_stream);
		return 0;
	}
	s->ptr = new_stream;
	s->mode = stream_user;
	return 1;
}
int NAL_stdin_set(const char *path) {
	return int_open_stream(&int_stdin, path, "r");
}
int NAL_stdout_set(const char *path) {
	int_stdout_check();
	return int_open_stream(&int_stdout, path, "w");
}
int NAL_stderr_set(const char *path) {
	int_stderr_check();
	return int_open_stream(&int_stderr, path, "w");
}

/* Special - if stdout and stderr should be the same file, set stdout and call
 * this function to have stderr use the same output stream. */

int NAL_stderr_to_stdout(void)
{
	int_stderr_check();
	if(!int_close_stream(&int_stderr))
		return 0;
	int_stderr.ptr = int_stdout.ptr;
	int_stderr.mode = stream_user;
	return 1;
}


int NAL_fprintf(FILE *fp, const char *fmt, ...)
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

