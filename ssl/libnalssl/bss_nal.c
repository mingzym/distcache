/* distcache, Distributed Session Caching technology
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

/* We must declare our purpose to libsys */
#define SYS_GENERATING_LIB

#include <libsys/pre.h>
#include <libnal/nal.h>

/* Source OpenSSL */
#include <openssl/bio.h>
#include <openssl/ssl.h>

#include <libnal/nal_ssl.h>
#include <libsys/post.h>

/* Uncomment to debug the BIO implementation */
/* #define NAL_BIO_DEBUG */

static int NAL_bio_write(BIO *, const char *, int);
static int NAL_bio_read(BIO *, char *, int);
static int NAL_bio_puts(BIO *, const char *);
static long NAL_bio_ctrl(BIO *, int, long, void *);
static int NAL_bio_new(BIO *);
static int NAL_bio_free(BIO *);

static BIO_METHOD NAL_bio_meth = {
	BIO_TYPE_BIO,
	"NAL_CONNECTION",
	NAL_bio_write,
	NAL_bio_read,
	NAL_bio_puts,
	NULL, /* bgets */
	NAL_bio_ctrl,
	NAL_bio_new,
	NAL_bio_free,
	NULL /* callback_ctrl */
};

BIO *BIO_new_NAL_CONNECTION(NAL_CONNECTION *c)
{
	BIO *b = BIO_new(&NAL_bio_meth);
	if(!b) return NULL;
	b->ptr = c;
	b->init = 1;
	b->shutdown = 1;
	return b;
}

static int NAL_bio_new(BIO *b)
{
#ifdef NAL_BIO_DEBUG
	SYS_fprintf(SYS_stdout, "NAL_BIO_DEBUG: NAL_bio_new()\n");
#endif
	b->init = 0;
	b->num = -1;
	b->ptr = NULL;
	b->flags = 0;
	return 1;
}

static int NAL_bio_free(BIO *b)
{
#ifdef NAL_BIO_DEBUG
	SYS_fprintf(SYS_stdout, "NAL_BIO_DEBUG: NAL_bio_free()\n");
#endif
	if(b->shutdown && b->init && b->ptr) {
		NAL_CONNECTION *c = b->ptr;
		NAL_CONNECTION_free(c);
	}
	return 1;
}

static int NAL_bio_write(BIO *b, const char *ptr, int len)
{
	unsigned int res;
	NAL_CONNECTION *c = (NAL_CONNECTION *)b->ptr;
	NAL_BUFFER *buf = NAL_CONNECTION_get_send(c);
#ifdef NAL_BIO_DEBUG
	SYS_fprintf(SYS_stdout, "NAL_BIO_DEBUG: NAL_bio_write(%d)\n", len);
#endif
	BIO_clear_retry_flags(b);
	res = NAL_BUFFER_write(buf, (const unsigned char *)ptr, len);
#ifdef NAL_BIO_DEBUG
	SYS_fprintf(SYS_stdout, "NAL_BIO_DEBUG: NAL_bio_write, NAL_BUFFER_write=%d\n", res);
#endif
	if(res > 0) return res;
	BIO_set_retry_write(b);
	return -1;
}

static int NAL_bio_read(BIO *b, char *ptr, int len)
{
	unsigned int res;
	NAL_CONNECTION *c = (NAL_CONNECTION *)b->ptr;
	NAL_BUFFER *buf = NAL_CONNECTION_get_read(c);
#ifdef NAL_BIO_DEBUG
	SYS_fprintf(SYS_stdout, "NAL_BIO_DEBUG: NAL_bio_read(%d)\n", len);
#endif
	BIO_clear_retry_flags(b);
	res = NAL_BUFFER_read(buf, (unsigned char *)ptr, len);
#ifdef NAL_BIO_DEBUG
	SYS_fprintf(SYS_stdout, "NAL_BIO_DEBUG: NAL_bio_read, NAL_BUFFER_read=%d\n", res);
#endif
	if(res > 0)
		return res;
	BIO_set_retry_read(b);
	return -1;
}

static int NAL_bio_puts(BIO *b, const char *s)
{
	return NAL_bio_write(b, s, strlen(s));
}

static long NAL_bio_ctrl(BIO *b, int cmd, long num, void *ptr)
{
#ifdef NAL_BIO_DEBUG
	SYS_fprintf(SYS_stdout, "NAL_BIO_DEBUG: NAL_bio_ctrl(%d)\n", cmd);
#endif
	switch(cmd) {
	/* Commands we don't (yet) implement */
	case BIO_CTRL_RESET:
	case BIO_CTRL_INFO:
#ifdef NAL_BIO_DEBUG
		SYS_fprintf(SYS_stderr, "FIXME: unimplemented BIO ctrl %d\n", cmd);
#endif
		return 0;
	/* Commands we ignore */
	case BIO_CTRL_FLUSH:
	case BIO_CTRL_PUSH:
	case BIO_CTRL_POP:
		return 1;
	/* Commands */
	case BIO_CTRL_GET_CLOSE:
		return b->shutdown;
	case BIO_CTRL_SET_CLOSE:
		b->shutdown = (int)num;
		return 1;
	default:
#ifdef NAL_BIO_DEBUG
		SYS_fprintf(SYS_stderr, "Error: unexpected BIO ctrl %d\n", cmd);
#endif
		break;
	}
	return 0;
}

