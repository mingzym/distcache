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
#include <libnal/common.h>
#include <libnal/nal.h>
#include <distcache/dc_client.h>
#include <distcache/dc_enc.h>
#include <distcache/dc_server.h>

/* I want to take OpenSSL out of the picture for now but am reluctant to simply
 * axe all code relating to it. Eg. the "-withcert" option may be useful one
 * day if it's important to test behaviour with session data coming from
 * SSL_SESSION serialisation with and without client certificate information.
 * So this hack just forces HAVE_OPENSSL to be off, no matter what autoconf
 * decided. */
#ifdef HAVE_OPENSSL
#undef HAVE_OPENSSL
#endif
/* and now we return you to your scheduled viewing ... */

#ifdef HAVE_OPENSSL
#include <openssl/rand.h>
#include <openssl/ssl.h>
#endif

static const char *def_client = NULL;
static const unsigned int def_sessions = 10;
static const unsigned int def_datamin = 50;
static const unsigned int def_datamax = 2100;
static const unsigned int def_withcert = 0;
static const unsigned int def_timeout = 60;
static const unsigned int def_timevar = 5;
static const unsigned long def_progress = 0;

/* Avoid the dreaded "greater than the length `509' ISO C89 compilers are
 * required to support" warning by splitting this into an array of strings. */
static const char *usage_msg[] = {
"",
"Usage: dc_test [options]     where 'options' are from;",
"  -connect <addr>  (connect to server at address 'addr')",
"  -progress <num>  (report transaction count every 'num' operations)",
"  -sessions <num>  (create 'num' sessions to use for testing)",
"  -datamin <num>   (each session's data must be at least <num> bytes)",
"  -datamax <num>   (each session's data must be at most <num> bytes)",
#ifdef HAVE_OPENSSL
"  -withcert <num>  (make 'num' of the sessions use peer certificates)",
#endif
"  -timeout <secs>  (add sessions with a timeout of 'secs')",
"  -timevar <secs>  (randomly offset '-timeout' +/- 'secs')",
"  -ops <num>       (run <num> random tests, def: 10 * ('sessions')^2)",
"  -persistent      (use a persistent connection for all operations)",
"  -<h|help|?>      (display this usage message)",
"",
"Eg. dc_test -connect UNIX:/tmp/session_cache -sessions 10 -withcert 3",
"  will start connecting to a cache server (or a cache proxy like 'dc_client')",
"  and will runs tests using 10 sample SSL/TLS sessions, 3 of which will be",
"  large due to peer-certificate encoding.",
"NB: '-progress' ensures that if 'num' operations have accumulated,",
"  statistics are generated. However in server mode, statistics are also",
"  generated due to cache activity, so '-progress' just ensures they are",
"  generated at least as often as the number of operations grows by 'num'.",
"", NULL};

#define MAX_SESSIONS		512
#define MAX_TIMEOUT		3600 /* 1 hour */
#define MAX_OPS			1000000
#define MAX_PROGRESS		(unsigned long)1000000

/* When contructing sessions with peer-certificates, we use this cert */
#define CERT_PATH		"A-client.pem"

/* Prototypes */
static void generate_random_bytes(unsigned char *buf, unsigned int num);
static int do_client(const char *address, unsigned int num_sessions,
			unsigned int datamin, unsigned int datamax,
			unsigned int withcert, unsigned int timeout,
			unsigned int timevar, unsigned int tests,
			unsigned long progress, int persistent);

static int usage(void)
{
	const char **u = usage_msg;
	while(*u)
		SYS_fprintf(SYS_stderr, "%s\n", *(u++));
	/* Return 0 because main() can use this is as a help
	 * screen which shouldn't return an "error" */
	return 0;
}
static const char *CMD_HELP1 = "-h";
static const char *CMD_HELP2 = "-help";
static const char *CMD_HELP3 = "-?";
static const char *CMD_CLIENT = "-connect";
static const char *CMD_SESSIONS = "-sessions";
static const char *CMD_DATAMIN = "-datamin";
static const char *CMD_DATAMAX = "-datamax";
static const char *CMD_WITHCERT = "-withcert";
static const char *CMD_TIMEOUT = "-timeout";
static const char *CMD_TIMEVAR = "-timevar";
static const char *CMD_PROGRESS = "-progress";
static const char *CMD_OPS = "-ops";
static const char *CMD_PERSISTENT = "-persistent";

static int err_noarg(const char *arg)
{
	SYS_fprintf(SYS_stderr, "Error, -%s requires an argument\n", arg);
	usage();
	return 1;
}
static int err_badrange(const char *arg)
{
	SYS_fprintf(SYS_stderr, "Error, -%s given an invalid argument\n", arg);
	usage();
	return 1;
}
static int err_badswitch(const char *arg)
{
	SYS_fprintf(SYS_stderr, "Error, \"%s\" not recognised\n", arg);
	usage();
	return 1;
}

/*****************/
/* MAIN FUNCTION */
/*****************/

#define ARG_INC {argc--;argv++;}
#define ARG_CHECK(a) \
	if(argc < 2) \
		return err_noarg(a); \
	ARG_INC

int main(int argc, char *argv[])
{
	int sessions_set = 0;
	/* Overridables */
	unsigned int sessions = 0;
	unsigned int datamin = def_datamin;
	unsigned int datamax = def_datamax;
	const char *client = def_client;
	unsigned int withcert = def_withcert;
	unsigned int timeout = def_timeout;
	unsigned int timevar = def_timevar;
	unsigned long progress = def_progress;
	int persistent = 0;
	unsigned int ops = MAX_OPS + 1;

	ARG_INC;
	while(argc > 0) {
		if((strcmp(*argv, CMD_HELP1) == 0) ||
				(strcmp(*argv, CMD_HELP2) == 0) ||
				(strcmp(*argv, CMD_HELP3) == 0))
			return usage();
		if(strcmp(*argv, CMD_PERSISTENT) == 0)
			persistent = 1;
		else if(strcmp(*argv, CMD_CLIENT) == 0) {
			ARG_CHECK(CMD_CLIENT);
			client = *argv;
		} else if(strcmp(*argv, CMD_SESSIONS) == 0) {
			ARG_CHECK(CMD_SESSIONS);
			sessions = (unsigned int)atoi(*argv);
			sessions_set = 1;
		} else if(strcmp(*argv, CMD_DATAMIN) == 0) {
			ARG_CHECK(CMD_DATAMIN);
			datamin = (unsigned int)atoi(*argv);
		} else if(strcmp(*argv, CMD_DATAMAX) == 0) {
			ARG_CHECK(CMD_DATAMAX);
			datamax = (unsigned int)atoi(*argv);
		} else if(strcmp(*argv, CMD_WITHCERT) == 0) {
#ifndef HAVE_OPENSSL
			SYS_fprintf(SYS_stderr, "Error, no OpenSSL support "
				"compiled in, -with-cert not available.\n");
			return 1;
#endif
			ARG_CHECK(CMD_WITHCERT);
			withcert = (unsigned int)atoi(*argv);
		} else if(strcmp(*argv, CMD_TIMEOUT) == 0) {
			ARG_CHECK(CMD_TIMEOUT);
			timeout = (unsigned int)atoi(*argv);
			if(timeout > MAX_TIMEOUT)
				return err_badrange(CMD_TIMEOUT);
		} else if(strcmp(*argv, CMD_TIMEVAR) == 0) {
			ARG_CHECK(CMD_TIMEVAR);
			timevar = (unsigned int)atoi(*argv);
			if(timevar > MAX_TIMEOUT)
				return err_badrange(CMD_TIMEVAR);
		} else if(strcmp(*argv, CMD_PROGRESS) == 0) {
			ARG_CHECK(CMD_PROGRESS);
			progress = (unsigned long)atoi(*argv);
			if(progress > MAX_PROGRESS)
				return err_badrange(CMD_PROGRESS);
		} else if(strcmp(*argv, CMD_OPS) == 0) {
			ARG_CHECK(CMD_OPS);
			ops = (unsigned int)atoi(*argv);
			if(ops > MAX_OPS)
				return err_badrange(CMD_OPS);
		} else
			return err_badswitch(*argv);
		ARG_INC;
	}

	/* Scrutinise the settings */
	if(!client) {
		SYS_fprintf(SYS_stderr, "Error, must provide -connect\n");
		return 1;
	}
	if(!sessions_set)
		sessions = def_sessions;
	/* The limits on "-sessions" depend on client/server ... */
	if((sessions < 1) || (sessions > MAX_SESSIONS))
		return err_badrange(CMD_SESSIONS);
	if(withcert > sessions) {
		SYS_fprintf(SYS_stderr, "Error, -withcert can't be larger than "
				"-sessions\n");
		return 1;
	}
	if(timevar >= timeout) {
		SYS_fprintf(SYS_stderr, "Error, -timevar must be strictly "
				"smaller than -timeout\n");
		return 1;
	}
	if(datamin < 4) {
		SYS_fprintf(SYS_stderr, "Error, -datamin should be at least 4\n");
		return 1;
	}
	if(datamax > 4096) {
		SYS_fprintf(SYS_stderr, "Error, -datamax should be at most 4096\n");
		return 1;
	}

	if(!SYS_sigpipe_ignore()) {
#if SYS_DEBUG_LEVEL > 0
		SYS_fprintf(SYS_stderr, "Error, couldn't ignore SIGPIPE\n");
#endif
		return 1;
	}

	if(ops > MAX_OPS)
		/* "-ops" wasn't specified, guess a suitable value */
		ops = sessions * sessions * 10;

	/* Since we're using rand() in places, the generator needs seeding */
	srand(time(NULL));

	return do_client(client, sessions, datamin, datamax, withcert, timeout, timevar,
			ops, progress, persistent);
}

/* Generate 'num' pseudo-random bytes of a specified length, placing them in
 * 'buf'.  If available, OpenSSL's random number generator is used. Otherwise we
 * try /dev/urandom, and failing all else we *warn*! */
static void generate_random_bytes(unsigned char *buf, unsigned int num)
{
#ifdef HAVE_OPENSSL
	RAND_pseudo_bytes(buf, num);
#else
	static int first_time = 1;
	static FILE *urandom = NULL;
	unsigned int i;
	if(first_time) {
		urandom = fopen("/dev/urandom", "r");
	}
	if(urandom) {
		fread(buf, 1, num, urandom);
		first_time = 0;
		return;
	}
	if(first_time) {
		SYS_fprintf(SYS_stderr, "Warning - no random seed, will "
			"generate repeating sequence!!!\n");
		first_time = 0;
	}
	for (i = 0; i < num; i++) {
		buf[i] = (unsigned char)(255.0 * rand() / (RAND_MAX + 1.0));
	}
#endif
}

#ifdef HAVE_OPENSSL
/* Prototype some ugliness we want to leave at the end */
static SSL_SESSION *int_new_ssl_session(int withcert);
#else
/* Define a function to produce binary noise in place of SSL_SESSION */
static unsigned char *int_new_noise(unsigned int len)
{
	unsigned char *ptr = SYS_malloc(unsigned char, len);
	if(!ptr) return ptr;
	generate_random_bytes(ptr, len);
	return ptr;
}
#endif

static int do_client(const char *address, unsigned int num_sessions,
			unsigned int datamin, unsigned int datamax,
			unsigned int withcert, unsigned int timeout,
			unsigned int timevar, unsigned int tests,
			unsigned long progress, int persistent)
{
	int sessions_bool[MAX_SESSIONS];
	unsigned char *sessions_enc[MAX_SESSIONS];
	unsigned char *sessions_id[MAX_SESSIONS];
	unsigned int sessions_len[MAX_SESSIONS];
	unsigned int sessions_idlen[MAX_SESSIONS];
	unsigned int idx = 0;
	DC_CTX *ctx = DC_CTX_new(address,
			persistent ? DC_CTX_FLAG_PERSISTENT : 0);
	unsigned char tmp[DC_MAX_TOTAL_DATA];
	unsigned int tmp_used, tmp_size = DC_MAX_TOTAL_DATA;

	if(!ctx) {
		SYS_fprintf(SYS_stderr, "Error, 'DC_CTX' creation "
				"failed\n");
		return 1;
	}

	while(idx < num_sessions) {
#ifdef HAVE_OPENSSL
		SSL_SESSION *tmp_session;
		unsigned char *ptr;
		int ret;
		/* Create a session structure */
		if((tmp_session = int_new_ssl_session((idx < withcert) ?
						1 : 0)) == NULL) {
			SYS_fprintf(SYS_stderr, "Error, couldn't generate a new "
					"SSL_SESSION\n");
			return 1;
		}
		/* Copy the session id */
		sessions_idlen[idx] = tmp_session->session_id_length;
		sessions_len[idx] = i2d_SSL_SESSION(tmp_session, NULL);
		ptr = SYS_malloc(unsigned char, sessions_idlen[idx]);
		if(!ptr) {
			SYS_fprintf(SYS_stderr, "Error, malloc failure\n");
			return 1;
		}
		SYS_memcpy_n(unsigned char, ptr, tmp_session->session_id,
				sessions_idlen[idx]);
		sessions_id[idx] = ptr;
		/* Encode (copy) the session data (in DER encoding) */
		ptr = SYS_malloc(unsigned char, sessions_len[idx]);
		if(!ptr) {
			SYS_fprintf(SYS_stderr, "Error, malloc failure\n");
			return 1;
		}
		sessions_enc[idx] = ptr;
		ret = i2d_SSL_SESSION(tmp_session, &ptr);
		assert(ret == sessions_len[idx]);
		SSL_SESSION_free(tmp_session);
#else
		/* We generate some kind of arbitrary nonsense due to having no
		 * OpenSSL support. */
		sessions_idlen[idx] = 10+(int)(54.0*rand()/(RAND_MAX+1.0));
		sessions_len[idx] = datamin +(int)((1.0*datamax-datamin)*rand()/(RAND_MAX+1.0));
		if((sessions_id[idx] = int_new_noise(sessions_idlen[idx])) == NULL) {
			SYS_fprintf(SYS_stderr, "Error, malloc failure\n");
			return 1;
		}
		if((sessions_enc[idx] = int_new_noise(sessions_len[idx])) == NULL) {
			SYS_fprintf(SYS_stderr, "Error, malloc failure\n");
			return 1;
		}
#endif
		/* It's not currently on the server */
		sessions_bool[idx] = 0;
		idx++;
	}
	SYS_fprintf(SYS_stdout, "Info, %u sessions generated, will run %u "
			"random tests\n", num_sessions, tests);
	idx = 0;
	while(idx < tests) {
		int ret;
		unsigned int s, op;
		unsigned long t;
		unsigned int c[3];
		/* Pick a random session and a random add/remove/get */
		generate_random_bytes((unsigned char *)c, sizeof(c));
		s = c[0] % num_sessions;
		op = c[1] % 4;
		switch(op) {
		case 0:
			/* add */
			/* pick a random timeout (NB: we operate this program in
			 * seconds for user-simplicity, but the API works in
			 * milliseconds). */
			if(timevar)
				t = c[2] % (2000 * timevar);
			else
				t = 0;
			t += (1000 * (timeout - timevar));
			ret = DC_CTX_add_session(ctx,
					sessions_id[s], sessions_idlen[s],
					sessions_enc[s], sessions_len[s], t);
			/* This should succeed iff the session wasn't already on
			 * the server */
			if(sessions_bool[s]) {
				if(ret) {
					SYS_fprintf(SYS_stderr, "Error, add "
						"succeeded and shouldn't have!\n");
					goto bail;
				}
			} else {
				if(!ret) {
					SYS_fprintf(SYS_stderr, "Error, add "
							"failed!\n");
					goto bail;
				}
				sessions_bool[s] = 1;
			}
			break;
		case 1:
			/* remove */
			ret = DC_CTX_remove_session(ctx,
					sessions_id[s], sessions_idlen[s]);
			/* This should succeed iff the session was there */
			if(sessions_bool[s]) {
				if(!ret) {
					SYS_fprintf(SYS_stderr, "Error, remove "
						"failed!\n");
					goto bail;
				}
				sessions_bool[s] = 0;
			} else {
				if(ret) {
					SYS_fprintf(SYS_stderr, "Error, remove "
						"succeeded and shouldn't have!\n");
					goto bail;
				}
			}
			break;
		case 2:
			/* get */
			ret = DC_CTX_get_session(ctx, sessions_id[s],
					sessions_idlen[s],
					tmp, tmp_size, &tmp_used);
			/* This should succeed iff the session was there */
			if(sessions_bool[s]) {
				if(!ret) {
					SYS_fprintf(SYS_stderr, "Error, get "
						"failed!\n");
					goto bail;
				}
				if((tmp_used != sessions_len[s]) ||
						(memcmp(tmp, sessions_enc[s],
							tmp_used) != 0)) {
					SYS_fprintf(SYS_stderr, "Error, received "
						"mismatched session\n");
					goto bail;
				}
			} else {
				if(ret) {
					SYS_fprintf(SYS_stderr, "Error, get "
						"succeeded and shouldn't have!\n");
					goto bail;
				}
			}
			break;
		case 3:
			/* have */
			ret = DC_CTX_has_session(ctx,
					sessions_id[s], sessions_idlen[s]);
			/* If this returns negative, there was an error */
			if(ret < 0) {
				SYS_fprintf(SYS_stderr, "Error, transaction "
						"failure\n");
				goto bail;
			}
			/* This should return > 0 iff the session was there */
			if(sessions_bool[s]) {
				if(!ret) {
					SYS_fprintf(SYS_stderr, "Error, have "
							"failed!\n");
					goto bail;
				}
			} else {
				if(ret) {
					SYS_fprintf(SYS_stderr, "Error, have "
						"succeeded and shouldn't have!\n");
					goto bail;
				}
			}
			break;
		default:
			abort();
		}
		idx++;
		if(progress && ((idx % progress) == 0))
			SYS_fprintf(SYS_stdout, "Info, total operations = "
					"%7u\n", idx);
	}
	SYS_fprintf(SYS_stdout, "Info, all tests complete\n");
	return 0;
bail:
	SYS_fprintf(SYS_stdout, "Info, %u tests succeeded before the first failure\n",
			idx);
	return 1;
}

#ifdef HAVE_OPENSSL
/***************************************/

/* Steal this SSL_CIPHER definition from s3_lib.c so that we can manually
 * construct SSL_SESSION structures. NB: I also have to steal all the dependant
 * definitions from ssl_locl.h ... OpenSSL should have its "ssl/" tree taken out
 * and shot. */
#define SSL_kRSA                0x00000001L /* RSA key exchange */
#define SSL_aRSA                0x00000040L /* Authenticate with RSA */
#define SSL_RC4                 0x00004000L
#define SSL_MD5                 0x00080000L
#define SSL_SSLV3               0x00400000L
#define SSL_EXPORT              0x00000002L
#define SSL_EXP40               0x00000004L
#define SSL_MKEY_MASK           0x0000003FL
#define SSL_AUTH_MASK           0x00000FC0L
#define SSL_ENC_MASK            0x0087F000L
#define SSL_MAC_MASK            0x00180000L
#define SSL_EXP_MASK            0x00000003L
#define SSL_STRONG_MASK         0x0000007cL
#define SSL_ALL_CIPHERS         (SSL_MKEY_MASK|SSL_AUTH_MASK|SSL_ENC_MASK|\
                                SSL_MAC_MASK)
#define SSL_ALL_STRENGTHS       (SSL_EXP_MASK|SSL_STRONG_MASK)
static SSL_CIPHER dummy_cipher = {
	1,
	SSL3_TXT_RSA_RC4_40_MD5,
	SSL3_CK_RSA_RC4_40_MD5,
	SSL_kRSA|SSL_aRSA|SSL_RC4  |SSL_MD5 |SSL_SSLV3,
	SSL_EXPORT|SSL_EXP40,
	0,
	40,
	128,
	SSL_ALL_CIPHERS,
	SSL_ALL_STRENGTHS,
};

/* Create and return a dummy SSL_SESSION given a provided 'peer' certificate
 * path (or NULL for none). */
static SSL_SESSION *int_new_ssl_session(int withcert)
{
	FILE *fp = NULL;
	SSL_SESSION *ss = SSL_SESSION_new();

	if(!ss)
		goto end;
	ss->ssl_version = SSL3_VERSION;
	ss->verify_result = X509_V_OK;
	ss->key_arg_length = SSL_MAX_KEY_ARG_LENGTH;
	ss->cipher = &dummy_cipher;
	RAND_pseudo_bytes(ss->key_arg, ss->key_arg_length);
	ss->master_key_length = SSL_MAX_MASTER_KEY_LENGTH;
	RAND_pseudo_bytes(ss->master_key, ss->master_key_length);
	ss->session_id_length = SSL_MAX_SSL_SESSION_ID_LENGTH;
	RAND_pseudo_bytes(ss->session_id, ss->session_id_length);
	ss->sid_ctx_length = 8;
	RAND_pseudo_bytes(ss->sid_ctx, ss->sid_ctx_length);
	if(withcert) {
		if((fp = fopen(CERT_PATH, "r")) == NULL) {
			SYS_fprintf(SYS_stderr, "Error, can't open '%s'\n", CERT_PATH);
			goto end;
		}
		ss->peer = PEM_read_X509(fp, NULL, NULL, NULL);
		fclose(fp); fp = NULL;
		if(!ss->peer)
			goto end;
	} else
		ss->peer = NULL;
	return ss;
end:
	if(ss)
		SSL_SESSION_free(ss);
	if(fp)
		fclose(fp);
	return NULL;
}
#endif
