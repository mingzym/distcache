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

#include "swamp.h"

/********************/
/* Default settings */
/********************/

#ifndef CACERT_PATH
#error "CACERT_PATH not set"
#endif
/* The list of paths to try for a CA cert if one is not supplied on the command
 * line. NB: This list must be NULL terminated. */
static const char *cacert_paths[] = {
	"CA.pem", "cacert.pem",
	CACERT_PATH,
	"/etc/cacert.pem", NULL};

/*******************************************/
/* Static function prototypes, macros, etc */
/*******************************************/

/* Static functions - OpenSSL API-specifics */
static void ossl_do_good_seeding(void);
static SSL_CTX *ossl_setup_ssl_ctx(const swamp_config *config);
static void ossl_close_ssl_ctx(SSL_CTX *ctx);
/* Static functions - swamp_item functions */
static int swamp_item_init(swamp_item *item);
static void swamp_item_finish(swamp_item *item);
static void swamp_item_dirty_loop(swamp_item *item);
/* Static functions - swamp_thread_ctx functions */
static int swamp_thread_ctx_init(swamp_thread_ctx *ctx,
				const swamp_config *config);
static void swamp_thread_ctx_finish(swamp_thread_ctx *ctx);
static int swamp_thread_ctx_loop(swamp_thread_ctx *ctx);

/********************************************/
/* Static functions - OpenSSL API-specifics */
/********************************************/

/* yes, the function name *is* sarcastic. This is a benchmarking program so
 * we're testing throughput, not security. */
static void ossl_do_good_seeding(void)
{
	unsigned int loop;

	for(loop = 0; loop < 1000; loop++)
		RAND_seed(&loop, sizeof(loop));
}

/* initialise the SSL_CTX */
static SSL_CTX *ossl_setup_ssl_ctx(const swamp_config *config)
{
	FILE *fp = NULL;
	X509 *x509 = NULL;
	RSA *rsa = NULL;
	SSL_CTX *ctx = NULL;
	const char **paths;
#ifdef HAVE_ENGINE
	ENGINE *e = NULL;
#endif

	/* Initialise OpenSSL */
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();

#ifdef HAVE_ENGINE
	/* Load up the appropriate engine */
	if(config->engine_id) {
		if((e = ENGINE_by_id(config->engine_id)) == NULL) {
			SYS_fprintf(SYS_stderr, "No such engine as \"%s\"\n",
				config->engine_id);
			return NULL;
		}
		if(!ENGINE_set_default(e, ENGINE_METHOD_ALL)) {
			SYS_fprintf(SYS_stderr, "Engine was unable to initialise\n");
			return NULL;
		}
		/* Remove our (structural) reference */
		ENGINE_free(e);
	}
#endif

	/* Create the SSL_CTX */
	ctx = SSL_CTX_new(SSLv23_client_method());
	if(!ctx)
		return NULL;

	/* Add the CA cert */
	if(config->cacert) {
		fp = fopen(config->cacert, "r");
		if(fp == NULL)
			return NULL;
		if(!PEM_read_X509(fp, &x509, NULL, NULL))
			return NULL;
	} else {
		SYS_fprintf(SYS_stderr, "No 'cacert' supplied, trying defaults ...");
		/* Iterate through our list */
		paths = cacert_paths;
		while(*paths && !fp) {
			fp = fopen(*paths, "r");
			if((fp == NULL) || !PEM_read_X509(fp, &x509,
						NULL, NULL)) {
				if(fp) fclose(fp);
				fp = NULL;
			}
			if(fp)
				SYS_fprintf(SYS_stderr, " '%s' found.\n", *paths);
			else
				paths++;
		}
		if(!fp) {
			/* We didn't load a cacert file */
			SYS_fprintf(SYS_stderr, " none found\n");
			return NULL;
		}
	}
	if(fp) {
		fclose(fp);
		fp = NULL;
	}
	if(x509) {
		if(!X509_STORE_add_cert(ctx->cert_store, x509))
			return NULL;
		/* Reference counts */
		X509_free(x509);
		x509 = NULL;
	}
	if(!SSL_CTX_set_default_verify_paths(ctx))
		return NULL;

	if(config->cert) {
		/* Add the client cert */
		fp = fopen(config->cert, "r");
		if(fp == NULL)
			return NULL;
		if(!PEM_read_X509(fp, &x509, NULL, NULL))
			return NULL;
		if(!SSL_CTX_use_certificate(ctx, x509))
			return NULL;
		/* Reference counts */
		X509_free(x509);
		x509 = NULL;

		/* Add the private key */
		if(!PEM_read_RSAPrivateKey(fp, &rsa, NULL, NULL))
			return NULL;
		if(!SSL_CTX_use_RSAPrivateKey(ctx, rsa))
			return NULL;
		RSA_free(rsa);
		rsa = NULL;
		fclose(fp);
		fp = NULL;
	} else
		SYS_fprintf(SYS_stderr, "no client cert provided, continuing "
			"anyway.\n");

	if(config->cipher_string)
		/* Add the cipher string */
		if(!SSL_CTX_set_cipher_list(ctx, config->cipher_string))
			return NULL;

	return ctx;
}

static void ossl_close_ssl_ctx(SSL_CTX *ctx)
{
	SSL_CTX_free(ctx);
}

/*****************************************************/
/* Static functions - top-level swamp_item functions */
/*****************************************************/

/* initialise the swamp items */
static int swamp_thread_ctx_init(swamp_thread_ctx *ctx,
				const swamp_config *config)
{
	unsigned int loop;

	/* TODO: Each "swamp_item" is now pointing to the thread_ctx, is it
	 * necessary to initialise all this if the items can obtain the
	 * information directly??? */

	/* Sanitise the memory first */
	SYS_zero(swamp_thread_ctx, ctx);
	/* Allocate the list of 'swamp_item's */
	ctx->items = SYS_malloc(swamp_item, config->list_size);
	if(!ctx->items)
		goto fail;
	SYS_zero_n(swamp_item, ctx->items, config->list_size);
	ctx->size = config->list_size;
	/* Create our async-I/O selector */
	if((ctx->sel = NAL_SELECTOR_new()) == NULL)
		goto fail;
	/* Plug in the configuration */
	ctx->config = config;
	/* Set up the SSL_CTX ready for action */
	ctx->ssl_ctx = ossl_setup_ssl_ctx(config);
	if(!ctx->ssl_ctx) {
		openssl_err();
		goto fail;
	}
	ctx->total_completed = 0;
	ctx->total_failed = 0;
	ctx->total_max = config->total_max;
	for(loop = 0; loop < ctx->size; loop++)
	{
		ctx->items[loop].parent = ctx;
		ctx->items[loop].request =
			(const unsigned char *)config->request_string;
		ctx->items[loop].request_size = strlen(config->request_string);
		ctx->items[loop].response = SYS_malloc(unsigned char,
					config->response_size);
		if(!ctx->items[loop].response)
			goto fail;
		ctx->items[loop].response_size = config->response_size;
		ctx->items[loop].response_expected = config->response_expected;
		ctx->items[loop].conn = NULL;
		if(!(ctx->items[loop].server_iterator = server_iterator_new(
				config->distribution)))
			goto fail;
	}
	return 1;
fail:
	if(ctx->items) {
		for(loop = 0; loop < ctx->size; loop++) {
			if(ctx->items[loop].server_iterator)
				server_iterator_free(
					ctx->items[loop].server_iterator);
		}
		SYS_free(swamp_item, ctx->items);
		ctx->items = NULL;
	}
	if(ctx->sel) {
		NAL_SELECTOR_free(ctx->sel);
		ctx->sel = NULL;
	}
	if(ctx->ssl_ctx) {
		ossl_close_ssl_ctx(ctx->ssl_ctx);
		ctx->ssl_ctx = NULL;
	}
	return 0;
}

static void swamp_thread_ctx_finish(swamp_thread_ctx *ctx)
{
	unsigned int loop;
	for(loop = 0; loop < ctx->size; loop++) {
		SYS_free(unsigned char, ctx->items[loop].response);
		server_iterator_free(ctx->items[loop].server_iterator);
	}
	SYS_free(swamp_item, ctx->items);
	NAL_SELECTOR_free(ctx->sel);
	ossl_close_ssl_ctx(ctx->ssl_ctx);
	/* SYS_zero(swamp_thread_ctx, ctx); */
}

static void swamp_item_dirty_loop(swamp_item *item)
{
	unsigned int max;
	NAL_BUFFER *buf;
	/* Verbs, you gotta love 'em */
	int handshook = SSL_is_init_finished(item->ssl);
	if(!handshook)
		/* Handshaking isn't done, see if the latest traffic can stir
		 * that a bit. */
		SSL_do_handshake(item->ssl);
	/* Read dirty traffic out of the SSL machine;
	 *    bio_out -->  conn
	 */
	buf = NAL_CONNECTION_get_send(item->conn);
	max = NAL_BUFFER_unused(buf);
	if(max) {
		unsigned char *ptr = NAL_BUFFER_write_ptr(buf);
		int tmp = BIO_read(item->bio_out, ptr, max);
		if(tmp > 0)
			NAL_BUFFER_wrote(buf, tmp);
	}
	/* Write dirty traffic in to the SSL machine;
	 *    bio_in  <--  conn
	 */
	buf = NAL_CONNECTION_get_read(item->conn);
	max = NAL_BUFFER_used(buf);
	if(max) {
		const unsigned char *ptr = NAL_BUFFER_data(buf);
		int tmp = BIO_write(item->bio_in, ptr, max);
		if(tmp > 0)
			NAL_BUFFER_read(buf, NULL, tmp);
	}
	if(!handshook && !SSL_is_init_finished(item->ssl))
		/* We were in handshaking, and still are, so maybe another loop
		 * will help (this allows a reply to dirty incoming data to be
		 * put in the dirty outgoing data in a single loop). */
		SSL_do_handshake(item->ssl);
}

static int swamp_item_init(swamp_item *item)
{
	const swamp_config *config;
	config = item->parent->config;

	if(((item->conn = NAL_CONNECTION_new()) == NULL) ||
			!NAL_CONNECTION_create(item->conn, server_iterator_next(
				item->server_iterator))) {
		SYS_fprintf(SYS_stderr, "connect failed\n");
		if(item->conn)
			NAL_CONNECTION_free(item->conn);
		return 0;
	}
	/* Create the SSL */
	item->ssl = SSL_new(item->parent->ssl_ctx);
	if(!item->ssl) {
		SYS_fprintf(SYS_stderr, "SSL_new() failed\n");
		return 0;
	}
	/* Create the BIOs */
	item->bio_in = BIO_new(BIO_s_mem());
	item->bio_out = BIO_new(BIO_s_mem());
	if(!item->bio_in || !item->bio_out) {
		SYS_fprintf(SYS_stderr, "BIO_new() failed\n");
		return 0;
	}
	/* Resume a previous session? */
	if(config->session_string &&
			(config->session_string[item->total_completed %
				config->session_string_length] == 'r'))
		SSL_set_session(item->ssl, item->ssl_sess);
	/* Set the verify depth */
	SSL_set_verify_depth(item->ssl, 10);
	/* Establish the SSL - BIOs relationship */
	SSL_set_bio(item->ssl, item->bio_in, item->bio_out);
	/* Kick start the SSL handshake */
	SSL_set_connect_state(item->ssl);
	item->request_sent = 0;
	item->response_received = 0;
	item->handshake_complete = 0;
	return 1;
}

static void swamp_item_finish(swamp_item *item)
{
	SSL_free(item->ssl);
	item->ssl = NULL;
	item->bio_in = item->bio_out = NULL;
	NAL_CONNECTION_free(item->conn);
	item->conn = NULL;
}

static int swamp_thread_ctx_loop(swamp_thread_ctx *ctx)
{
	int tmp;
	unsigned int loop;
	swamp_item *item;
	SSL_SESSION *temp_session = NULL;
	const char *session_string = ctx->config->session_string;
	unsigned int session_string_length =
			ctx->config->session_string_length;

	/* Reset the global counters and add them up along the way again. */
	ctx->total_completed = 0;
	ctx->total_failed = 0;
	ctx->resumes_hit = 0;
	ctx->resumes_missed = 0;

	for(loop = 0; loop < ctx->size; loop++)
	{
		item = ctx->items + loop;

		/* Network I/O */
		if(item->conn && !NAL_CONNECTION_io(item->conn, ctx->sel)) {
			swamp_item_finish(item);
			item->total_failed++;
		}

		/* After the network IO, the state-machine gets to grind its
		 * gears ... */
possible_reconnect:
		/* Case 1: it's not connected. */
		if(!item->conn && !swamp_item_init(item))
			return 0;
		/* Do a "dirty" loop in case reads become possible that weren't,
		 * and likewise for writes */
		swamp_item_dirty_loop(item);
		/* Case 2: it's still handshaking */
		if(!item->handshake_complete &&
				SSL_is_init_finished(item->ssl)) {
			/* Check the cert verification didn't fail
			 * (hint, CAfile needs to be set to match what
			 * the server has!) */
			if(SSL_get_verify_result(item->ssl) != X509_V_OK)
				verify_result_warning();
			item->handshake_complete = 1;
			/* "session_string" is non-NULL if we have a pattern of
			 * resumes to follow */
			if(session_string) {
				temp_session = SSL_get1_session(item->ssl);
				/* Was it an attempted resume? */
				if(session_string[item->total_completed %
						session_string_length] == 'r') {
					if(temp_session == item->ssl_sess)
						item->resumes_hit++;
					else
						item->resumes_missed++;
					SSL_SESSION_free(temp_session);
				} else {
					/* Replace the item's stored session. */
					if(item->ssl_sess)
						SSL_SESSION_free(item->ssl_sess);
					item->ssl_sess = temp_session;
				}
			}
			if(ctx->config->output_sessions) {
				temp_session = SSL_get1_session(item->ssl);
				/* debug some stuff :-) */
				SYS_fprintf(SYS_stdout, "session-id[conn:%i]:", loop);
				for(tmp = 0; tmp < (int)temp_session->session_id_length;
						tmp++)
					SYS_fprintf(SYS_stdout, "%02X",
						temp_session->session_id[tmp]);
				SYS_fprintf(SYS_stdout, "\n");
				SSL_SESSION_free(temp_session);
			}
		}
		/* Case 3: we're writing the request. */
		if(item->request_sent < item->request_size) {
			/* Try and write some more */
			tmp = SSL_write(item->ssl, item->request + item->request_sent,
				item->request_size - item->request_sent);
			if(tmp > 0)
				item->request_sent += tmp;
		}
		/* Case 4: we should be reading. */
		if((item->request_sent == item->request_size) &&
				(item->response_received < item->response_expected)) {
			/* Try and read some more */
			tmp = SSL_read(item->ssl, (char *)item->response,
				item->response_size);
			if(tmp > 0)
				item->response_received += tmp;
			/* Here's our hook point to send the SSL_shutdown prior
			 * to closing (because "Case 5" won't close the
			 * connection until the outgoing buffer is empty). */
			if(item->response_received >= item->response_expected)
				SSL_shutdown(item->ssl);
		}
		/* Cast 5: we should be closing. */
		if((item->request_sent == item->request_size) &&
				(item->response_received >=
				item->response_expected)) {
			/* The SSL_shutdown will have been started in the final
			 * run of Case 4. Now we wait for the outgoing buffer to
			 * be empty before closing the connection. */
			if(NAL_BUFFER_empty(NAL_CONNECTION_get_send(item->conn))) {
				swamp_item_finish(item);
				item->total_completed++;
				/* If we don't loop back to the "connect" step
				 * here, we may end up stuck in our select. */
				goto possible_reconnect;
			}
		}
		/* To finish ... we do any more "dirty" processing possible as a
		 * result of the above and then adjust the next select for
		 * whatever is required. But only if we have a connection of
		 * course! */
		if(item->conn) {
			swamp_item_dirty_loop(item);
			NAL_SELECTOR_add_conn(ctx->sel, item->conn);
		}
		ctx->total_completed += item->total_completed;
		ctx->total_failed += item->total_failed;
		ctx->resumes_hit += item->resumes_hit;
		ctx->resumes_missed += item->resumes_missed;
	}
	/* Flush stdout */
	fflush(SYS_stdout);
	return(1);
}

/* Another to save duplication. */
#define PRINT_PERIOD_UPDATE() { \
	long span; rate = (float)-1; SYS_gettime(&exact_finish); \
	if((span = SYS_msecs_between(&exact_start, &exact_finish)) > 0) \
		rate = (float)(ctx.total_completed - last_total) * 1000 / span; \
	SYS_timecpy(&exact_start, &exact_finish); \
	SYS_fprintf(SYS_stdout, "%u seconds since starting, %u successful, " \
		"%u failed, resumes(+%u,-%u) %.2f ops/sec\n", \
		(unsigned int)(finish - start), ctx.total_completed, \
		ctx.total_failed, ctx.resumes_hit, ctx.resumes_missed, rate); \
	last_update += config.period_update; \
	last_total = ctx.total_completed; }

int main(int argc, char *argv[])
{
	swamp_config config;
	swamp_thread_ctx ctx;
	time_t start, finish;
	time_t last_update, last_csv;
	struct timeval exact_start, exact_finish;
	float rate;
	int select_res, toreturn = 0;
	unsigned int last_total = 0;

	/* Set up our defaults before processing the command line */
	swamp_config_init(&config);

	/* Make the PRNG happy (in an illusion of entropy) */
	ossl_do_good_seeding();

	/* Process the command line (we constify the array as our processing
	 * doesn't intend to alter the underlying string data anyway). */
	if(!swamp_config_process_command_line(&config,
			argc - 1, (const char **)argv + 1))
		return 1;

	/* Prefix the text header */
	copyright(config.nologo);

	/* Set up the 'thread_ctx' containing our list of swamp items */
	if(!swamp_thread_ctx_init(&ctx, &config)) {
		SYS_fprintf(SYS_stderr, "error setting up swamp_thread_ctx");
		return(openssl_err());
	}

	/* Commence activities */
	time(&start);
	last_update = last_csv = start;
#ifdef DATE_OUTPUT
	SYS_fprintf(SYS_stdout, "%s", ctime(&start));
#endif
	time(&finish);
	SYS_gettime(&exact_start);

loop_start:
	/* Do the state-machine logic (select(), reads/writes, and data
	 * post-processing on each swamp item). */
	if(!swamp_thread_ctx_loop(&ctx)) {
		SYS_fprintf(SYS_stderr, "error in data loop");
		return(openssl_err());
	}
	/* Check for a "finished" condition. First, number of completed
	 * requests. */
	if((ctx.total_max > 0) && ((ctx.total_completed +
			ctx.total_failed) >= ctx.total_max))
		goto loop_complete;
	/* Second, the time swamp has been running. */
	if((config.time_max > 0) && ((unsigned long)(finish - start) >= config.time_max))
		goto loop_complete;
	/* Run a select on the network events we're waiting on */
	select_res = NAL_SELECTOR_select(ctx.sel, 0, 0);
	if(select_res < 0) {
		SYS_fprintf(SYS_stderr, "error in select()");
		toreturn = 1; /* So main() doesn't look like it succeeded */
		goto loop_complete;
	}
	/* Grab the time again now the select is done. */
	time(&finish);
	/* Now log an update to stdout if it's been long enough since the last
	 * one (and the user wants any). */
	if(config.period_update > 0) {
		if((unsigned long)(finish - last_update) >= config.period_update)
			PRINT_PERIOD_UPDATE()
	}
	/* Similarly, output CSV data if we are configured to and the time is
	 * right. */
	if(config.csv_output && (finish > last_csv)) {
		char time_cheat[50];
		int time_cheat_len;
		/* We use the ctime() format ... */
		time_cheat_len = sprintf(time_cheat, "%s", ctime(&last_csv));
		/* ... but strip out any trailing '\n' */
		if(time_cheat[time_cheat_len - 1] == '\n')
			time_cheat[time_cheat_len - 1] = '\0';
		SYS_fprintf(config.csv_output, "%s,%u,%u,%u,%u\n",
			time_cheat, ctx.total_completed, ctx.total_failed,
			ctx.resumes_hit, ctx.resumes_missed);
		fflush(config.csv_output);
		last_csv = finish;
	}
	goto loop_start;
	/* Loop finished. Output a final line of statistics. */
loop_complete:
	PRINT_PERIOD_UPDATE()
#ifdef DATE_OUTPUT
	SYS_fprintf(SYS_stdout, "%s", ctime(&finish));
#endif
	/* Cleanup before stopping */
	swamp_thread_ctx_finish(&ctx);
	swamp_config_finish(&config);
	return toreturn;
}
