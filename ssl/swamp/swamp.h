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
#ifndef HEADER_SWAMP_H
#define HEADER_SWAMP_H

/* We must declare our purpose to libsys */
#define SYS_GENERATING_EXE

#include <libsys/pre.h>
#include <libnal/nal.h>

/* Source OpenSSL */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#ifdef HAVE_ENGINE
#include <openssl/engine.h>
#endif

#include <libsys/post.h>

/*********************************************************/
/* types and defines implemented/used in;    swamp.c     */
/*********************************************************/

/* Predeclarations */
typedef struct st_swamp_thread_ctx	swamp_thread_ctx;
typedef struct st_server_iterator	server_iterator;
typedef struct st_swamp_config		swamp_config;
typedef struct st_dist_pattern		dist_pattern;

/* An individual "swamp_item". Each one of these cycles through the loop of
 * connecting to a server, performing the SSL/TLS handshake, sending a request,
 * reading a response, and closing the connection. */
typedef struct st_swamp_item {
	/* The parent "thread_ctx" that owns us */
	const swamp_thread_ctx *parent;
	/********************************************************/
	/* The SSL/TLS, http(s), request/response "state" stuff */
	/********************************************************/
	SSL *ssl;
	/* Last used session, for resumes. */
	SSL_SESSION *ssl_sess;
	/* The BIOs hooked into the 'dirty' side of 'ssl'. */
	BIO *bio_in;
	BIO *bio_out;
	/* A buffer for the clear-text request we're sending */
	const unsigned char *request;
	unsigned int request_size;
	unsigned int request_sent;
	/* A buffer for the clear-text response we're reading */
	unsigned char *response;
	unsigned int response_size;
	unsigned int response_received;
	unsigned int response_expected;
	/********************************/
	/* The connection to the server */
	/********************************/
	NAL_CONNECTION *conn;
	/***************************************/
	/* The iterator across the server list */
	/***************************************/
	server_iterator *server_iterator;
	/*********/
	/* Stats */
	/*********/
	unsigned int total_completed;
	unsigned int total_failed;
	unsigned int handshake_complete;
	unsigned int resumes_hit;
	unsigned int resumes_missed;
} swamp_item;

/* A context for managing multiple "swamp_item"s in a single-thread
 * single-process async-I/O manner. */
struct st_swamp_thread_ctx {
	/* The configuration we work from */
	const swamp_config *config;
	/* SSL_CTX containing our settings and OpenSSL state */
	SSL_CTX *ssl_ctx;
	/* The list of swamp items */
	swamp_item *items;
	unsigned int size;
	/* The selector used for async-I/O */
	NAL_SELECTOR *sel;
	/* Collected stats from across all swamp items */
	unsigned int total_completed;
	unsigned int total_failed;
	unsigned int total_max;
	unsigned int resumes_hit;
	unsigned int resumes_missed;
};

/*********************************************************/
/* types and defines implemented/used in;    text_msg.c  */
/*********************************************************/

void copyright(int nologo);
void main_usage(void);
int unknown_switch(const char *str);
void verify_result_warning(void);
int openssl_err(void);

/*********************************************************/
/* types and defines implemented/used in;    utils.c     */
/*********************************************************/

	/* tokeniser code */

typedef struct {
	const char *string;
	const char *delimiters;
	const char *position;
	char *token;
} tokeniser_t;
int init_tokeniser(tokeniser_t *t, const char *string, const char *delimiters);
void free_tokeniser(tokeniser_t *t);
char *do_tokenising(tokeniser_t *t);

	/* Common library wrapper functions */

/* Wrap strtol so we (a) get error handling automatically, (b) don't have to *
 * specify a base, and (c) could build easily on platforms without strol(). */ 
int int_strtol(const char *str, long *val);
/* Wrap strtoul in the same way, except we also return failure if the number
 * parsed was in fact negative. */
int int_strtoul(const char *str, unsigned long *val);

/* Substring variants. These work the same as the above except it is not assumed
 * the string up to the NULL-terminator must be entirely numeric, parsing can
 * terminate on any non-numeric character, if valid_terms is NULL *or* on the
 * first character from the valid_terms string. If valid_terms is non-NULL and
 * parsing encounters a non-numeric character not in valid_terms, the result is
 * failure. */
int int_substrtol(const char *str, long *val, const char *valid_terms);
int int_substrtoul(const char *str, unsigned long *val, const char *valid_terms);

	/* Parsing and manipulation tools */

/* Take a string input and return a copy with all "un-escaping" performed. Ie.
 * the literal string "hello\nI am fine\n" is converted to a string with two
 * line-feed control-characters. */
char *util_parse_escaped_string(const char *str_toconvert);

typedef enum st_swamp_sslmeth {
	SWAMP_SSLMETH_NORMAL,	/* SSLv23_client_method() */
	SWAMP_SSLMETH_SSLv2,	/* SSLv2_client_method() */
	SWAMP_SSLMETH_SSLv3,	/* SSLv3_client_method() */
	SWAMP_SSLMETH_TLSv1	/* TLSv1_client_method() */
} swamp_sslmeth;

/* Take a string input and map it to one of the SSLMETH types. */
int util_parse_sslmeth(const char *str_toconvert, swamp_sslmeth *val);

/*********************************************************/
/* types and defines implemented/used in;   swamp_conf.c */
/*********************************************************/

/* If DATE_OUTPUT is defined, the date/time the testing begins is output before
 * the tests start and likewise the date/time of the completion is output last.
 * Useful when many simultaneous instances are being run and the output is being
 * piped to files. */
/* #define DATE_OUTPUT */

/* The maximum number of connections we will allocate and connect
 * with during the test. */
#define MAX_LIST_SIZE 100
/* The maximum finite limit we will put on requests (0 = let it
 * run indefinately). */
#define MAX_TOTAL_MAX 2000000
/* The maximum finite time limit we will put on the running time
 * (0 = let it run indefiniately). */
#define MAX_TIME_MAX 86400 /* one day */
/* The maximum allowed response size we will accept. */
#define MAX_RESPONSE_SIZE 65536
/* An "expectation" amount which effectively means we will keep accepting
 * data until the server closes the connection. */
#define EXPECT_SERVER_CLOSE ((unsigned int)-1)
/* The maximum number of seconds between stdout updates. */
#define MAX_PERIOD_UPDATE 300
/* The size we should make the FIFO arrays */
#define SWAMP_BUFFER_SIZE 2048

struct st_swamp_config {
	/* OpenSSL "SSL_CTX" settings */
	const char *cacert;
	const char *cert;
	const char *cipher_string;
	swamp_sslmeth sslmeth;
#ifdef HAVE_ENGINE
	const char *engine_id;
#endif
	/* The number of "swamp_item"s in a "swamp_thread_ctx" */
	unsigned long list_size;
	/* If non-zero, the maximum number of requests before stopping */
	unsigned long total_max;
	/* If non-zero, the maximum number of seconds before stopping */
	unsigned long time_max;
	/* The (minimum) size to allocate our response buffer */
	unsigned long response_size;
	/* How much response to expect before we are satisfied */
	unsigned long response_expected;
	/* What request string to send to servers */
	const char *request_string;
	/* The sequence of "s" and "r" items to control SSL_SESSION behaviour */
	const char *session_string;
	/* A cached value of the string's length */
	unsigned int session_string_length;
	/* A line of statistics is printed after this many seconds */
	unsigned long period_update;
	/* Whether the logo should be printed or not */
	unsigned int nologo;
	/* Whether each negotiated (and resumed) SSL_SESSION should be logged */
	unsigned int output_sessions;
	/* If non-NULL, comma-separated output is written each second */
	FILE *csv_output;
	/* The distribution pattern of 'servers' */
	dist_pattern *distribution;
};

/* Initialise/cleanup a 'swamp_config' structure */
void swamp_config_init(swamp_config *sc);
void swamp_config_finish(swamp_config *sc);

/* Process command-line input */
int swamp_config_process_command_line(swamp_config *sc,
			int argc, const char **argv);

/* Macro to declare a command-line switch's name */
#define CMD_STR(s,v)	static const char CMD_STR_##s[] = v;
/* Macro to declare a matching enumerated item */
#define CMD_NUM(s)	CMD_NUM_##s
/* Macro to instantiate the avaiable command strings */
#define IMPLEMENT_CMDS_STRINGS_RAW \
	CMD_STR(SESSION_IDS, "-session_ids") \
	CMD_STR(NOLOGO, "-nologo") \
	CMD_STR(HELP1, "-h") \
	CMD_STR(HELP2, "-?") \
	CMD_STR(HELP3, "--help") \
	CMD_STR(CONNECT, "-connect") \
	CMD_STR(CAFILE, "-CAfile") \
	CMD_STR(CERT, "-cert") \
	CMD_STR(SSLMETH, "-sslmeth") \
	CMD_STR(NUM, "-num") \
	CMD_STR(COUNT, "-count") \
	CMD_STR(TIME, "-time") \
	CMD_STR(EXPECT, "-expect") \
	CMD_STR(REQUEST, "-request") \
	CMD_STR(SESSION, "-session") \
	CMD_STR(UPDATE, "-update") \
	CMD_STR(CIPHER, "-cipher") \
	CMD_STR(CSV, "-csv") \
	CMD_STR(DISTRIBUTE, "-distribute")
#ifndef HAVE_ENGINE
#define IMPLEMENT_CMDS_STRINGS IMPLEMENT_CMDS_STRINGS_RAW
#else
#define IMPLEMENT_CMDS_STRINGS \
	IMPLEMENT_CMDS_STRINGS_RAW \
	CMD_STR(ENGINE, "-engine")
#endif
/* Declare the corresponding command ids as an enumerated type */
typedef enum {
	CMD_NUM(SESSION_IDS),
	CMD_NUM(NOLOGO),
	CMD_NUM(HELP1),
	CMD_NUM(HELP2),
	CMD_NUM(HELP3),
	CMD_NUM(CONNECT),
	CMD_NUM(CAFILE),
	CMD_NUM(CERT),
	CMD_NUM(SSLMETH),
	CMD_NUM(NUM),
	CMD_NUM(COUNT),
	CMD_NUM(TIME),
	CMD_NUM(EXPECT),
	CMD_NUM(REQUEST),
	CMD_NUM(SESSION),
	CMD_NUM(UPDATE),
	CMD_NUM(CIPHER),
	CMD_NUM(CSV),
	CMD_NUM(DISTRIBUTE)
#ifdef HAVE_ENGINE
	,CMD_NUM(ENGINE)
#endif
} cmd_id_t;
/* The structure each command-line switch is represented by */
typedef struct st_cmd_defn {
	const char *	cmd_name;
	cmd_id_t	cmd_id;
	unsigned int	cmd_args;
} cmd_defn;
/* Macros to declare a command-line switches with zero or one arguments */
#define CMD0(s)		{CMD_STR_##s, CMD_NUM_##s, 0}
#define CMD1(s)		{CMD_STR_##s, CMD_NUM_##s, 1}
/* Finally, a macro to instantiate the supported list of command-switches */
#define IMPLEMENT_CMDS_RAW \
	IMPLEMENT_CMDS_STRINGS \
	static const cmd_defn cmds[] = { \
	/* Commands that take no arguments */ \
	CMD0(SESSION_IDS), CMD0(NOLOGO), CMD0(HELP1), CMD0(HELP2), CMD0(HELP3), \
	/* Commands that take a single argument */ \
	CMD1(CONNECT), CMD1(CAFILE), CMD1(CERT), CMD1(SSLMETH), CMD1(NUM), CMD1(COUNT), \
	CMD1(TIME), CMD1(EXPECT), CMD1(REQUEST), CMD1(SESSION), CMD1(UPDATE), \
	CMD1(CIPHER), CMD1(CSV), CMD1(DISTRIBUTE),
#ifndef HAVE_ENGINE
#define IMPLEMENT_CMDS \
	IMPLEMENT_CMDS_RAW \
	{NULL,0,0} }
#else
#define IMPLEMENT_CMDS \
	IMPLEMENT_CMDS_RAW \
	CMD1(ENGINE), \
	{NULL,0,0} }
#endif

/*********************************************************/
/* types and defines implemented/used in; dist_pattern.c */
/*********************************************************/

/* Error return codes for dist_pattern_* functions. */
typedef enum {
	ERR_DIST_PAT_OKAY = 0,
	ERR_DIST_PAT_VALUE_OUT_OF_RANGE,
	ERR_DIST_PAT_INVALID_SYNTAX,
	ERR_DIST_PAT_ARRAY_FULL,
	ERR_DIST_PAT_INTERNAL_PROBLEM
} dist_pattern_error_t;

void dist_pattern_up(dist_pattern *p);
dist_pattern *dist_pattern_new(void);
void dist_pattern_free(dist_pattern *dist);
unsigned int dist_pattern_get_start_idx(dist_pattern *p);
unsigned int dist_pattern_period(dist_pattern *dist);
unsigned int dist_pattern_num(dist_pattern *dist);
const NAL_ADDRESS *dist_pattern_get(const dist_pattern *dist,
				unsigned int idx);
int dist_pattern_push_address(dist_pattern *dist,
				const char *address);
dist_pattern_error_t dist_pattern_parse(dist_pattern *dist,
				const char *dist_str);
const char *dist_pattern_error_string(dist_pattern_error_t err);

/**********************************************************/
/* types and defines implemented/used in; serv_iterator.c */
/**********************************************************/

/* Create a new iterator over the supplied dist_pattern */
server_iterator *server_iterator_new(dist_pattern *p);
/* Free an iterator */
void server_iterator_free(server_iterator *c);
/* Return the swamp_address corresponding to our iterator on the pattern and
 * increment the index for next time. */
const NAL_ADDRESS *server_iterator_next(server_iterator *c);

#endif /* !defined(HEADER_SWAMP_H) */
