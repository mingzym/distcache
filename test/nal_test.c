/* distcache, Distributed Session Caching technology
 * Copyright (C) 2000-2003  Geoff Thorpe, and Cryptographic Appliances, Inc.
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

#define SYS_GENERATING_EXE

#include <libsys/pre.h>
#include <libnal/nal.h>
#include <libsys/post.h>

/* Avoid the dreaded "greater than the length `509' ISO C89 compilers are
 * required to support" warning by splitting this into an array of strings. */
static const char *usage_msg[] = {
"",
"Usage: nal_test [options]     where 'options' are from;",
"  -<h|help|?>      (display this usage message)",
"", NULL};

#define NUM_ALLOC_ADDRESS	(unsigned long)5000000
#define NUM_ALLOC_BUFFER	(unsigned long)3000000
#define NUM_ALLOC_LISTENER	(unsigned long)5000000
#define NUM_ALLOC_CONNECTION	(unsigned long)5000000
#define NUM_ALLOC_SELECTOR	(unsigned long)2000000

#define NUM_CREATE_ADDRESS1	(unsigned long)1000000
#define NUM_CREATE_ADDRESS2	(unsigned long)400000
#define NUM_CREATE_ADDRESS3	(unsigned long)20000 /* gethostbyname is SLOW */
#define NUM_CREATE_ADDRESS4	(unsigned long)1000000
#define NUM_CREATE_BUFFER1	(unsigned long)1000000
#define NUM_CREATE_BUFFER2	(unsigned long)1000000
#define NUM_CREATE_LISTENER1	(unsigned long)70000

/* Prototypes */
static int do_alloc_timings(void);
static int do_create_timings(void);

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

#if 0
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
#endif
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
	ARG_INC;
	while(argc > 0) {
		if((strcmp(*argv, CMD_HELP1) == 0) ||
				(strcmp(*argv, CMD_HELP2) == 0) ||
				(strcmp(*argv, CMD_HELP3) == 0))
			return usage();
		else
			return err_badswitch(*argv);
		ARG_INC;
	}

	if(!SYS_sigpipe_ignore()) {
#if SYS_DEBUG_LEVEL > 0
		SYS_fprintf(SYS_stderr, "Error, couldn't ignore SIGPIPE\n");
#endif
		return 1;
	}

	if(!do_alloc_timings() || !do_create_timings())
		return 1;
	return 0;
}

static void int_preamble(const char *s)
{
	size_t len = strlen(s);
	SYS_fprintf(SYS_stdout, "%s ", s);
	while(len++ < 55)
		SYS_fprintf(SYS_stdout, "%c", '.');
	fflush(SYS_stdout);
}
#ifdef HAVE_GETRUSAGE
#define LOOP(num, info, code) do { \
	unsigned long loop; \
	unsigned long msecs_all, msecs_system; \
	unsigned int perc; \
	struct rusage ru_start, ru_finish; \
	int_preamble(info); \
	loop = 0; \
	getrusage(RUSAGE_SELF, &ru_start); \
	while(loop++ < num) { \
		code \
	} \
	getrusage(RUSAGE_SELF, &ru_finish); \
	msecs_system = SYS_msecs_between(&ru_start.ru_stime, &ru_finish.ru_stime); \
	msecs_all = SYS_msecs_between(&ru_start.ru_utime, &ru_finish.ru_utime) + \
			msecs_system; \
	perc = (unsigned int)(100.0 * (float)msecs_system / (float)msecs_all + 0.5); \
	SYS_fprintf(SYS_stdout, " %8.2f per msec (%2d%% system)\n", \
		(msecs_all ? (float)num / (float)msecs_all : -1), perc); \
} while(0)
#else
#define LOOP(num, info, code) do { \
	unsigned long loop; \
	unsigned long msecs; \
	struct timeval tv_start, tv_finish; \
	int_preamble(info); \
	loop = 0; \
	SYS_gettime(&tv_start); \
	while(loop++ < num) { \
		code \
	} \
	SYS_gettime(&tv_finish); \
	msecs = SYS_msecs_between(&tv_start, &tv_finish); \
	SYS_fprintf(SYS_stdout, " %8.2f per msec\n", \
		(msecs ? (float)num / (float)msecs : -1)); \
} while(0)
#endif

static int do_alloc_timings(void)
{
	LOOP(NUM_ALLOC_ADDRESS, "new/free pairs for NAL_ADDRESS",
		NAL_ADDRESS *n_var = NAL_ADDRESS_new();
		if(!n_var) goto err;
		NAL_ADDRESS_free(n_var););
	LOOP(NUM_ALLOC_BUFFER, "new/free pairs for NAL_BUFFER",
		NAL_BUFFER *n_var = NAL_BUFFER_new();
		if(!n_var) goto err;
		NAL_BUFFER_free(n_var););
	LOOP(NUM_ALLOC_LISTENER, "new/free pairs for NAL_LISTENER",
		NAL_LISTENER *n_var = NAL_LISTENER_new();
		if(!n_var) goto err;
		NAL_LISTENER_free(n_var););
	LOOP(NUM_ALLOC_CONNECTION, "new/free pairs for NAL_CONNECTION",
		NAL_CONNECTION *n_var = NAL_CONNECTION_new();
		if(!n_var) goto err;
		NAL_CONNECTION_free(n_var););
	LOOP(NUM_ALLOC_SELECTOR, "new/free pairs for NAL_SELECTOR",
		NAL_SELECTOR *n_var = NAL_SELECTOR_new();
		if(!n_var) goto err;
		NAL_SELECTOR_free(n_var););
	return 1;
err:
	SYS_fprintf(SYS_stdout, "\nerror!\n");
	return 0;
}

static int do_create_timings(void)
{
	NAL_ADDRESS *address;
	LOOP(NUM_CREATE_ADDRESS1, "new/create(IP:9001)/free for NAL_ADDRESS",
		NAL_ADDRESS *n_var = NAL_ADDRESS_new();
		if(!n_var || !NAL_ADDRESS_create(n_var, "IP:9001", 2048))
			goto err;
		NAL_ADDRESS_free(n_var););
	LOOP(NUM_CREATE_ADDRESS2, "new/create(IP:192.168.0.1:9001)/free for NAL_ADDRESS",
		NAL_ADDRESS *n_var = NAL_ADDRESS_new();
		if(!n_var || !NAL_ADDRESS_create(n_var, "IP:192.168.0.1:9001", 2048))
			goto err;
		NAL_ADDRESS_free(n_var););
	LOOP(NUM_CREATE_ADDRESS3, "new/create(IP:localhost:9001)/free for NAL_ADDRESS",
		NAL_ADDRESS *n_var = NAL_ADDRESS_new();
		if(!n_var || !NAL_ADDRESS_create(n_var, "IP:localhost:9001", 2048))
			goto err;
		NAL_ADDRESS_free(n_var););
	LOOP(NUM_CREATE_ADDRESS4, "new/create(UNIX:/tmp/foo)/free for NAL_ADDRESS",
		NAL_ADDRESS *n_var = NAL_ADDRESS_new();
		if(!n_var || !NAL_ADDRESS_create(n_var, "UNIX:/tmp/foo", 2048))
			goto err;
		NAL_ADDRESS_free(n_var););
	LOOP(NUM_CREATE_BUFFER1, "new/set_size(2kb)/free for NAL_BUFFER",
		NAL_BUFFER *n_var = NAL_BUFFER_new();
		if(!n_var || !NAL_BUFFER_set_size(n_var, 2048))
			goto err;
		NAL_BUFFER_free(n_var););
	LOOP(NUM_CREATE_BUFFER2, "new/set_size(32kb)/free for NAL_BUFFER",
		NAL_BUFFER *n_var = NAL_BUFFER_new();
		if(!n_var || !NAL_BUFFER_set_size(n_var, 32768))
			goto err;
		NAL_BUFFER_free(n_var););
	if(((address = NAL_ADDRESS_new()) == NULL) ||
			!NAL_ADDRESS_create(address, "IP:9001", 2048))
		goto err;
	LOOP(NUM_CREATE_LISTENER1, "new/create(IP:9001)/free for NAL_LISTENER",
		NAL_LISTENER *n_var = NAL_LISTENER_new();
		if(!n_var || !NAL_LISTENER_create(n_var, address))
			goto err;
		NAL_LISTENER_free(n_var););
	return 1;
err:
	SYS_fprintf(SYS_stdout, "\nerror!\n");
	return 0;
}
