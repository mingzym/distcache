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

#include "private.h"

/* This file implements the "dc_client" utility - a self-contained program that
 * connects to a back-end session cache server, listens on a local address for
 * connections, and for each of those connections, manages the forwarding of
 * requests to back-end cache server (and demultiplexing its responses). */

#define CLIENT_BUFFER_SIZE	(sizeof(DC_MSG) * 2)

/********************/
/* Default settings */
/********************/

#define MAX_RETRY_PERIOD	3600000 /* 1 hour */
#define MIN_RETRY_PERIOD	1
#define MAX_IDLE_PERIOD		3600000 /* 1 hour */

static const char *def_listen_addr = "UNIX:/tmp/scache";
static const unsigned long def_retry_period = 5000;
static const unsigned long def_idle_timeout = 0;
#ifndef WIN32
static const char *def_pidfile = NULL;
#endif

/* Avoid the dreaded "greater than the length `509' ISO C89 compilers are
 * required to support" warning by splitting this into an array of strings. */
static const char *usage_msg[] = {
"",
"Usage: dc_client [options]      where 'options' are from;",
#ifndef WIN32
"  -daemon           (detach and run in the background)",
#endif
"  -listen <addr>    (listen on address 'addr', def: UNIX:/tmp/scache)",
"  -server <addr>    (connects to a cache server at 'addr')",
"  -connect <addr>   (alias for '-server')",
"  -retry <num>      (retry period (msecs) for cache servers, def: 5000)",
"  -idle <num>       (idle timeout (msecs) for client connections, def: 0)",
#ifndef WIN32
"  -pidfile <path>   (a file to store the process ID in)",
#endif
"  -<h|help|?>       (display this usage message)",
"",
" Eg. dc_client -listen UNIX:/tmp/scache -server IP:192.168.2.5:9003",
" will listen on a unix domain socket at /tmp/scache and will manage",
" forwarding requests and responses to and from two the cache server.",
"", NULL};

static const char *CMD_HELP1 = "-h";
static const char *CMD_HELP2 = "-help";
static const char *CMD_HELP3 = "-?";
#ifndef WIN32
static const char *CMD_DAEMON = "-daemon";
static const char *CMD_PIDFILE = "-pidfile";
#endif
static const char *CMD_LISTEN = "-listen";
static const char *CMD_SERVER1 = "-server";
static const char *CMD_SERVER2 = "-connect";
static const char *CMD_RETRY = "-retry";
static const char *CMD_IDLE = "-idle";

/* Little help functions to keep main() from bloating. */
static int usage(void) {
	const char **u = usage_msg;
	while(*u)
		SYS_fprintf(SYS_stderr, "%s\n", *(u++));
	return 0;
}
static int err_noarg(const char *arg) {
	SYS_fprintf(SYS_stderr, "Error, %s requires an argument\n", arg);
	usage();
	return 1;
}
static int err_badarg(const char *arg) {
	SYS_fprintf(SYS_stderr, "Error, %s given an invalid argument\n", arg);
	usage();
	return 1;
}
static int err_badswitch(const char *arg) {
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
	NAL_ADDRESS *addr;
	NAL_SELECTOR *sel;
	NAL_LISTENER *listener;
	NAL_CONNECTION *conn = NULL;
	unsigned long timeout;
	struct timeval now;
	server_t *server;
	clients_t *clients;
	multiplexer_t *multiplexer;
	const char *server_address = NULL;
	/* Overridables */
#ifndef WIN32
	int daemon_mode = 0;
	const char *pidfile = def_pidfile;
#endif
	const char *listen_addr = def_listen_addr;
	unsigned long retry_period = def_retry_period;
	unsigned long idle_timeout = def_idle_timeout;

	/* Pull options off the command-line */
	ARG_INC;
	while(argc > 0) {
		/* Check options with no arguments */
		if((strcmp(*argv, CMD_HELP1) == 0) ||
				(strcmp(*argv, CMD_HELP2) == 0) ||
				(strcmp(*argv, CMD_HELP3) == 0))
			return usage();
#ifndef WIN32
		if(strcmp(*argv, CMD_DAEMON) == 0)
			daemon_mode = 1;
		/* Check options with an argument */
		else
#endif
		if(strcmp(*argv, CMD_LISTEN) == 0) {
			ARG_CHECK(CMD_LISTEN);
			listen_addr = *argv;
		} else if((strcmp(*argv, CMD_SERVER1) == 0) ||
				(strcmp(*argv, CMD_SERVER2) == 0)) {
			ARG_CHECK(*argv);
			if(server_address) {
				SYS_fprintf(SYS_stderr, "Error, too many servers\n");
				return err_badarg(*(argv - 1));
			}
			server_address = *argv;
		} else if(strcmp(*argv, CMD_RETRY) == 0) {
			char *tmp_ptr;
			ARG_CHECK(*argv);
			retry_period = strtoul(*argv, &tmp_ptr, 10);
			if((tmp_ptr == *argv) || (*tmp_ptr != '\0') ||
					(retry_period < MIN_RETRY_PERIOD) ||
					(retry_period > MAX_RETRY_PERIOD)) {
				return err_badarg(*(argv - 1));
			}
		} else if(strcmp(*argv, CMD_IDLE) == 0) {
			char *tmp_ptr;
			ARG_CHECK(*argv);
			idle_timeout = strtoul(*argv, &tmp_ptr, 10);
			if((tmp_ptr == *argv) || (*tmp_ptr != '\0') ||
					(idle_timeout > MAX_IDLE_PERIOD)) {
				return err_badarg(*(argv - 1));
			}
#ifndef WIN32
		} else if(strcmp(*argv, CMD_PIDFILE) == 0) {
			ARG_CHECK(*argv);
			pidfile = *argv;
#endif
		} else
			return err_badswitch(*argv);
		ARG_INC;
	}

	if(!server_address) {
		SYS_fprintf(SYS_stderr, "Error, no server specified!\n");
		return 1;
	}
	/* Initialise things */
#ifdef WIN32
	if(!sockets_init()) {
		SYS_fprintf(SYS_stderr, "Error, couldn't initialise socket layer\n");
		return 1;
	}
#else
	if(!SYS_sigpipe_ignore()) {
		SYS_fprintf(SYS_stderr, "Error, couldn't ignore SIGPIPE\n");
		return 1;
	}
#endif

	/* Define a "now" value that can be used during initialisation and
	 * during the first (pre-select) main loop */
	SYS_gettime(&now);
	/* Prepare the structures */
	if(((server = server_new(server_address, retry_period, &now)) == NULL) ||
			((clients = clients_new()) == NULL) ||
			((multiplexer = multiplexer_new()) == NULL)) {
		SYS_fprintf(SYS_stderr, "Error, internal initialisation problems\n");
		return 1;
	}
	/* Prepare our networking bits */
	if(((addr = NAL_ADDRESS_new()) == NULL) ||
			!NAL_ADDRESS_create(addr, listen_addr,
				CLIENT_BUFFER_SIZE) ||
			!NAL_ADDRESS_can_listen(addr) ||
			((listener = NAL_LISTENER_new()) == NULL) ||
			!NAL_LISTENER_create(listener, addr)) {
		SYS_fprintf(SYS_stderr, "Error, bad listen address\n");
		return 1;
	}
	if((sel = NAL_SELECTOR_new()) == NULL) {
		SYS_fprintf(SYS_stderr, "Error, malloc problem\n");
		return 1;
	}
	NAL_ADDRESS_free(addr);

#ifndef WIN32
	/* If we're going daemon() mode, do it now */
	if(daemon_mode) {
		/* working directory becomes "/" */
		/* stdin/stdout/SYS_stderr -> /dev/null */
		if(!SYS_daemon(0)) {
			SYS_fprintf(SYS_stderr, "Error, couldn't detach!\n");
			return 1;
		}
	}
	/* If we're storing our pid, do it now */
	if(pidfile) {
		FILE *fp = fopen(pidfile, "w");
		if(!fp) {
			SYS_fprintf(SYS_stderr, "Error, couldn't open 'pidfile' "
					"at '%s'.\n", pidfile);
			return 1;
		}
		SYS_fprintf(fp, "%lu", (unsigned long)SYS_getpid());
		fclose(fp);
	}
#endif

	/* Choose an appropriate select timeout relative to the retry period */
	timeout = retry_period * 333;
	if(timeout < 20000)
		timeout = 20000;

main_loop:
	/* If our "conn" is NULL, malloc it (an accepted connection gets
	 * consumed by the resulting "plug" so we need to alloc it again each
	 * time). */
	if(!conn && ((conn = NAL_CONNECTION_new()) == NULL)) {
		SYS_fprintf(SYS_stderr, "Error, connection couldn't be created!!\n");
		goto end;
	}
	if(conn) NAL_LISTENER_add_to_selector(listener, sel);
	clients_to_selector(clients, sel);
	server_to_selector(server, sel, multiplexer, clients, &now);
	if(NAL_SELECTOR_select(sel, timeout, 1) < 0) {
		/* We try to be resistant against signal interruptions */
		if(errno != EINTR)
			SYS_fprintf(SYS_stderr, "Warning, selector returned an "
					"error\n");
		goto main_loop;
	}
	/* Set a "now" value that can be used throughout this post-select loop
	 * (saving on redundant calls to gettimeofday()). */
	SYS_gettime(&now);
	if(conn && NAL_CONNECTION_accept(conn, listener, sel)) {
		if(!clients_new_client(clients, conn, &now)) {
			SYS_fprintf(SYS_stderr, "Error, couldn't add in new "
				"client connection - dropping it.\n");
			NAL_CONNECTION_free(conn);
		}
		/* The connection was "consumed" by the client, even in the
		 * event of an error. */
		conn = NULL;
	}
	if(!clients_io(clients, sel, multiplexer, &now, idle_timeout) ||
			!server_io(server, sel, multiplexer, clients, &now)) {
		SYS_fprintf(SYS_stderr, "Error, a fatal problem with the "
			"client or server code occured. Closing.\n");
		goto end;
	}
	/* Now the logic-loop, which is "multiplexer"-driven. */
	if(!multiplexer_run(multiplexer, clients, server, &now)) {
		SYS_fprintf(SYS_stderr, "Error, a fatal problem with the "
			"multiplexer has occured. Closing.\n");
		goto end;
	}
	goto main_loop;
end:
	if(conn)
		NAL_CONNECTION_free(conn);
	NAL_SELECTOR_free(sel);
	NAL_LISTENER_free(listener);
	clients_free(clients);
	server_free(server);
	multiplexer_free(multiplexer);
	return 1;
}

