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
#include "swamp.h"

static unsigned int verify_fail_reported = 0; /* Certificate-verification failures
						 are reported only once. */

void copyright(int nologo)
{
	if(!nologo)
		SYS_fprintf(SYS_stderr,
			"\nThis is SWAMP (%s), an OpenSSL-based SSL/TLS load-tester\n"
			"Distributed as part of the Distcache Project (www.distcache.org)\n"
			"Copyright (c) 2001-2003 Geoff Thorpe, http://www.geoffthorpe.net/\n"
			"With thanks to Red Hat (http://www.redhat.com/) and\n"
			"Cryptographic Appliances (http://www.cryptoapps.com/)\n\n",
			PACKAGE_VERSION);
}

void main_usage(void)
{
	SYS_fprintf(SYS_stdout,
		"usage: sslswamp [options ...]    where the options are\n");
	SYS_fprintf(SYS_stdout,
		"    -connect [ IP:<host>:<port> | UNIX:<path> ]\n");
	SYS_fprintf(SYS_stdout,
		"                      - (REQUIRED) a network address to connect to\n");
	SYS_fprintf(SYS_stdout,
		"    -CAfile <path>    - a PEM file containing trusted CA certificates\n");
	SYS_fprintf(SYS_stdout,
		"                        (default = a list of common global paths)\n");
	SYS_fprintf(SYS_stdout,
		"    -cert <path>      - a PEM file containing the client cert and key\n");
	SYS_fprintf(SYS_stdout,
		"                        (default, no client certificate)\n");
	SYS_fprintf(SYS_stdout,
		"    -num <n>          - the number of simultaneous connections to use\n");
	SYS_fprintf(SYS_stdout,
		"                        (default = 5)\n");
	SYS_fprintf(SYS_stdout,
		"    -count <n>        - the maximum number of requests to count\n");
	SYS_fprintf(SYS_stdout,
		"                        (default = 0, keep going indefinitely)\n");
	SYS_fprintf(SYS_stdout,
		"    -time <n>         - the maximum number of seconds to run for\n");
	SYS_fprintf(SYS_stdout,
		"                        (default = 0, keep going indefinitely)\n");
	SYS_fprintf(SYS_stdout,
		"    -request <string> - the string to send to the server\n");
	SYS_fprintf(SYS_stdout,
		"                        (default = \"GET /\\r\\n\")\n");
	SYS_fprintf(SYS_stdout,
		"    -expect <n>       - the amount of data to expect in a response\n");
	SYS_fprintf(SYS_stdout,
		"                        (default = 20 bytes)\n");
	SYS_fprintf(SYS_stdout,
		"    -session <string> - a string of 's' (new session) and 'r' (resume)\n");
	SYS_fprintf(SYS_stdout,
		"                        (default = \"s\")\n");
	SYS_fprintf(SYS_stdout,
		"    -update <n>       - the number of seconds between printed updates\n");
	SYS_fprintf(SYS_stdout,
		"                        (default = 0, no printed updates)\n");
	SYS_fprintf(SYS_stdout,
		"    -cipher <string>  - a string specifying the cipher suites\n");
	SYS_fprintf(SYS_stdout,
		"                        (default = 0, assume OpenSSL defaults)\n");
	SYS_fprintf(SYS_stdout,
		"    -csv <path>       - output per-second summaries to a CSV file\n");
	SYS_fprintf(SYS_stdout,
		"                        (default, no CSV output)\n");
	SYS_fprintf(SYS_stdout,
		"    -session_ids      - display all SSL session IDs negotiated\n");
#ifdef HAVE_ENGINE
	SYS_fprintf(SYS_stdout,
		"    -engine <id>      - Initialise and use the specified engine\n");
#endif
	SYS_fprintf(SYS_stdout,
		"    -distribute <str> - a pattern of server indexes for distribution\n");
	SYS_fprintf(SYS_stdout,
		"    -nologo           - supresses the output of the program name and author\n");
	SYS_fprintf(SYS_stdout,
		"                        (useful when trying to parse output automatically)\n");
	SYS_fprintf(SYS_stdout,
		"    -h, -? or --help  - display version number and usage information\n");
}

int unknown_switch(const char *str)
{
	SYS_fprintf(SYS_stderr,
		"invalid switch \"%s\" (or invalid value). See 'sslswamp -h' for usage\n",
		str);
	return 0;
}

void verify_result_warning(void)
{
	if(verify_fail_reported)
		return;
	SYS_fprintf(SYS_stderr,
"Certificate verification failed, probably a self-signed server cert *or*\n"
"the signing CA cert is not trusted by us (hint: use '-CAfile').\n"
"This message will only be printed once\n");
	verify_fail_reported = 1;
}

/* This function gains some code clarity in main() */
int openssl_err(void)
{
	SYS_fprintf(SYS_stderr, " (OpenSSL errors follow)\n");
	ERR_print_errors_fp(SYS_stderr);
	return 1;
}
