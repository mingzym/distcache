/* distcache, Distributed Session Caching technology
 * Copyright (C) 2000-2004  Geoff Thorpe, and Cryptographic Appliances, Inc.
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

static char *def_cacert = NULL;
static char *def_cert = NULL;
static swamp_sslmeth def_sslmeth = SWAMP_SSLMETH_NORMAL;
static unsigned int def_list_size = 5;
static unsigned int def_total_max = 0; /* Keep running */
static unsigned int def_time_max = 0; /* Keep running */
static unsigned int def_response_size = 8192;
static unsigned int def_response_expected = 20;
static const char *def_request_string = "GET /\r\n";
static const char *def_session_string = "s";
static unsigned int def_period_update = 0;
static unsigned int def_nologo = 0;
static const char *def_cipher_string = NULL;
static unsigned int def_output_sessions = 0;
#ifdef HAVE_ENGINE
static const char *def_engine_id = NULL;
#endif

/*************************************************************/
/* Command-line definitions (switches, argument syntax, etc) */
/*************************************************************/

/* This is all predeclared in the header - we simply invoke a macro to
 * instantiate everything here. */
IMPLEMENT_CMDS;

/*******************************************/
/* Static function prototypes, macros, etc */
/*******************************************/

/* Static functions - miscellaneous string parsing/checking */
static int session_string_set(swamp_config *sc, const char *val);
/* Static functions - settings and command-line functions */
static int command_line_next_token(int *argc, const char ***argv,
			cmd_id_t *cmd_id, const char **cmd_val);

/************************************************************/
/* Static functions - miscellaneous string parsing/checking */
/************************************************************/

static int session_string_set(swamp_config *sc, const char *val)
{
	unsigned int loop = 0, has_resumes = 0, val_len = strlen(val);

	for(loop = 0; loop < val_len; loop++) {
		switch(val[loop]) {
		case('r'):
			has_resumes = 1;
		case('s'):
			break;
		default:
			/* invalid */
			return 0;
		}
	}
	/* 'val' is OK. But leave "session_string" as NULL if it contains no
	 * resumes. */
	if(has_resumes) {
		sc->session_string = val;
		sc->session_string_length = val_len;
	} else
		sc->session_string = NULL;
	return 1;
}

/* This function returns zero on failure, otherwise returns the next command in
 * terms of a matching 'cmd_id_t' value, and if it takes a parameter, 'cmd_val'
 * is pointed to it otherwise it is set to NULL. */
static int command_line_next_token(int *argc, const char ***argv,
			cmd_id_t *cmd_id, const char **cmd_val)
{
	const cmd_defn *iterator = cmds;
	if(*argc <= 0)
		return 0;
	/* Search for a matching command name */
	while(iterator->cmd_name && strcmp(iterator->cmd_name, **argv))
		iterator++;
	if(!iterator->cmd_name)
		return unknown_switch(**argv);
	(*argc)--;
	(*argv)++;
	/* For now at least we only support commands with zero or one arguments.
	 * This function's prototype needs changing otherwise. */
	assert(iterator->cmd_args < 2);
	if(*argc < (int)iterator->cmd_args) {
		SYS_fprintf(SYS_stderr,
			"Error, '%s' requires %u arguments (only %u "
			"supplied)\n", **argv, iterator->cmd_args, *argc);
		return 0;
	}
	*cmd_id = iterator->cmd_id;
	if(iterator->cmd_args) {
		*cmd_val = **argv;
		(*argv)++;
		*argc -= iterator->cmd_args;
	} else
		*cmd_val = NULL;
	return 1;
}

/*******************************************************/
/* API functions - settings and command-line functions */
/*******************************************************/

/* Initialise settings from defaults (prior to possible overrides) */
void swamp_config_init(swamp_config *sc)
{
	/* Direct assignments */
	sc->cacert = def_cacert;
	sc->cert = def_cert;
	sc->sslmeth = def_sslmeth;
	sc->list_size = def_list_size;
	sc->total_max = def_total_max;
	sc->time_max = def_time_max;
	sc->response_size = def_response_size;
	sc->response_expected = def_response_expected;
	sc->request_string = def_request_string;
	sc->period_update = def_period_update;
	sc->nologo = def_nologo;
	sc->cipher_string = def_cipher_string;
	sc->output_sessions = def_output_sessions;
	sc->csv_output = NULL;
#ifdef HAVE_ENGINE
	sc->engine_id = def_engine_id;
#endif
	/* Function-based initialisation */
	session_string_set(sc, def_session_string);
	sc->distribution = dist_pattern_new();
	assert(sc->distribution);
}

/* Cleanup anything that requires it from 'defaults_init()' */
void swamp_config_finish(swamp_config *sc)
{
	dist_pattern_free(sc->distribution);
	if(sc->csv_output)
		fclose(sc->csv_output);
}

/* Process the command-line parameters into settings */
int swamp_config_process_command_line(swamp_config *sc,
			int argc, const char **argv)
{
	dist_pattern_error_t err;
	unsigned int num_servers;
	cmd_id_t cmd;
	const char *val;
	const char *dist_pattern_str = NULL;
	const char *sess_pattern_str = NULL;
	const char *csv_path = NULL;

	/* This label gives us 8 white-spaces back (and one less level of
	 * nesting). */
cmd_loop:
	/* The original argc and argv have been advanced beyond any commands
	 * to the actual arguments. */
	if(!argc)
		goto post_process;
	/* Pull out the next command[+argument] and handle errors */
	if(!command_line_next_token(&argc, &argv, &cmd, &val))
		return 0;
	/* Switch on the command type */
	switch(cmd) {
	case CMD_NUM(SESSION_IDS):
		sc->output_sessions = 1; break;
	case CMD_NUM(NOLOGO):
		sc->nologo = 1; break;
	case CMD_NUM(HELP1):
	case CMD_NUM(HELP2):
	case CMD_NUM(HELP3):
		/* To get the usage, just output the copyright and
		 * return FALSE without displaying an error. */
		copyright(sc->nologo);
		main_usage();
		return 0;
	case CMD_NUM(CONNECT):
		if(!dist_pattern_push_address(sc->distribution, val)) {
			SYS_fprintf(SYS_stderr, "invalid syntax [%s]\n", val);
			return 0;
		}
		break;
	case CMD_NUM(CAFILE):
		sc->cacert = val; break;
	case CMD_NUM(CERT):
		sc->cert = val; break;
	case CMD_NUM(SSLMETH):
		if(!util_parse_sslmeth(val, &sc->sslmeth)) {
			SYS_fprintf(SYS_stderr, "invalid ssl/tls method\n");
			return 0;
		}
		break;
	case CMD_NUM(NUM):
		if(!int_strtoul(val, &sc->list_size) || !sc->list_size ||
					(sc->list_size > MAX_LIST_SIZE)) {
			SYS_fprintf(SYS_stderr, "invalid number of connections\n");
			return 0;
		}
		break;
	case CMD_NUM(COUNT):
		if(!int_strtoul(val, &sc->total_max) ||
				(sc->total_max > MAX_TOTAL_MAX)) {
			SYS_fprintf(SYS_stderr, "invalid number of requests\n");
			return 0;
		}
		break;
	case CMD_NUM(TIME):
		if(!int_strtoul(val, &sc->time_max) ||
				(sc->time_max > MAX_TIME_MAX)) {
			SYS_fprintf(SYS_stderr, "invalid time limit\n");
			return 0;
		}
		break;
	case CMD_NUM(EXPECT):
		/* Catch the negative case and set it to the highest unsigned
		 * value we can - this will pretty much ensure we stay open
		 * until the server closes us down. */
		{
		long tmp_long;
		if(!int_strtol(val, &tmp_long) || (tmp_long > MAX_RESPONSE_SIZE)) {
			SYS_fprintf(SYS_stderr, "invalid expected response size\n");
			return 0;
		}
		sc->response_expected = (tmp_long < 0 ?
				EXPECT_SERVER_CLOSE : (unsigned long)tmp_long);
		if(sc->response_expected > sc->response_size)
			sc->response_size = sc->response_expected;
		}
		break;
	case CMD_NUM(REQUEST):
		sc->request_string = util_parse_escaped_string(val); break;
	case CMD_NUM(SESSION):
		if(sess_pattern_str) {
			SYS_fprintf(SYS_stderr, "Only one -sessions argument can be "
					"specified\n");
			return 0;
		}
		sess_pattern_str = val;
		break;
	case CMD_NUM(UPDATE):
		if(!int_strtoul(val, &sc->period_update) ||
				(sc->period_update > MAX_PERIOD_UPDATE)) {
			SYS_fprintf(SYS_stderr, "invalid update period\n");
			return 0;
		}
		break;
	case CMD_NUM(CIPHER):
		sc->cipher_string = val; break;
	case CMD_NUM(CSV):
		if(csv_path) {
			SYS_fprintf(SYS_stderr, "Only one -csv argument can be "
					"specified\n");
			return 0;
		}
		csv_path = val;
		break;
	case CMD_NUM(DISTRIBUTE):
		if(dist_pattern_str) {
			SYS_fprintf(SYS_stderr, "Only one -distribute argument can be "
					"specified\n");
			return 0;
		}
		dist_pattern_str = val;
		break;
#ifdef HAVE_ENGINE
	case CMD_NUM(ENGINE):
		sc->engine_id = val; break;
#endif
	default:
		/* shouldn't happen - '!command_line_next_token()' should
		 * prevent this happening. */
		assert(NULL == "shouldn't happen!!!");
		return 0;
	}
	goto cmd_loop;

post_process:
	/* Post-processing processing of command line arguments */

	/* Parse the distribution pattern. Now that all '-connect's have been
	 * read in and processed, we know how many servers there are to swamp
	 * and can use that figure as the upper limit for the distribution
	 * pattern elements (not all servers may be up, but that will be
	 * determined later when the swamping begins). */
	num_servers = dist_pattern_num(sc->distribution);
	if(num_servers == 0) {
		SYS_fprintf(SYS_stderr, "Error, no servers specified. See 'sslswamp -h' for usage on '-connect'\n");
		return 0;
	}

	err = dist_pattern_parse(sc->distribution, dist_pattern_str);
	if (err != ERR_DIST_PAT_OKAY) {
		if(dist_pattern_str)
			SYS_fprintf(SYS_stderr, "Error, '%s' is an invalid distribute "
				"pattern: %s\n", dist_pattern_str,
				dist_pattern_error_string(err));
		else
			SYS_fprintf(SYS_stderr, "Error, 'dist_pattern' failed: %s\n",
				dist_pattern_error_string(err));
		/* Be nice and give a hint */
		if (err == ERR_DIST_PAT_VALUE_OUT_OF_RANGE)
			SYS_fprintf(SYS_stderr, "Specify values between 1 and "
					"%d.\n", num_servers);
		return 0;
	}

	/* Parse the session pattern. */
	if(sess_pattern_str && !session_string_set(sc, sess_pattern_str)) {
		SYS_fprintf(SYS_stderr, "Error, '%s' is an invalid session string\n",
				sess_pattern_str);
		return 0;
	}
	/* Open the "csv" output if required */
	if(csv_path && ((sc->csv_output = fopen(val, "w")) == NULL)) {
		SYS_fprintf(SYS_stderr, "Error, '%s' is invalid csv path\n",
				csv_path);
		return 0;
	}
	return 1;
}
