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

/* Global defined if we want verbose output */
static int verbose = 0;

/*******************************/
/* Miscellaneous systemy utils */
/*******************************/

static int move_fd(int src, int dest)
{
	if(dup2(src, dest) == -1)
		return 0;
	close(src);
	return 1;
}

/**************/
/* Pipe rules */
/**************/

typedef struct st_pipe_defn pipe_defn;
struct st_pipe_defn {
	int fd_left;   /* the descriptor used by the left-hand task */
	int fd_right;  /* the descriptor used by the right-hand task */
	int ltr;       /* boolean: is it left to right? */
	/* Once we start creating the pipe fds, these store the (temporary)
	 * locations we create them to. */
	int safe_left;
	int safe_right;
};

static void pipe_defn_close_left(pipe_defn *d)
{
	close(d->safe_left);
}

static void pipe_defn_close_right(pipe_defn *d)
{
	close(d->safe_right);
}

static int pipe_defn_apply_left(pipe_defn *d)
{
	return move_fd(d->safe_left, d->fd_left);
}

static int pipe_defn_apply_right(pipe_defn *d)
{
	return move_fd(d->safe_right, d->fd_right);
}

static int pipe_defn_umbilicus(pipe_defn *d, NAL_CONNECTION *conn)
{
	NAL_ADDRESS *addr = NAL_ADDRESS_new();
	char buf[256]; /* Big enough for "FD:<num>:-1" */
	pipe_defn_close_right(d);
	if(!pipe_defn_apply_left(d)) return 0;
	if(!addr) return 0;
	/* umbilicii are rtl */
	if(d->ltr) return 0;
	sprintf(buf, "FD:%d:-1", d->fd_left);
	if(!NAL_ADDRESS_create(addr, buf, 1))
		return 0;
	if(!NAL_CONNECTION_create(conn, addr))
		return 0;
	NAL_ADDRESS_free(addr);
	return 1;
}

static void pipe_defn_print(pipe_defn *d)
{
	SYS_fprintf(SYS_stderr, "%d%s%d ", d->fd_left,
			(d->ltr ? ">" : "<"), d->fd_right);
}

static void pipe_defn_set(pipe_defn *d, int left, int right, int ltr)
{
	d->fd_left = left;
	d->fd_right = right;
	d->ltr = ltr;
}

static int pipe_defn_parse(pipe_defn *d, const char **s)
{
	int step = 0;
	int num = 0;
loop:
	if(isdigit(**s)) {
		num *= 10;
		num += (int)(**s - '0');
	} else if((**s == '>') || (**s == '<')) {
		if(step) return 0;
		d->fd_left = num;
		d->ltr = ((**s == '>') ? 1 : 0);
		step = 1;
		num = 0;
	} else if((**s == ',') || (**s == '\0')) {
		if(!step) return 0;
		d->fd_right = num;
		return 1;
	} else
		return 0;
	(*s)++;
	goto loop;
}

static int pipe_defn_build(pipe_defn *d, int *fdnext)
{
	int fds[2];
	int fdtmp;
	d->safe_left = d->safe_right = -1;
	if(pipe(fds) != 0)
		return 0;
	/* To really prevent overruns and conflicts, we provide a temporary
	 * threshold that is greater than; (fdnext + 1), fds[0], and fds[1].
	 * Make_fd_safe() can then, for each of the two fds, temporarily dup2()
	 * descriptors off our radar so they can be dup2()'d back into place
	 * without overwriting anything. */
	fdtmp = *fdnext + 2;
	if(fdtmp <= fds[0]) fdtmp = fds[0] + 1;
	if(fdtmp <= fds[1]) fdtmp = fds[1] + 1;
	if(!move_fd(fds[0], fdtmp) || !move_fd(fds[1], fdtmp + 1))
		return 0;
	/* Now move the fds into their "safe" block prior to forking */
	if(!move_fd(fdtmp, *fdnext)) return 0;
	fds[0] = (*fdnext)++;
	if(!move_fd(fdtmp + 1, *fdnext)) return 0;
	fds[1] = (*fdnext)++;
	if(d->ltr) {
		/* fds[0] is for reading which is what the right hand side does */
		d->safe_left = fds[1];
		d->safe_right = fds[0];
	} else {
		/* fds[0] is for reading which is what the left hand side does */
		d->safe_left = fds[0];
		d->safe_right = fds[1];
	}
	return 1;
}

typedef struct st_pipe_rules pipe_rules;
struct st_pipe_rules {
#define PIPE_RULES_SIZE 8
	pipe_defn *defns;
	unsigned int used, size;
	/* When setting up pipes in advance we call pipe(), followed by dup2()
	 * and close() on both the generated file-descriptors. We do this so
	 * that our bank of pipes are using a "safe" range of file-descriptors
	 * that won't conflict when we try to dup2() them back to their
	 * intended destinations, in the exec'd processes. */
	int safe_start, safe_next;
};

static void pipe_rules_close_left(pipe_rules *r)
{
	unsigned int idx = 0;
	while(idx < r->used)
		pipe_defn_close_left(r->defns + (idx++));
}

static void pipe_rules_close_right(pipe_rules *r)
{
	unsigned int idx = 0;
	while(idx < r->used)
		pipe_defn_close_right(r->defns + (idx++));
}

static int pipe_rules_apply_left(pipe_rules *r)
{
	unsigned int idx = 0;
	while(idx < r->used)
		if(!pipe_defn_apply_left(r->defns + (idx++)))
			return 0;
	return 1;
}

static int pipe_rules_apply_right(pipe_rules *r)
{
	unsigned int idx = 0;
	while(idx < r->used)
		if(!pipe_defn_apply_right(r->defns + (idx++)))
			return 0;
	return 1;
}

/* only used by pipe_rules_set() */
static int pipe_rules_makeroom(pipe_rules *r)
{
	if(r->used == r->size) {
		unsigned int newsize = (r->size ? (r->size * 3 / 2) : PIPE_RULES_SIZE);
		pipe_defn *newdefns = SYS_malloc(pipe_defn, newsize);
		if(!newdefns) return 0;
		if(r->used) SYS_memcpy_n(pipe_defn, newdefns, r->defns, r->used);
		if(r->size) SYS_free(pipe_defn, r->defns);
		r->defns = newdefns;
		r->size = newsize;
	}
	return 1;
}

/* This function is called with 'params' pointing to the first character after the pipe
 * symbol. Ie. *params=='\0' or "...". */
static int pipe_rules_set(pipe_rules *r, const char *params)
{
	r->defns = NULL;
	r->used = r->size = 0;
	if(*params == '\0') return pipe_rules_set(r, "1>0,0<1");
	if(!isdigit(*params)) return 0;
	do {
		if(!pipe_rules_makeroom(r)) return 0;
		if(!pipe_defn_parse(r->defns + r->used, &params)) return 0;
		r->used++;
	} while(*(params++) == ',');
	if(*(--params) != '\0') return 0;
	return 1;
}

static void pipe_rules_print(pipe_rules *r)
{
	unsigned int idx = 0;
	while(idx < r->used)
		pipe_defn_print(r->defns + (idx++));
	SYS_fprintf(SYS_stderr, "\n");
}

static int pipe_rules_build(pipe_rules *r, int fdsafe)
{
	unsigned int idx = 0;
	r->safe_start = r->safe_next = fdsafe;
	while(idx < r->used)
		if(!pipe_defn_build(r->defns + (idx++), &r->safe_next))
			return 0;
	return 1;
}

static int pipe_rules_build_xtra(pipe_rules *r, pipe_defn *d)
{
	pipe_defn_set(d, r->safe_next++, r->safe_next++, 0);
	return pipe_defn_build(d, &r->safe_next);
}

/******************/
/* Task arguments */
/******************/

typedef struct st_task_args task_args;
struct st_task_args {
#define TASK_ARGS_MAX 511
	const char *args[TASK_ARGS_MAX + 1];
	unsigned used;
};

static void task_args_init(task_args *a)
{
	a->used = 0;
}

static int task_args_add(task_args *a, const char *arg)
{
	if(a->used == TASK_ARGS_MAX) return 0;
	a->args[a->used++] = arg;
	return 1;
}

static void task_args_exec(task_args *a)
{
	/* This sodding around is to avoid gcc's "cast discards qualifier..." */
	char *argv[TASK_ARGS_MAX + 1];
	SYS_memcpy_n(char *, argv, a->args, a->used + 1);
	execvp(a->args[0], argv);
}

static int task_args_reasonable(task_args *a)
{
	/* We use this opportunity to NULL-terminate the argument list for
	 * execvp() */
	return ((a->used > 0) && task_args_add(a, NULL));
}

static void task_args_print(task_args *a)
{
	unsigned int idx = 0;
	while(idx < a->used)
		SYS_fprintf(SYS_stderr, "%s ", a->args[idx++]);
	SYS_fprintf(SYS_stderr, "\n");
}

/******************/
/* Pipe task list */
/******************/

typedef struct st_pipe_task pipe_task;
struct st_pipe_task {
	/* The command and arguments are maintained in this element. */
	task_args args;
	/* For the parent, this pipe is a life-line */
	pipe_defn umbilicus_pipe;
	NAL_CONNECTION *umbilicus_conn;
	/* Used for process cleanup in waitpid() */
	pid_t child_pid;
};

static int pipe_task_exec(pipe_task *task, pipe_rules *rules, pipe_task *left)
{
	pid_t res;
	if(!pipe_rules_build_xtra(rules, &task->umbilicus_pipe))
		return 0;
	/* Now fork() */
	res = fork();
	switch(res) {
	case -1:
		/* error */
		return 0;
	case 0:
		break;
	default:
		/* parent process */
		task->child_pid = res;
		if(left)
			pipe_rules_close_right(rules);
		else
			pipe_rules_close_left(rules);
		if(!pipe_defn_umbilicus(&task->umbilicus_pipe, task->umbilicus_conn))
			return 0;
		return 1;
	}
	/* child process! */
	pipe_defn_close_left(&task->umbilicus_pipe);
	if(left) {
		/* We should also clear out the umbilicus of the peer task */
		pipe_defn_close_left(&left->umbilicus_pipe);
		if(!pipe_rules_apply_right(rules))
			return 1;
	} else {
		pipe_rules_close_right(rules);
		if(!pipe_rules_apply_left(rules))
			return 1;
	}
	task_args_exec(&task->args);
	/* The above should not return */
	exit(1);
}

static int pipe_task_init(pipe_task *task)
{
	task_args_init(&task->args);
	task->umbilicus_conn = NAL_CONNECTION_new();
	return (task->umbilicus_conn ? 1 : 0);
}

static int pipe_task_reasonable(pipe_task *task)
{
	if(!task_args_reasonable(&task->args)) {
		SYS_fprintf(SYS_stderr, "Error, empty command\n");
		return 0;
	}
	return 1;
}

static int pipe_task_gobble(pipe_task *task, const char *s)
{
	if(!task_args_add(&task->args, s)) {
		SYS_fprintf(SYS_stderr, "Error, internal error\n");
		return 0;
	}
	return 1;
}

static void pipe_task_print(pipe_task *task)
{
	task_args_print(&task->args);
}

static int do_waitpid(pid_t pid)
{
	int status;
	if(waitpid(pid, &status, 0) <= 0)
		return 0;
	if(WEXITSTATUS(status) != 0)
		return 0;
	return 1;
}

static int do_waiting(pipe_task *task1, pipe_task *task2)
{
	NAL_SELECTOR *sel = NAL_SELECTOR_new();
	if(!sel) return 1;
	if((task1->child_pid != -1) && !NAL_CONNECTION_add_to_selector(
			task1->umbilicus_conn, sel))
		return 0;
	if((task2->child_pid != -1) && !NAL_CONNECTION_add_to_selector(
			task2->umbilicus_conn, sel))
		return 0;
	while(1) {
		NAL_SELECTOR_select(sel, 0, 0);
		if((task1->child_pid != -1) &&
				!NAL_CONNECTION_io(task1->umbilicus_conn)) {
			if(verbose)
				SYS_fprintf(SYS_stderr,
					"task1 lost contact, cleaning ...\n");
			NAL_CONNECTION_free(task1->umbilicus_conn);
			if(!do_waitpid(task1->child_pid)) {
				if(verbose)
					SYS_fprintf(SYS_stderr, "task1 failed\n");
				return 1;
			}
			if(verbose)
				SYS_fprintf(SYS_stderr, "task1 exited cleanly\n");
			task1->child_pid = -1;
		}
		if((task2->child_pid != -1) &&
				!NAL_CONNECTION_io(task2->umbilicus_conn)) {
			if(verbose)
				SYS_fprintf(SYS_stderr,
					"task2 lost contact, cleaning ...\n");
			NAL_CONNECTION_free(task2->umbilicus_conn);
			if(!do_waitpid(task2->child_pid)) {
				if(verbose)
					SYS_fprintf(SYS_stderr, "task2 failed\n");
				return 1;
			}
			task2->child_pid = -1;
			if(verbose)
				SYS_fprintf(SYS_stderr, "task2 exited cleanly\n");
		}
		if((task1->child_pid == -1) && (task2->child_pid == -1))
			return 0;
	}
}

/* Avoid the dreaded "greater than the length `509' ISO C89 compilers are
 * required to support" warning by splitting this into an array of strings. */
static const char *usage_msg[] = {
"",
"Usage: piper [options] <cmd1 ...> --[...] <cmd2 ...>",
"  where 'options' are from;",
"  -<h|help|?>      (display this usage message)",
"  -pipe <string>   (change the bipipe symbol from '--' to <string>)",
"  -safe <num>      (when pre-allocating pipes, use descriptors >= <num>)",
"  -v               (display verbose messages)",
"",
"This will set up various pipes between a two commands. The pipe symbol is",
"'--', though it can be overriden by using the '-pipe' switch. The pipe",
"symbol can be followed by a list specifying the pipes to be established",
"for the two commands. If this list is not supplied, the default is for",
"stdin/stdout to bound between the two commands (like a bidirectional",
"version of the traditional '|' pipe). The two commands are executed as",
"child processes of 'piper', and 'piper' itself exits once both child",
"processes have completed. Note also that many shells will require you to",
"escape or quote the pipe symbols to avoid them being intercepted and",
"misinterpreted by the shell interpreter. Eg. the following commands are",
"equivalent when run under the bash shell;",
"",
"   piper prog1 -- prog2",
"   piper prog1 --1\\>0,0\\<1 prog2",
"   piper prog1 \"--1>0,0<1\" prog2",
"", NULL};

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
static const char *CMD_PIPE = "-pipe";
static const char *CMD_SAFE = "-safe";
static const char *CMD_VERBOSE = "-v";

static const char *def_pipe_sep = "--";
static int def_fdsafe = 50;
static int def_verbose = 0;

static int err_noarg(const char *arg)
{
	SYS_fprintf(SYS_stderr, "Error, %s requires an argument\n", arg);
	usage();
	return 1;
}
static int err_badrange(const char *arg)
{
	SYS_fprintf(SYS_stderr, "Error, %s given an invalid argument\n", arg);
	usage();
	return 1;
}
static int err_badswitch(const char *arg)
{
	SYS_fprintf(SYS_stderr, "Error, \"%s\" not recognised\n", arg);
	usage();
	return 1;
}

/* Our global separator symbol */
static const char *pipe_sep = NULL;
/* Macro for spotting a separator symbol */
#define IS_SEP(s) (strncmp((s), pipe_sep, strlen(pipe_sep)) == 0)

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
	int fdsafe;
	/* These pipe rules are set by the separator symbol */
	pipe_rules rules;
	/* These represent the two commands to be executed */
	pipe_task task1, task2;
	/* state of the command-line parsing */
	enum {
		PARSE_TASK1,
		PARSE_TASK2
	} state = PARSE_TASK1;
	/* Overridables */
	pipe_sep = def_pipe_sep;
	fdsafe = def_fdsafe;
	verbose = def_verbose;

	ARG_INC;
	while(argc > 0) {
		if((*argv[0] != '-') || IS_SEP(*argv)) goto done;
		if((strcmp(*argv, CMD_HELP1) == 0) ||
				(strcmp(*argv, CMD_HELP2) == 0) ||
				(strcmp(*argv, CMD_HELP3) == 0))
			return usage();
		else if(strcmp(*argv, CMD_PIPE) == 0) {
			ARG_INC;
			if(!argc) return err_noarg(CMD_PIPE);
			pipe_sep = *argv;
		} else if(strcmp(*argv, CMD_SAFE) == 0) {
			ARG_INC;
			if(!argc) return err_noarg(CMD_SAFE);
			fdsafe = atoi(*argv);
			if((fdsafe < 3) || (fdsafe > 512))
				return err_badrange(CMD_SAFE);
		} else if(strcmp(*argv, CMD_VERBOSE) == 0)
			verbose++;
		else
			return err_badswitch(*argv);
		ARG_INC;
	}
done:
	if(!argc) {
		SYS_fprintf(SYS_stderr, "Error, no command to execute\n");
		return 1;
	}
	if(!SYS_sigpipe_ignore()) {
#if SYS_DEBUG_LEVEL > 0
		SYS_fprintf(SYS_stderr, "Error, couldn't ignore SIGPIPE\n");
#endif
		return 1;
	}
	/* Initialise the task structures */
	if(!pipe_task_init(&task1) || !pipe_task_init(&task2)) return 1;
	/* Pull the arguments off the command-line */
	while(argc) {
		switch(state) {
		case PARSE_TASK1:
			if(IS_SEP(*argv)) {
				if(!pipe_task_reasonable(&task1))
					/* error msg already handled */
					return 1;
				if(!pipe_rules_set(&rules, *argv + strlen(pipe_sep))) {
					SYS_fprintf(SYS_stderr, "Error, invalid pipe rules\n");
					return 1;
				}
				state = PARSE_TASK2;
				break;
			}
			if(!pipe_task_gobble(&task1, *argv))
				/* error msg already handled */
				return 1;
			break;
		case PARSE_TASK2:
			if(!pipe_task_gobble(&task2, *argv))
				/* error msg already handled */
				return 1;
			break;
		}
		ARG_INC;
	}
	if(!pipe_task_reasonable(&task2))
		/* error msg already handled */
		return 1;
	if(verbose) {
		SYS_fprintf(SYS_stderr, "Info task1: ");
		pipe_task_print(&task1);
		SYS_fprintf(SYS_stderr, "Info task2: ");
		pipe_task_print(&task2);
		SYS_fprintf(SYS_stderr, "Info pipes: ");
		pipe_rules_print(&rules);
	}
	if(!pipe_rules_build(&rules, fdsafe))
		return 1;
	if(!pipe_task_exec(&task1, &rules, NULL) || !pipe_task_exec(&task2, &rules, &task1))
		return 1;
	/* Go into the loop waiting for the tasks to end */
	return do_waiting(&task1, &task2);
}

