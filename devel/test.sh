#!/bin/sh

BAILOUT=no
BAILREASON=""
THISDIR=`pwd`
DC_SERVER_PROG="$THISDIR/sessserver/dc_server"
DC_SERVER_UNIX="$THISDIR/unix.dc_server"
DC_SERVER_PID="$THISDIR/pid.dc_server"
DC_CLIENT_PROG="$THISDIR/sessclient/dc_client"
DC_CLIENT_UNIX="$THISDIR/unix.dc_client"
DC_CLIENT_PID="$THISDIR/pid.dc_client"
NUM_OPS=4000
DC_TEST="$THISDIR/test/dc_test -timeout 30 -timevar 10"

DC_SERVER="$DC_SERVER_PROG -listen UNIX:$DC_SERVER_UNIX -pidfile $DC_SERVER_PID -daemon"
DC_CLIENT="$DC_CLIENT_PROG -listen UNIX:$DC_CLIENT_UNIX -pidfile $DC_CLIENT_PID -daemon -server UNIX:$DC_SERVER_UNIX"

cleanup() {
	if [ -f "$DC_SERVER_PID" ]; then
		kill `cat $DC_SERVER_PID` || echo "couldn't kill 'dc_server'!"
	fi
	if [ -f "$DC_CLIENT_PID" ]; then
		kill `cat $DC_CLIENT_PID` || echo "couldn't kill 'dc_client'!"
	fi
	rm -f $DC_SERVER_PID $DC_SERVER_UNIX
	rm -f $DC_CLIENT_PID $DC_CLIENT_UNIX
}

bang() {
	echo "Bailing out:$BAILREASON"
	cleanup
	exit 1
}

# run_test $1 $2 $3
# $1: number of operations
# $2: "server" or "client" (target address)
# $3: "temporary" or "persistent"  (whether to use -persistent)
run_test() {
	text="$1 random operations"
	cmd="$DC_TEST -ops $1 -connect UNIX:"
	if [ "$2" = "server" ]; then
		text="$text direct to"
		cmd="$cmd$DC_SERVER_UNIX"
	else
		text="$text through"
		cmd="$cmd$DC_CLIENT_UNIX"
	fi
	text="$text dc_$2 ($3 connections) ... "
	if [ "$3" = "persistent" ]; then
		cmd="$cmd -persistent"
	fi
	printf "%s" "$text"
	$cmd 1> /dev/null 2> /dev/null && echo "SUCCESS" && return 0
	echo "FAILED"
	return 1
}

if [ ! -x "$DC_SERVER_PROG" ]; then
	echo "Either you haven't compiled the source-code or you are executing"
	echo "from the wrong directory. Please run this script from the top-level"
	echo "directory, ie;"
	echo "   ./devel/test.sh"
	BAILOUT=yes
	BAILREASON="$BAILREASON ($DC_SERVER_PROG not found)"
fi

if [ -f "$DC_SERVER_PID" ]; then
	BAILOUT=yes
	BAILREASON="$BAILREASON (pid.dc_server exists)"
fi

if [ -S "$DC_SERVER_UNIX" ]; then
	BAILOUT=yes
	BAILREASON="$BAILREASON (unix.dc_server exists)"
fi

if [ "x$BAILOUT" != "xno" ]; then
	bang
fi

printf "Starting dc_server daemon on %s ... " "$DC_SERVER_UNIX"
$DC_SERVER 1> /dev/null 2> /dev/null || (echo "FAILED" && exit 1) || exit 1
echo "SUCCESS"
printf "Starting dc_client daemon on %s ... " "$DC_CLIENT_UNIX"
$DC_CLIENT 1> /dev/null 2> /dev/null || (echo "FAILED" && exit 1) || exit 1
echo "SUCCESS"

echo ""

sleep 1

run_test 8000 server temporary
run_test 8000 server persistent

run_test 8000 client temporary
run_test 8000 client persistent

cleanup

