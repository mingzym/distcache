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
TESTSESS="$THISDIR/test/test_session -timeout 30 -timevar 10 -ops 20000"
TESTSESSP="$TESTSESS -persistent"

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

start_daemon() {
	cmd=$1
	cute=$2
	# TODO: Should we check the service is started?
	$cmd 1> /dev/null 2> /dev/null && echo "... SUCCESS" && return 0
	BAILREASON=" failure starting '$cute'"
	bang
	return 1
}

run_test() {
	cmd=$1
	cute=$2
	$cmd 1> /dev/null 2> /dev/null && echo "... SUCCESS" && return 0
	echo "... FAILED running '$cute'"
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

echo "Starting dc_server daemon on $DC_SERVER_UNIX ..."
start_daemon "$DC_SERVER" "dc_server" || exit 1
echo "Starting dc_client daemon on $DC_CLIENT_UNIX ..."
start_daemon "$DC_CLIENT" "dc_client" || exit 1

echo ""

sleep 1

echo "Testing direct to dc_server, using temporary connections ..."
run_test "$TESTSESS -connect UNIX:$DC_SERVER_UNIX" "test_session" || echo "continuing anyway"
echo "Testing direct to dc_server, using persistent connections ..."
run_test "$TESTSESSP -connect UNIX:$DC_SERVER_UNIX" "test_session" || echo "continuing anyway"

echo "Testing through dc_client, using temporary connections ..."
run_test "$TESTSESS -connect UNIX:$DC_CLIENT_UNIX" "test_session" || echo "continuing anyway"
echo "Testing through dc_client, using persistent connections ..."
run_test "$TESTSESSP -connect UNIX:$DC_CLIENT_UNIX" "test_session" || echo "continuing anyway"

cleanup

