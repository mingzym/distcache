#!/bin/sh

BAILOUT=no
BAILREASON=""
THISDIR=`pwd`
SSERVER_PROG="$THISDIR/sessserver/sserver"
SSERVER_UNIX="$THISDIR/unix.sserver"
SSERVER_PID="$THISDIR/pid.sserver"
SCLIENT_PROG="$THISDIR/sessclient/sclient"
SCLIENT_UNIX="$THISDIR/unix.sclient"
SCLIENT_PID="$THISDIR/pid.sclient"
TESTSESS="$THISDIR/test/test_session -timeout 30 -timevar 10 -ops 20000"
TESTSESSP="$TESTSESS -persistent"

SSERVER="$SSERVER_PROG -listen UNIX:$SSERVER_UNIX -pidfile $SSERVER_PID -daemon"
SCLIENT="$SCLIENT_PROG -listen UNIX:$SCLIENT_UNIX -pidfile $SCLIENT_PID -daemon -server UNIX:$SSERVER_UNIX"

cleanup() {
	if [ -f "$SSERVER_PID" ]; then
		kill `cat $SSERVER_PID` || echo "couldn't kill 'sserver'!"
	fi
	if [ -f "$SCLIENT_PID" ]; then
		kill `cat $SCLIENT_PID` || echo "couldn't kill 'sclient'!"
	fi
	rm -f $SSERVER_PID $SSERVER_UNIX
	rm -f $SCLIENT_PID $SCLIENT_UNIX
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

if [ ! -x "$SSERVER_PROG" ]; then
	echo "Either you haven't compiled the source-code or you are executing"
	echo "from the wrong directory. Please run this script from the top-level"
	echo "directory, ie;"
	echo "   ./devel/test.sh"
	BAILOUT=yes
	BAILREASON="$BAILREASON ($SSERVER_PROG not found)"
fi

if [ -f "$SSERVER_PID" ]; then
	BAILOUT=yes
	BAILREASON="$BAILREASON (pid.sserver exists)"
fi

if [ -S "$SSERVER_UNIX" ]; then
	BAILOUT=yes
	BAILREASON="$BAILREASON (unix.sserver exists)"
fi

if [ "x$BAILOUT" != "xno" ]; then
	bang
fi

echo "Starting sserver daemon on $SSERVER_UNIX ..."
start_daemon "$SSERVER" "sserver" || exit 1
echo "Starting sclient daemon on $SCLIENT_UNIX ..."
start_daemon "$SCLIENT" "sclient" || exit 1

echo ""

sleep 1

echo "Testing direct to sserver, using temporary connections ..."
run_test "$TESTSESS -connect UNIX:$SSERVER_UNIX" "test_session" || echo "continuing anyway"
echo "Testing direct to sserver, using persistent connections ..."
run_test "$TESTSESSP -connect UNIX:$SSERVER_UNIX" "test_session" || echo "continuing anyway"

echo "Testing through sclient, using temporary connections ..."
run_test "$TESTSESS -connect UNIX:$SCLIENT_UNIX" "test_session" || echo "continuing anyway"
echo "Testing through sclient, using persistent connections ..."
run_test "$TESTSESSP -connect UNIX:$SCLIENT_UNIX" "test_session" || echo "continuing anyway"

cleanup

