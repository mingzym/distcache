#!/bin/sh

# This script helps sanitise the source code for bad practises
TMPFILE=.sweepfile

# 1. no direct use of malloc and friends, all should go through the SYS_***
# versions. NB: this means don't use the string "malloc" in error messages. :-)

find . -name "*.[ch]" -not -name "post.h" \
	-exec sh -c "egrep -H -n '[^_]malloc\(' {}" \; > $TMPFILE
find . -name "*.[ch]" -not -name "post.h" \
	-exec sh -c "egrep -H -n '[^_]realloc\(' {}" \; >> $TMPFILE
find . -name "*.[ch]" -not -name "post.h" \
	-exec sh -c "egrep -H -n '[^_]free\(' {}" \; >> $TMPFILE
find . -name "*.[ch]" -not -name "post.h" \
	-exec sh -c "egrep -H -n '[^_]memset\(' {}" \; >> $TMPFILE
find . -name "*.[ch]" -not -name "post.h" \
	-exec sh -c "egrep -H -n '[^_]memcpy\(' {}" \; >> $TMPFILE
find . -name "*.[ch]" -not -name "post.h" \
	-exec sh -c "egrep -H -n '[^_]memmove\(' {}" \; >> $TMPFILE
find . -name "*.[ch]" -not -name "post.h" \
	-exec sh -c "egrep -H -n '[^_]stdin\(' {}" \; >> $TMPFILE
find . -name "*.[ch]" -not -name "post.h" \
	-exec sh -c "egrep -H -n '[^_]stdout\(' {}" \; >> $TMPFILE
find . -name "*.[ch]" -not -name "post.h" \
	-exec sh -c "egrep -H -n '[^_]stderr\(' {}" \; >> $TMPFILE
find . -name "*.[ch]" -not -name "post.h" \
	-exec sh -c "egrep -H -n '[^_]fprintf\(' {}" \; >> $TMPFILE
find . -name "*.[ch]" -not -name "post.h" \
	-exec sh -c "egrep -H -n '[^_]strncpy\(' {}" \; >> $TMPFILE
find . -name "*.[ch]" -not -name "post.h" \
	-exec sh -c "egrep -H -n '[^_]strdup\(' {}" \; >> $TMPFILE
find . -name "*.[ch]" -not -name "post.h" -not -name "sys.c" \
	-exec sh -c "egrep -H -n '[^_]getpid\(' {}" \; >> $TMPFILE
find . -name "*.[ch]" -not -name "post.h" -not -name "sys.c" \
	-exec sh -c "egrep -H -n '[^_]daemon\(' {}" \; >> $TMPFILE
find . -name "*.[ch]" -not -name "post.h" -not -name "sys.c" \
	-exec sh -c "egrep -H -n '[^_]setuid\(' {}" \; >> $TMPFILE
if [ "x`cat $TMPFILE`" != "x" ]; then
	echo "Invalid uses of system functions have been found in the code."
	echo "These must be replaced by SYS_*** equivalents."
	echo "The grep output follows;"
	cat $TMPFILE
	exit 1
fi

echo "OK"
exit 0
