#!/bin/sh

# This script handles grinding the GNU autotools. From a fresh CVS checkout, you
# need to run this - and it assumes your machine has autoconf, automake, and
# libtool installed. From then onwards, you probably don't need to run this as
# changes to the metafiles (Makefile.am, configure.in, etc) should be
# automatically handled by the generated Makefile anyway.

#set -x

produce_stuff()
{
aclocal
autoheader
libtoolize --copy --automake
automake --foreign --add-missing --copy
autoconf

# Finally, get rid of the crud generated by autoheader (and automake if you put
# the 'rm' before it!) This is to make sure the generated tree is suitable for
# packaging - if the host system really has auto<whatever> and it wants to
# regenerate stuff, it can recreate the cache directory itself.
rm -rf autom4te*
}

# Produce the ssl/configure.ac using ssl/configure.ac.template
export DC_VER=`cat configure.ac | grep 'AC_INIT(' | \
	sed 's/^.*distcache, //' | sed 's/, distcache-users.*$//'`
(cd ssl / && \
	echo "# DO NOT EDIT THIS FILE" > configure.ac &&
	echo "# IT IS AUTOMATICALLY GENERATED FROM configure.ac.template" >> configure.ac && \
	cat configure.ac.template | \
	sed "s/^AC_INIT(.*)/AC_INIT(distcache-ssl, $DC_VER, distcache-users@lists.sourceforge.net)/" | \
	sed "s/^AM_INIT_AUTOMAKE(.*)/AM_INIT_AUTOMAKE(distcache-ssl, $DC_VER)/" >> configure.ac )

# Run the routine in this directory and then the required sub-directories
produce_stuff || exit 1
(cd ssl/ && produce_stuff) || exit 1

# Now handle preset environment variables
if [ "x$PRECONF" = "x" ]; then
	echo ""
	echo "No PRECONF environment variable set, will not run ./configure"
	echo ""
	echo "To preconfigure, set PRECONF to one of the following;"
	echo "   gcc-RELEASE"
	echo "   gcc-DEBUG"
	echo "PREFLAGS, if it is set, will be passed to ./configure in"
	echo "addition to any parameters provided to this script on the"
	echo "command line."
	echo ""
else
	CONFFLAGS="--enable-ssl --enable-swamp --disable-shared"
	if [ "$PRECONF" = "gcc-RELEASE" ]; then
		export CFLAGS="-Wall -O3 -fomit-frame-pointer -DNDEBUG"
	elif [ "$PRECONF" = "gcc-DEBUG" ]; then
		export CFLAGS="-Wall -pedantic -Wundef -Wshadow -Wpointer-arith \
		-Wbad-function-cast -Wcast-qual -Wcast-align \
		-Wsign-compare -Wmissing-prototypes \
		-Wmissing-declarations -Wredundant-decls -Wwrite-strings \
		-g -ggdb3 -Werror"
	else
		echo "Error, '$PRECONF' is not recognised as a value for PRECONF"
		exit 1
	fi
	./configure $CONFFLAGS $PREFLAGS $@ || exit 1
fi

