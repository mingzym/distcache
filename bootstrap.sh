#!/bin/sh

# This script handles grinding the GNU autotools. From a fresh CVS checkout, you
# need to run this - and it assumes your machine has autoconf, automake, and
# libtool installed. From then onwards, you probably don't need to run this as
# changes to the metafiles (Makefile.am, configure.in, etc) should be
# automatically handled by the generated Makefile anyway.

set -x

if [ ! -d config ]; then
	mkdir config
fi

aclocal
autoheader

# Work around for a bug in libtoolize versions up to and including 1.4.2.
# libtoolize will look for 'AC_CONFIG_AUX_DIR' in configure.in, even though
# it's aware that configure.ac exists.
echo > 'configure.in' `grep '^AC_CONFIG_AUX_DIR' configure.ac`
libtoolize --copy --automake
# Remove the temporary file.
rm 'configure.in'

automake --foreign --add-missing --copy
autoconf
