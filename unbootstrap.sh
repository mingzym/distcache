#!/bin/sh

# This script handles unwinding the GNU autotools.
#
# Running this script should (hopefully) clean up any/all gunge left lying
# around from the autotools - ie. leaving you with something resembling as
# closely as possible the state of CVS.

undo_stuff()
{
# Zilch any "Makefile.in" files, and zilch configure too
find . -type f -name "Makefile.in" | xargs rm -f
rm -f configure

# Zilch miscellaneous generated files
find . -type f -name "aclocal.m4*" | xargs rm -f
rm -f aclocal.m4
rm -rf autom4te*.cache
rm -f config.*
rm -f conftest*
rm -f depcomp compile libtool
rm -f install-sh ltmain.sh missing mkinstalldirs
rm -f stamp-h*
rm -f .sweepfile

# Residual backup files and what-not
find . -type f -name "*~" | xargs rm -f
find . -type f -name "*.bak" | xargs rm -f
find . -type f -name ".#*" | xargs rm -f

# Get rid of packaging byproducts
rm -f .packagelist
rm -rf .temppackagedir
rm -f distcache-*.tar.*

# Clean autoconf stuff that autoconf itself doesn't clean
rm -f config.status
}

# Before running the "rm" operations, use autotool cleanup
if [ -f Makefile ]; then
	make distclean
fi
if [ -f ssl/Makefile ]; then
	(cd ssl/ && make distclean) || exit 1
fi

# Run the routine in all required sub-directories and then this directory
(cd ssl/ && undo_stuff) || exit 1
undo_stuff || exit 1

# Finally, the ssl subdirectory derives configure.ac from configure.ac.template
rm -f ssl/configure.ac

