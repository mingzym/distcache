#!/bin/sh

# This script handles unwinding the GNU autotools.
# 
# Running this script should (hopefully) clean up any/all gunge left lying
# around from the autotools - ie. leaving you with something resembling as
# closely as possible the state of CVS.

if [ -f Makefile ]; then
	make distclean
fi

# Zilch any "*.in" files except configure.in, and zilch configure too
find . -type f -name "*.in" | egrep -v "configure.in$" | xargs rm -f
rm -f configure

# Zilch miscellaneous generated files
find . -type f -name "aclocal.m4*" | xargs rm -f
rm -f config.*
rm -f conftest*
rm -f depcomp
rm -f install-sh ltmain.sh missing mkinstalldirs
rm -f stamp-h.in
rm -f aclocal.m4
rm -rf autom4te*.cache

# If the config/ directory exists, blow it away
#if [ -d config ]; then
#	rm -rf config/
#fi

# Residual backup files and what-not
find . -type f -name "*~" | xargs rm -f
find . -type f -name "*.bak" | xargs rm -f
find . -type f -name ".#*" | xargs rm -f

# Get rid of packaging byproducts
rm -f .packagelist
rm -rf .temppackagedir

# Clean autoconf stuff that autoconf itself doesn't clean
rm -f config.status

