CC=gcc
RM=rm -f
MAKE=make -s
MAKEDEP=makedepend
AR=ar -r
RANLIB=ranlib

# Used to quickly add extra flags ...
CDEFINES=
# Tweak these settings to alter debugging/release options
DSTRIP=echo "not stripping debug builds: "
RSTRIP=strip
# I'd like to add "-Wcoversion" but it blows goats all over some linux headers.
# I'd also like to add "-Wstrict-prototypes" and "-Wredundant-decls", but they
# puke on OpenSSL headers.
DCOTHERS=-Wall -Werror -Wcast-align -Wcast-qual -Wmissing-prototypes \
	-Wmissing-declarations -Wpointer-arith -Wshadow -Wwrite-strings \
	-g -ggdb3
RCOTHERS=-Wall -Werror -Wcast-align -Wcast-qual -Wmissing-prototypes \
	-Wmissing-declarations -Wpointer-arith -Wshadow -Wwrite-strings \
	-O3 -DNDEBUG

# Default to "release" settings
STRIP=$(RSTRIP)
COTHERS=$(RCOTHERS)

CFLAGS=-c $(CDEFINES) $(COTHERS)

# To compile on CygWin, set "SUFFIX" equal to .exe
#SUFFIX=.exe
SUFFIX=

# To compile on CygWin (and some others), remove "-ldl"
PLATFORMLIBS=-ldl

# To compile on CygWin (and some others), add NO_DAEMON_FN
#PLATFORMDEFNS=-DNO_DAEMON_FN
PLATFORMDEFNS=

# The subdirectories that contain real work to do!
SUBDIRS=libnal libdistcache libdistcacheserver sessclient sessserver test

# These are the local libraries used when linking (can be used in dependencies)
LOCALLIBS=$(TOP)libnal.a
# These are the external libraries used when linking
EXTLIBS=$(PLATFORMLIBS)

# Prepared Commands
INCLUDES=-I$(TOP)
COMPILE=$(CC) $(EXTCFLAGS) $(CFLAGS) $(PLATFORMDEFNS) $(INCLUDES)
LINK=$(CC) -o
# Flags for the makedepend
MAKEDEPFLAGS=-f Makefile -m -- $(CFLAGS) $(INCLUDES) -- -DIN_MAKEDEPEND

default: build

build:
	@for i in $(SUBDIRS) ; do \
	(cd $$i && $(MAKE) SUFFIX='$(SUFFIX)') || exit 1 ; done

# Apart from running the "regular" rules on this directory and all the SUBDIRs,
# we also take the chance to apply manual cleaning to dumb directories - ie.
# directories that just store files.
clean:
	@$(MAKE) SUBDIR="./" sclean
	@for i in $(SUBDIRS) ; do \
	(cd $$i && $(MAKE) SUFFIX='$(SUFFIX)' clean) || exit 1 ; done

depend:
	@for i in $(SUBDIRS) ; do \
	(cd $$i && $(MAKE) depend) || exit 1 ; done

# Build a shared library
shared: build
	gcc -shared -o libsession.so -Wl,-S,-soname=libsession \
		-Wl,--whole-archive libsession.a \
		-Wl,--no-whole-archive libnal.a
	$(STRIP) libsession.so

# This is like the previous target, except it builds a shared library
# for Solaris/cc systems. The syntax was taken in part from OpenSSL's
# solaris-shared target in the top-level Makefile.ssl.
solaris-shared: build
	cc -G -o libsession.so -h libsession \
		-z allextract libsession.a \
		-z weakextract \
		libnal.a \


# Recursive "callbacks" - this is where subdirectory makefiles have passed
# control back to us so we can in turn pass it back to them with the settings
# they require (so the settings are all maintained in this top-level makefile).

# sdir is called so we can call a target in that makefile with the right
# settings.
sdir:
	@echo ""
	@echo "building in $(SUBDIR): target '$(LIBNAME)'"
	@(cd $(SUBDIR) && $(MAKE) AR='$(AR)' RANLIB='$(RANLIB)' \
		COMPILE='$(COMPILE)' LINK='$(LINK)' \
		LOCALLIBS='$(LOCALLIBS)' EXTLIBS='$(EXTLIBS)' \
		STRIP='$(STRIP)' SUFFIX='$(SUFFIX)' \
		$(LIBNAME)) || exit 1

# sclean is called so we can clean that directory - it passes us any specific
# files and we add the usual extras
sclean:
	@echo "cleaning in $(SUBDIR)"
	(cd $(SUBDIR) && $(RM) $(SPECIFICS) *.bak *~ core *.so) || exit 1

# sdepend is called so we can build dependencies in that directory
sdepend:
	@echo "creating dependencies in $(SUBDIR)"
	@(cd $(SUBDIR) && cp Makefile Makefile.old && \
		echo "$(MAKEDEP) $(MAKEDEPFLAGS) $(SPECIFICS)" && \
		$(MAKEDEP) $(MAKEDEPFLAGS) $(SPECIFICS) && \
		$(RM) Makefile.old) || exit 1

# DO NOT DELETE THIS LINE -- make depend depends on it.

