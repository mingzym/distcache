MAKE=make -s

THISDIR=sessclient/
TOP=../
DIRNAME=sessclient
LIBNAME=$(TOP)sclient$(SUFFIX)
LIB_DISTCACHE=$(TOP)libdistcache.a

# Due to some quirky make/shell combinations - if this is non-empty, you'll
# need to add the "for" loops back in the build, clean, and depend targets
SUBDIRS=

OURSRCS=sclient.c clients.c server.c multiplexer.c
OUROBJS=sclient.o clients.o server.o multiplexer.o

default: build

# We need to pass TOP and LIBNAME back to the top-level makefile so it can
# invoke our library target and pass a "COMPILE" symbol with correctly
# constructed includes (ie. it can get the path correct relative to us).
build:
	@(cd $(TOP) ; $(MAKE) SUBDIR='$(THISDIR)' TOP='$(TOP)' \
		LIBNAME='$(LIBNAME)' sdir)
#	@for i in $(SUBDIRS) ; do \
#	(cd $$i && $(MAKE) build) || exit 1 ; done

clean:
	@(cd $(TOP) ; $(MAKE) SUBDIR='$(THISDIR)' \
		SPECIFICS='$(OUROBJS) $(LIBNAME)' sclean)
#	@for i in $(SUBDIRS) ; do \
#	(cd $$i && $(MAKE) clean) || exit 1 ; done

# Same thing applies as with "sdir"
depend:
	@(cd $(TOP) ; $(MAKE) SUBDIR='$(THISDIR)' TOP='$(TOP)' \
		SPECIFICS='$(OURSRCS)' sdepend)
#	@for i in $(SUBDIRS) ; do \
#	(cd $$i && $(MAKE) depend) || exit 1 ; done

.c.o:
	echo "$(COMPILE) $<"
	$(COMPILE) $<

# The top-level makefile calls this target with "COMPILE", "LINK", "LINKLIBS",
# "AR", "RANLIB", and "STRIP" constructed for us (including any path-dependant
# flags).

$(LIBNAME): $(OUROBJS) $(LOCALLIBS) $(LIB_DISTCACHE)
	echo "$(LINK) $(LIBNAME) $(OUROBJS) $(LIB_DISTCACHE) $(LOCALLIBS) $(EXTLIBS)"
	$(LINK) $(LIBNAME) $(OUROBJS) $(LIB_DISTCACHE) $(LOCALLIBS) $(EXTLIBS)
	$(STRIP) $(LIBNAME)

# DO NOT DELETE THIS LINE -- make depend depends on it.

sclient.o: ../libnal/common.h ../libnal/nal.h ../libdistcache/dc_enc.h
sclient.o: private.h
clients.o: ../libnal/common.h ../libnal/nal.h ../libdistcache/dc_enc.h
clients.o: private.h
server.o: ../libnal/common.h ../libnal/nal.h ../libdistcache/dc_enc.h
server.o: private.h
multiplexer.o: ../libnal/common.h ../libnal/nal.h ../libdistcache/dc_enc.h
multiplexer.o: private.h
