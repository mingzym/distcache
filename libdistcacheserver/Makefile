MAKE=make -s

THISDIR=libdistcacheserver/
TOP=../
DIRNAME=libdistcacheserver
TARGETS=$(TOP)libdistcacheserver.a

# Due to some quirky make/shell combinations - if this is non-empty, you'll
# need to add the "for" loops back in the build, clean, and depend targets
SUBDIRS=

OURSRCS=dc_server.c dc_server_default.c
OUROBJS=dc_server.o dc_server_default.o

default: build

# We need to pass TOP and LIBNAME back to the top-level makefile so it can
# invoke our library target and pass a "COMPILE" symbol with correctly
# constructed includes (ie. it can get the path correct relative to us).
build:
	@for i in $(TARGETS) ; do \
	(cd $(TOP) ; $(MAKE) SUBDIR='$(THISDIR)' TOP='$(TOP)' \
		LIBNAME=$$i sdir) || exit 1 ; done
#	@for i in $(SUBDIRS) ; do \
#	(cd $$i && $(MAKE) build) || exit 1 ; done

clean:
	@(cd $(TOP) ; $(MAKE) SUBDIR='$(THISDIR)' \
		SPECIFICS='$(OUROBJS) $(TARGETS)' sclean)
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


$(TOP)libdistcacheserver.a: $(OUROBJS)
	$(AR) $(TOP)libdistcacheserver.a $(OUROBJS)
	$(RANLIB) $(TOP)libdistcacheserver.a

# DO NOT DELETE THIS LINE -- make depend depends on it.

dc_server.o: ../libnal/common.h ../libnal/nal.h
dc_server.o: ../libdistcacheserver/dc_server.h ../libdistcache/dc_enc.h
dc_server_default.o: ../libnal/common.h ../libnal/nal.h
dc_server_default.o: ../libdistcache/dc_enc.h
dc_server_default.o: ../libdistcacheserver/dc_server.h
