MAKE=make -s

THISDIR=test/
TOP=../
DIRNAME=test
TARGETS=$(TOP)test_session$(SUFFIX)
OSSL_INC=-I$(TOP)../openssl-0.9.7-dev/include
OSSL_LIB=-L$(TOP)../openssl-0.9.7-dev -lssl -lcrypto
LIB_SESSION=$(TOP)libdistcacheserver.a $(TOP)libdistcache.a

# Due to some quirky make/shell combinations - if this is non-empty, you'll
# need to add the "for" loops back in the build, clean, and depend targets
SUBDIRS=

OURSRCS=test_session.c
OUROBJS=test_session.o

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
	$(COMPILE) $(OSSL_INC) $<

# The top-level makefile calls these targets with "COMPILE", "LINK", "LINKLIBS",
# "AR", "RANLIB", and "STRIP" constructed for us (including any path-dependant
# flags).

$(TOP)test_session$(SUFFIX): test_session.o $(LOCALLIBS) $(LIB_SESSION)
	echo "$(LINK) $(TOP)test_session$(SUFFIX) test_session.o $(OSSL_LIB) $(LIB_SESSION) $(LOCALLIBS) $(EXTLIBS)"
	$(LINK) $(TOP)test_session$(SUFFIX) test_session.o $(OSSL_LIB) $(LIB_SESSION) $(LOCALLIBS) $(EXTLIBS)
	$(STRIP) $(TOP)test_session$(SUFFIX)

# DO NOT DELETE THIS LINE -- make depend depends on it.

test_session.o: ../libnal/common.h ../libnal/nal.h
test_session.o: ../libdistcache/dc_client.h ../libdistcache/dc_enc.h
test_session.o: ../libdistcacheserver/dc_server.h
