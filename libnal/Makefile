MAKE=make -s

THISDIR=libnal/
TOP=../
DIRNAME=libnal
LIBNAME=$(TOP)libnal.a

# Due to some quirky make/shell combinations - if this is non-empty, you'll
# need to add the "for" loops back in the build, clean, and depend targets
SUBDIRS=

OURSRCS=bincoding.c mem.c net.c streams.c sys.c
OUROBJS=bincoding.o mem.o net.o streams.o sys.o

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

$(LIBNAME): $(OUROBJS)
	$(AR) $(LIBNAME) $(OUROBJS)
	$(RANLIB) $(LIBNAME)

# DO NOT DELETE THIS LINE -- make depend depends on it.

bincoding.o: ../libnal/common.h ../libnal/nal.h
mem.o: ../libnal/common.h
net.o: ../libnal/common.h ../libnal/nal.h ../libnal/nal_internal.h
streams.o: common.h
sys.o: ../libnal/common.h
