INCLUDES		= -I$(top_srcdir)/include -I$(top_builddir)

bin_PROGRAMS		= nal_echo nal_ping nal_hose nal_pong dc_test nal_test
dc_test_SOURCES		= dc_test.c
dc_test_LDADD		= $(top_builddir)/libsys/libsys.la \
			  $(top_builddir)/libdistcache/libdistcache.la \
		     	  $(top_builddir)/libnal/libnal.la
nal_test_SOURCES	= nal_test.c
nal_test_LDADD		= $(top_builddir)/libsys/libsys.la \
		  	  $(top_builddir)/libnal/libnal.la
nal_echo_SOURCES	= echo.c timing.h
nal_echo_LDADD		= $(top_builddir)/libsys/libsys.la \
		  	  $(top_builddir)/libnal/libnal.la
nal_ping_SOURCES	= ping.c timing.h
nal_ping_LDADD		= $(top_builddir)/libsys/libsys.la \
		  	  $(top_builddir)/libnal/libnal.la
nal_hose_SOURCES	= hose.c
nal_hose_LDADD		= $(top_builddir)/libsys/libsys.la \
		  	  $(top_builddir)/libnal/libnal.la
nal_pong_SOURCES	= pong.c
nal_pong_LDADD		= $(top_builddir)/libsys/libsys.la \
		  	  $(top_builddir)/libnal/libnal.la

