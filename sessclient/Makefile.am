INCLUDES=-I$(top_srcdir)

bin_PROGRAMS		= sclient
sclient_SOURCES		= clients.c multiplexer.c private.h sclient.c \
		   	  server.c
sclient_LDADD		= $(top_builddir)/libdistcache/libdistcache.la \
		 	  $(top_builddir)/libnal/libnal.la

