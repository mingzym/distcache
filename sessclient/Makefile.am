INCLUDES=-I$(top_srcdir)/include -I$(top_builddir)

bin_PROGRAMS		= dc_client
dc_client_SOURCES	= clients.c multiplexer.c private.h sclient.c \
		   	  server.c
dc_client_LDADD		= $(top_builddir)/libdistcache/libdistcache.a \
		 	  $(top_builddir)/libnal/libnal.a

