INCLUDES		= -I$(top_srcdir)/include -I$(top_builddir)

bin_PROGRAMS	 	= dc_server
dc_server_SOURCES	= server.c
dc_server_LDADD	 	= $(top_builddir)/libsys/libsys.la \
			  $(top_builddir)/libdistcacheserver/libdistcacheserver.la \
			  $(top_builddir)/libdistcache/libdistcache.la \
			  $(top_builddir)/libnal/libnal.la

