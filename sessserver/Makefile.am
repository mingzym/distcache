INCLUDES=-I$(top_srcdir)/include -I$(top_builddir)

bin_PROGRAMS	 = dc_server
dc_server_SOURCES= server.c
dc_server_LDADD	 = $(top_builddir)/libsys/libsys.a \
		   $(top_builddir)/libdistcacheserver/libdistcacheserver.a \
		   $(top_builddir)/libdistcache/libdistcache.a \
		   $(top_builddir)/libnal/libnal.a

