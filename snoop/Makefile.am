INCLUDES=-I$(top_srcdir)/include -I$(top_builddir)/config

bin_PROGRAMS	 = dc_snoop
dc_snoop_SOURCES= snoop.c
dc_snoop_LDADD	 = $(top_builddir)/libdistcache/libdistcache.la \
		   $(top_builddir)/libnal/libnal.la

