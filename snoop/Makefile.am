AM_CPPFLAGS		= -I$(top_srcdir)/include -I$(top_builddir)

bin_PROGRAMS	 	= dc_snoop
dc_snoop_SOURCES 	= snoop.c
dc_snoop_LDADD		= $(top_builddir)/libsys/libsys.la \
			  $(top_builddir)/libdistcache/libdistcache.la \
			  $(top_builddir)/libnal/libnal.la

