EXTRA_DIST	= ANNOUNCE BUGS CHANGES FAQ LICENSE depcomp
ACLOCAL_AMFLAGS = -I build

if COND_SSL
  MAYBE_SSL = ssl
endif

SUBDIRS		= libsys libnal libdistcache libdistcacheserver \
		  sessclient sessserver snoop test util \
		  doc include devel $(MAYBE_SSL)
