INCLUDES		= -I$(top_srcdir)/../include -I$(top_builddir)

bin_PROGRAMS		= swamp
swamp_SOURCES		= swamp.c text_msg.c utils.c swamp_conf.c \
		 	  dist_pattern.c serv_iterator.c
swamp_LDADD		= $(top_builddir)/../libsys/libsys.a \
			  $(top_builddir)/../libnal/libnal.a

swamp_manpagelist	= swamp.1
swamp_podlist		= swamp.pod
# FIXME: Disabling HTML builds for the same reason as in ../../doc/Makefile.am
#swamp_htmllist		= swamp.html
#
#EXTRA_DIST		= $(swamp_manpagelist) $(swamp_htmllist) $(swamp_podlist)
EXTRA_DIST		= $(swamp_manpagelist) $(swamp_podlist)

CLEANFILES		= *.1 *.html

man_MANS		= $(swamp_manpagelist)

docdir			= $(datadir)/doc/swamp
#doc_DATA		= $(swamp_htmllist)

SUFFIXES		= .pod .1 .html

.pod.1:
	pod2man --section=1 --release=@VERSION@ --center=distcache --date=`date +%Y.%m.%d` \
	$< $@

#.pod.html:
#	echo "FIXME" && exit 1
#
