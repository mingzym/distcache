EXTRA_DIST = distcache.pod \
	     distcache.8 \
	     dc_server.1 dc_client.1 dc_snoop.1 dc_test.1

CLEANFILES = *.8 *.1 *.html

man_MANS = distcache.8 \
	   dc_server.1 dc_client.1 dc_snoop.1 dc_test.1

docdir = $(datadir)/doc/distcache
doc_DATA = distcache.html \
	   dc_server.html dc_client.html dc_snoop.html dc_test.html

SUFFIXES = .pod .1 .8 .html

# FIXME: "--release=0.3" should be replaced with something automatic
.pod.1:
	pod2man --section=1 --release=0.3 --center=distcache --date=`date +%Y.%m.%d` \
	$< $@

# FIXME: "--release=0.3" should be replaced with something automatic
.pod.8:
	pod2man --section=8 --release=0.3 --center=distcache --date=`date +%Y.%m.%d` \
	$< $@

.pod.html:
	pod2html --infile=$< --outfile=$@ --title distcache.8
	rm -f pod2htmd.x~~ pod2htmi.x~~

