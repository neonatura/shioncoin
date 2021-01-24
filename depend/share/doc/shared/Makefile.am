CLEANFILES = helpfile.stamp

if HAVE_HELP2MAN
MAN_PROG=$(HELP2MAN)
else
MAN_PROG=true
endif

if HAVE_DOXYGEN
DOXY_PROG=$(DOXYGEN)
else
DOXY_PROG=true
endif

if HAVE_HELP2MAN
dist_man_MANS = \
	shared
endif

man/man1/shared.1: helpfile.stamp

helpfile.stamp:
	mkdir -p man/man1
	$(MAN_PROG) --output=man/man1/shared.1 --name='libshare transaction daemon' $(top_builddir)/src/share-daemon/shared$(EXEXT)
	echo Timestamp > helpfile.stamp

$(htmldir): doxyfile.stamp

doxyfile.stamp:
	mkdir -p html man
	$(DOXY_PROG) doxygen.conf
	echo Timestamp > doxyfile.stamp

all-local: doxyfile.stamp helpfile.stamp
clean-local:
	rm -f doxyfile.stamp helpfile.stamp
	rm -rf $(builddir)/man
	rm -rf $(builddir)/$(htmldir)

