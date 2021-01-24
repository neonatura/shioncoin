
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
	man/man1/shcat.1 \
	man/man1/shdiff.1 \
	man/man1/shdelta.1 \
	man/man1/shpatch.1 \
	man/man1/shcp.1 \
	man/man1/shln.1 \
	man/man1/shstat.1 \
	man/man1/shls.1 \
	man/man1/shattr.1 \
	man/man1/shpref.1 \
	man/man1/shrm.1 \
	man/man1/shgeo.1 \
	man/man1/shalg.1 \
	man/man1/shrev.1 \
	man/man1/shz.1 \
	man/man1/shpasswd.1 \
	man/man1/shinfo.1 \
	man/man1/shpkg.1 \
	man/man1/shdb.1 \
	man/man1/shcert.1 \
	man/man1/shfsck.1
endif


man/man1/shcat.1: helpfile.stamp
man/man1/shdiff.1: helpfile.stamp
man/man1/shdelta.1: helpfile.stamp
man/man1/shpatch.1: helpfile.stamp
man/man1/shcp.1: helpfile.stamp
man/man1/shln.1: helpfile.stamp
man/man1/shstat.1: helpfile.stamp
man/man1/shls.1: helpfile.stamp
man/man1/shattr.1: helpfile.stamp
man/man1/shpref.1: helpfile.stamp
man/man1/shrm.1: helpfile.stamp
man/man1/shgeo.1: helpfile.stamp
man/man1/shalg.1: helpfile.stamp
man/man1/shrev.1: helpfile.stamp
man/man1/shz.1: helpfile.stamp
man/man1/shpasswd.1: helpfile.stamp
man/man1/shinfo.1: helpfile.stamp
man/man1/shpkg.1: helpfile.stamp
man/man1/shdb.1: helpfile.stamp
man/man1/shcert.1: helpfile.stamp
man/man1/shfsck.1: helpfile.stamp

helpfile.stamp:
	mkdir -p man/man1
	$(MAN_PROG) --output=man/man1/shcat.1 --name='libshare command-line tool' $(top_builddir)/src/share-util/static/shcat$(EXEEXT)
	$(MAN_PROG) --output=man/man1/shstat.1 --name='libshare command-line tool' $(top_builddir)/src/share-util/static/shstat$(EXEEXT)
	$(MAN_PROG) --output=man/man1/shls.1 --name='libshare command-line tool' $(top_builddir)/src/share-util/static/shls$(EXEEXT)
	$(MAN_PROG) --output=man/man1/shattr.1 --name='libshare command-line tool' $(top_builddir)/src/share-util/static/shattr$(EXEEXT)
	$(MAN_PROG) --output=man/man1/shpref.1 --name='libshare command-line tool' $(top_builddir)/src/share-util/static/shpref$(EXEEXT)
	$(MAN_PROG) --output=man/man1/shrm.1 --name='libshare command-line tool' $(top_builddir)/src/share-util/static/shrm$(EXEEXT)
	$(MAN_PROG) --output=man/man1/shalg.1 --name='libshare command-line tool' $(top_builddir)/src/share-util/static/shalg$(EXEEXT)
	$(MAN_PROG) --output=man/man1/shrev.1 --name='libshare command-line tool' $(top_builddir)/src/share-util/static/shrev$(EXEEXT)
	$(MAN_PROG) --output=man/man1/shz.1 --name='libshare command-line tool' $(top_builddir)/src/share-util/static/shz$(EXEEXT)
	$(MAN_PROG) --output=man/man1/shpasswd.1 --name='libshare command-line tool' $(top_builddir)/src/share-util/static/shpasswd$(EXEEXT)
	$(MAN_PROG) --output=man/man1/shinfo.1 --name='libshare command-line tool' $(top_builddir)/src/share-util/static/shinfo$(EXEEXT)
	$(MAN_PROG) --output=man/man1/shpkg.1 --name='libshare command-line tool' $(top_builddir)/src/share-util/static/shpkg$(EXEEXT)
	$(MAN_PROG) --output=man/man1/shdb.1 --name='libshare command-line tool' $(top_builddir)/src/share-util/static/shdb$(EXEEXT)
	$(MAN_PROG) --output=man/man1/shgeo.1 --name='libshare command-line tool' $(top_builddir)/src/share-util/static/shgeo$(EXEEXT)
	$(MAN_PROG) --output=man/man1/shalg.1 --name='libshare command-line tool' $(top_builddir)/src/share-util/static/shalg$(EXEEXT)
	$(MAN_PROG) --output=man/man1/shcert.1 --name='libshare command-line tool' $(top_builddir)/src/share-util/static/shcert$(EXEEXT)
	$(MAN_PROG) --output=man/man1/shfsck.1 --name='libshare command-line tool' $(top_builddir)/src/share-util/static/shfsck$(EXEEXT)
	$(MAN_PROG) --output=man/man1/shdiff.1 --name='libshare command-line tool' $(top_builddir)/src/share-util/static/shdiff$(EXEEXT)
	$(MAN_PROG) --output=man/man1/shdelta.1 --name='libshare command-line tool' $(top_builddir)/src/share-util/static/shdelta$(EXEEXT)
	$(MAN_PROG) --output=man/man1/shpatch.1 --name='libshare command-line tool' $(top_builddir)/src/share-util/static/shpatch$(EXEEXT)
	$(MAN_PROG) --output=man/man1/shcp.1 --name='libshare command-line tool' $(top_builddir)/src/share-util/static/shcp$(EXEEXT)
	$(MAN_PROG) --output=man/man1/shln.1 --name='libshare command-line tool' $(top_builddir)/src/share-util/static/shln$(EXEEXT)
	echo Timestamp > helpfile.stamp

html: doxyfile.stamp

doxyfile.stamp:
	mkdir -p html man
	$(DOXY_PROG) doxygen.conf
	echo Timestamp > doxyfile.stamp

CLEANFILES = helpfile.stamp
all-local: doxyfile.stamp helpfile.stamp
clean-local:
	rm -rf $(builddir)/html $(builddir)/man doxyfile.stamp helpfile.stamp

