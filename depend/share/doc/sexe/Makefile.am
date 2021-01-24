
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

html: doxyfile.stamp

if HAVE_HELP2MAN
dist_man_MANS = \
	man/man1/sxsh.1 \
	man/man1/sx.1 \
	man/man1/sxc.1 \
	man/man1/readsexe.1
endif

doxyfile.stamp:
	mkdir -p html man/man1
	$(DOXY_PROG) doxygen.conf
	$(MAN_PROG) --output=man/man1/sxsh.1 --name='sexe command-line interpreter' $(top_builddir)/src/sexe/shell/sxsh$(EXEEXT)
	$(MAN_PROG) --output=man/man1/readsexe.1 --name='sexe bytecode symbol list' $(top_builddir)/src/sexe/readsexe$(EXEEXT)
	$(MAN_PROG) --output=man/man1/sx.1 --name='sexe bytecode interpreter' $(top_builddir)/src/sexe/sx$(EXEEXT)
	$(MAN_PROG) --output=man/man1/sxc.1 --name='sexe bytecode compiler' $(top_builddir)/src/sexe/sxc$(EXEEXT)
	echo Timestamp > doxyfile.stamp

#	$(MAN_PROG) --output=man/man1/sxshd.1 --name='sexe command-line interpreter daemon' $(top_builddir)/src/sexe/shell/sxshd

man/man1/sxsh.1: doxyfile.stamp
man/man1/readsexe.1: doxyfile.stamp
man/man1/sx.1: doxyfile.stamp
man/man1/sxc.1: doxyfile.stamp

all-local: doxyfile.stamp
clean-local:
	rm -rf $(builddir)/html doxyfile.stamp

