

noinst_SCRIPTS = \
	.notice \
	libshare.a

noinst_PROGRAMS = \
	sx sxc readsexe sxsh

if WINDOWS
else
noinst_SCRIPTS += \
	libshare.so libshare.so.6 \
	libshare.so.6.0.$(version_patch)
endif
if HAVE_DOXYGEN
noinst_SCRIPTS += html man
endif


html: $(top_builddir)/doc/libshare/html
	rm -rf html
	cp -fr $(top_builddir)/doc/libshare/html .

man: $(top_builddir)/doc/libshare/man
	rm -rf man
	cp -fr $(top_builddir)/doc/libshare/man .


.notice:
	@echo > .notice
	@echo ""
	@echo "The  libshare library and it's components has been built."
	@echo ""
	@echo "It is now safe to perform a 'make install'."
	@echo "Perform a 'make check' for additional tests afterwards."
	@echo ""
	@echo "Check out the 'bin/' directory for programs and libraries."
	@echo "Documentation is located in the bin/html/ directory."
	@echo ""


libshare.a:
	ln -sf $(top_builddir)/src/share-lib/.libs/libshare.a  .

libshare.so:
	ln -sf $(top_builddir)/src/share-lib/.libs/libshare.so . 

libshare.so.6:
	ln -sf $(top_builddir)/src/share-lib/.libs/libshare.so.6 .

libshare.so.6.0.$(version_patch):
	ln -sf $(top_builddir)/src/share-lib/.libs/libshare.so.6.0.$(version_patch) .


sx$(EXEEXT):
	ln -sf $(top_builddir)/src/sexe/.libs/sx$(EXEEXT) .

sxc$(EXEEXT):
	ln -sf $(top_builddir)/src/sexe/.libs/sxc$(EXEEXT) .

readsexe$(EXEEXT):
	ln -sf $(top_builddir)/src/sexe/.libs/readsexe$(EXEEXT) .

sxsh$(EXEEXT):
	ln -sf $(top_builddir)/src/sexe/shell/.libs/sxsh$(EXEEXT) .


