AM_CFLAGS = -DDATADIR=\"$(datadir)\"
htmldir = html 
dist_docdir = $(datadir)/@PACKAGE@


if HAVE_HELP2MAN
dist_man_MANS = \
	man/man1/shcoin.1 \
	man/man1/shcoind.1

man/man1/shcoin.1: helpfile.stamp
man/man1/shcoind.1: helpfile.stamp

helpfile.stamp:
	mkdir -p man/man1
	$(HELP2MAN) --output=man/man1/shcoin.1 --name='share-coin command-line tool' $(top_builddir)/src/share-coin/shcoin
	$(HELP2MAN) --output=man/man1/shcoind.1 --name='share-coin daemon' $(top_builddir)/src/share-coin/shcoind
	echo Timestamp > helpfile.stamp
endif


if HAVE_DOXYGEN
dist_doc_DATA = shcoin_html.tar.gz

$(htmldir): doxyfile.stamp

doxyfile.stamp:
	mkdir -p html man
	$(DOXYGEN) doxygen.conf
	echo Timestamp > doxyfile.stamp

shcoin_html.tar.gz: doxyfile.stamp
	rm -f shcoin_html.tar.gz
	tar -cpf shcoin_html.tar $(htmldir)
	gzip shcoin_html.tar
	rm -f shcoin_html.tar
endif

EXTRA_DIST = $(htmldir)

clean-local:
	rm -f doxyfile.stamp helpfile.stamp
	rm -rf $(builddir)/man
	rm -rf $(builddir)/html
