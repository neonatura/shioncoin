if LIBSHARE_JAVA
if HAVE_SWIG
BUILT_SOURCES = libshare_java_wrap.c

swig_includes = -I$(top_srcdir)/src/share-lib -I$(top_srcdir)/src/share-lib/java 

SWIG_JAVA_OPT = $(swig_includes) -java -package net.sharelib -outdir $(srcdir)
SWIG_CONF = $(srcdir)/libshare_java.i

libshare_java_wrap.c: $(srcdir)/libshare_java.i
	$(SWIG_PROG) $(SWIG_JAVA_OPT) $(SWIG_CONF)
endif
endif
