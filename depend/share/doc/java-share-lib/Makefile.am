if HAVE_DOXYGEN

html: doxyfile.stamp

doxyfile.stamp:
	mkdir -p html
	$(DOXYGEN) doxygen.conf
	echo Timestamp > doxyfile.stamp

all-local: doxyfile.stamp
clean-local:
	rm -rf $(builddir)/html doxyfile.stamp
endif



