
noinst_LIBRARIES = libcdk.a

BUILT_SOURCES = \
	$(builddir)/scale.c \
	$(builddir)/uscale.c \
	$(builddir)/dscale.c \
	$(builddir)/fscale.c \
	$(builddir)/slider.c \
	$(builddir)/uslider.c \
	$(builddir)/fslider.c \
	$(builddir)/dscale.c

libcdk_a_SOURCES = \
	$(srcdir)/alphalist.c \
	$(srcdir)/binding.c \
	$(srcdir)/button.c \
	$(srcdir)/buttonbox.c \
	$(srcdir)/calendar.c \
	$(srcdir)/cdk.c \
	$(srcdir)/cdk_compat.c \
	$(srcdir)/cdk_display.c \
	$(srcdir)/cdk_objs.c \
	$(srcdir)/cdk_params.c \
	$(srcdir)/cdkscreen.c \
	$(srcdir)/debug.c \
	$(srcdir)/dialog.c \
	$(srcdir)/draw.c \
	$(srcdir)/entry.c \
	$(srcdir)/fselect.c \
	$(srcdir)/get_index.c \
	$(srcdir)/get_string.c \
	$(srcdir)/graph.c \
	$(srcdir)/histogram.c \
	$(srcdir)/itemlist.c \
	$(srcdir)/label.c \
	$(srcdir)/marquee.c \
	$(srcdir)/matrix.c \
	$(srcdir)/mentry.c \
	$(srcdir)/menu.c \
	$(srcdir)/popup_dialog.c \
	$(srcdir)/popup_label.c \
	$(srcdir)/position.c \
	$(srcdir)/radio.c \
	$(srcdir)/scroll.c \
	$(srcdir)/scroller.c \
	$(srcdir)/selection.c \
	$(srcdir)/swindow.c \
	$(srcdir)/select_file.c \
	$(srcdir)/template.c \
	$(srcdir)/traverse.c \
	$(srcdir)/version.c \
	$(srcdir)/view_file.c \
	$(srcdir)/view_info.c \
	$(srcdir)/viewer.c \
	$(builddir)/scale.c \
	$(builddir)/uscale.c \
	$(builddir)/dscale.c \
	$(builddir)/fscale.c \
	$(builddir)/slider.c \
	$(builddir)/uslider.c \
	$(builddir)/fslider.c

libcdk_a_CFLAGS = -I$(srcdir)/include -DHAVE_CONFIG_H -D_GNU_SOURCE


include/dscale.h: include/gen-scale.h
	./gen-scale.sh DSCALE DScale Double double include/gen-scale.h > include/dscale.h

include/fscale.h: include/gen-scale.h
	./gen-scale.sh FSCALE FScale Float float include/gen-scale.h > include/fscale.h

include/fslider.h: include/gen-slider.h
	./gen-scale.sh FSLIDER FSlider Float float include/gen-slider.h > include/fslider.h

include/scale.h: include/gen-scale.h
	./gen-scale.sh SCALE Scale Int int include/gen-scale.h > include/scale.h

include/slider.h: include/gen-slider.h
	./gen-scale.sh SLIDER Slider Int int include/gen-slider.h > include/slider.h

include/uscale.h: include/gen-scale.h
	./gen-scale.sh USCALE UScale Unsigned unsigned include/gen-scale.h > include/uscale.h

include/uslider.h: include/gen-slider.h
	./gen-scale.sh USLIDER USlider Unsigned unsigned include/gen-slider.h > include/uslider.h

$(builddir)/scale.c: $(srcdir)/gen-scale.c
	$(srcdir)/gen-scale.sh SCALE Scale Int int $(srcdir)/gen-scale.c > $(builddir)/scale.c

$(builddir)/uscale.c: $(srcdir)/gen-scale.c
	$(srcdir)/gen-scale.sh USCALE UScale Unsigned unsigned $(srcdir)/gen-scale.c >uscale.c

$(builddir)/dscale.c: $(srcdir)/gen-scale.c
	$(srcdir)/gen-scale.sh DSCALE DScale Double double $(srcdir)/gen-scale.c > $(builddir)/dscale.c

$(builddir)/fscale.c: $(srcdir)/gen-scale.c
	$(srcdir)/gen-scale.sh FSCALE FScale Float float $(srcdir)/gen-scale.c > $(builddir)/fscale.c

$(builddir)/slider.c: $(srcdir)/gen-slider.c
	$(srcdir)/gen-scale.sh SLIDER Slider Int int $(srcdir)/gen-slider.c > $(builddir)/slider.c

$(builddir)/uslider.c: $(srcdir)/gen-slider.c
	$(srcdir)/gen-scale.sh USLIDER USlider Unsigned unsigned $(srcdir)/gen-slider.c > $(builddir)/uslider.c

$(builddir)/fslider.c: gen-slider.c
	$(srcdir)/gen-scale.sh FSLIDER FSlider Float float $(srcdir)/gen-slider.c > $(builddir)/fslider.c


