
noinst_LIBRARIES = libjsonspirit.a

common_includes = \
	$(srcdir)/json_spirit_error_position.h \
	$(srcdir)/json_spirit.h \
	$(srcdir)/json_spirit_reader.h \
	$(srcdir)/json_spirit_reader_template.h \
	$(srcdir)/json_spirit_stream_reader.h \
	$(srcdir)/json_spirit_utils.h \
	$(srcdir)/json_spirit_value.h \
	$(srcdir)/json_spirit_writer.h \
	$(srcdir)/json_spirit_writer_template.h

common_sources = \
	$(srcdir)/json_spirit_reader.cpp \
	$(srcdir)/json_spirit_value.cpp \
	$(srcdir)/json_spirit_writer.cpp

libjsonspirit_a_SOURCES = \
	$(common_sources) \
	$(common_includes)

libdi3_a_CFLAGS = \
	-std=gnu11

