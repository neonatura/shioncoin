AUTOMAKE_OPTIONS = foreign
JAVAC_OPT=-d $(top_builddir)/src/java-share-lib

AM_CPPFLAGS = -I$(top_srcdir)/src/share-lib \
	-I$(top_srcdir)/src/share-lib/fs \
	-I$(top_srcdir)/src/share-lib/net \
	-I$(top_srcdir)/src/share-lib/mem \
	-I$(top_srcdir)/src/share-lib/sys

if LIBSHARE_JAVA

BUILT_SOURCES = libshare.jar
TESTS = test_libshare_java.sh
libshare_java_DATA = libshare.jar 
libshare_javadir = $(libdir)

# not used
xz_sources = \
	$(srcdir)/org/tukaani/xz/LZMA2Decoder.java \
	$(srcdir)/org/tukaani/xz/ARMOptions.java \
	$(srcdir)/org/tukaani/xz/ARMThumbOptions.java \
	$(srcdir)/org/tukaani/xz/BCJCoder.java \
	$(srcdir)/org/tukaani/xz/BCJDecoder.java \
	$(srcdir)/org/tukaani/xz/BCJEncoder.java \
	$(srcdir)/org/tukaani/xz/BCJOptions.java \
	$(srcdir)/org/tukaani/xz/BlockInputStream.java \
	$(srcdir)/org/tukaani/xz/BlockOutputStream.java \
	$(srcdir)/org/tukaani/xz/check/Check.java \
	$(srcdir)/org/tukaani/xz/check/CRC32.java \
	$(srcdir)/org/tukaani/xz/check/CRC64.java \
	$(srcdir)/org/tukaani/xz/check/None.java \
	$(srcdir)/org/tukaani/xz/check/SHA256.java \
	$(srcdir)/org/tukaani/xz/common/DecoderUtil.java \
	$(srcdir)/org/tukaani/xz/common/EncoderUtil.java \
	$(srcdir)/org/tukaani/xz/common/StreamFlags.java \
	$(srcdir)/org/tukaani/xz/common/Util.java \
	$(srcdir)/org/tukaani/xz/CorruptedInputException.java \
	$(srcdir)/org/tukaani/xz/CountingInputStream.java \
	$(srcdir)/org/tukaani/xz/CountingOutputStream.java \
	$(srcdir)/org/tukaani/xz/delta/DeltaCoder.java \
	$(srcdir)/org/tukaani/xz/delta/DeltaDecoder.java \
	$(srcdir)/org/tukaani/xz/delta/DeltaEncoder.java \
	$(srcdir)/org/tukaani/xz/DeltaCoder.java \
	$(srcdir)/org/tukaani/xz/DeltaDecoder.java \
	$(srcdir)/org/tukaani/xz/DeltaEncoder.java \
	$(srcdir)/org/tukaani/xz/DeltaInputStream.java \
	$(srcdir)/org/tukaani/xz/DeltaOptions.java \
	$(srcdir)/org/tukaani/xz/DeltaOutputStream.java \
	$(srcdir)/org/tukaani/xz/FilterCoder.java \
	$(srcdir)/org/tukaani/xz/FilterDecoder.java \
	$(srcdir)/org/tukaani/xz/FilterEncoder.java \
	$(srcdir)/org/tukaani/xz/FilterOptions.java \
	$(srcdir)/org/tukaani/xz/FinishableOutputStream.java \
	$(srcdir)/org/tukaani/xz/FinishableWrapperOutputStream.java \
	$(srcdir)/org/tukaani/xz/IA64Options.java \
	$(srcdir)/org/tukaani/xz/index/BlockInfo.java \
	$(srcdir)/org/tukaani/xz/index/IndexBase.java \
	$(srcdir)/org/tukaani/xz/index/IndexDecoder.java \
	$(srcdir)/org/tukaani/xz/index/IndexEncoder.java \
	$(srcdir)/org/tukaani/xz/index/IndexHash.java \
	$(srcdir)/org/tukaani/xz/index/IndexRecord.java \
	$(srcdir)/org/tukaani/xz/IndexIndicatorException.java \
	$(srcdir)/org/tukaani/xz/lz/BT4.java \
	$(srcdir)/org/tukaani/xz/lz/CRC32Hash.java \
	$(srcdir)/org/tukaani/xz/lz/Hash234.java \
	$(srcdir)/org/tukaani/xz/lz/HC4.java \
	$(srcdir)/org/tukaani/xz/lz/LZDecoder.java \
	$(srcdir)/org/tukaani/xz/lz/LZEncoder.java \
	$(srcdir)/org/tukaani/xz/lz/Matches.java \
	$(srcdir)/org/tukaani/xz/lzma/LZMACoder.java \
	$(srcdir)/org/tukaani/xz/lzma/LZMADecoder.java \
	$(srcdir)/org/tukaani/xz/lzma/LZMAEncoder.java \
	$(srcdir)/org/tukaani/xz/lzma/LZMAEncoderFast.java \
	$(srcdir)/org/tukaani/xz/lzma/LZMAEncoderNormal.java \
	$(srcdir)/org/tukaani/xz/lzma/Optimum.java \
	$(srcdir)/org/tukaani/xz/lzma/State.java \
	$(srcdir)/org/tukaani/xz/LZMA2Coder.java \
	$(srcdir)/org/tukaani/xz/LZMA2Encoder.java \
	$(srcdir)/org/tukaani/xz/LZMA2InputStream.java \
	$(srcdir)/org/tukaani/xz/LZMA2Options.java \
	$(srcdir)/org/tukaani/xz/LZMA2OutputStream.java \
	$(srcdir)/org/tukaani/xz/LZMAInputStream.java \
	$(srcdir)/org/tukaani/xz/LZMAOutputStream.java \
	$(srcdir)/org/tukaani/xz/MemoryLimitException.java \
	$(srcdir)/org/tukaani/xz/PowerPCOptions.java \
	$(srcdir)/org/tukaani/xz/rangecoder/RangeCoder.java \
	$(srcdir)/org/tukaani/xz/rangecoder/RangeDecoder.java \
	$(srcdir)/org/tukaani/xz/rangecoder/RangeDecoderFromBuffer.java \
	$(srcdir)/org/tukaani/xz/rangecoder/RangeDecoderFromStream.java \
	$(srcdir)/org/tukaani/xz/rangecoder/RangeEncoder.java \
	$(srcdir)/org/tukaani/xz/rangecoder/RangeEncoderToBuffer.java \
	$(srcdir)/org/tukaani/xz/rangecoder/RangeEncoderToStream.java \
	$(srcdir)/org/tukaani/xz/RawCoder.java \
	$(srcdir)/org/tukaani/xz/SeekableFileInputStream.java \
	$(srcdir)/org/tukaani/xz/SeekableInputStream.java \
	$(srcdir)/org/tukaani/xz/SeekableXZInputStream.java \
	$(srcdir)/org/tukaani/xz/simple/ARM.java \
	$(srcdir)/org/tukaani/xz/simple/ARMThumb.java \
	$(srcdir)/org/tukaani/xz/simple/IA64.java \
	$(srcdir)/org/tukaani/xz/simple/PowerPC.java \
	$(srcdir)/org/tukaani/xz/simple/SimpleFilter.java \
	$(srcdir)/org/tukaani/xz/simple/SPARC.java \
	$(srcdir)/org/tukaani/xz/simple/X86.java \
	$(srcdir)/org/tukaani/xz/SimpleInputStream.java \
	$(srcdir)/org/tukaani/xz/SimpleOutputStream.java \
	$(srcdir)/org/tukaani/xz/SingleXZInputStream.java \
	$(srcdir)/org/tukaani/xz/SPARCOptions.java \
	$(srcdir)/org/tukaani/xz/UncompressedLZMA2OutputStream.java \
	$(srcdir)/org/tukaani/xz/UnsupportedOptionsException.java \
	$(srcdir)/org/tukaani/xz/X86Options.java \
	$(srcdir)/org/tukaani/xz/XZ.java \
	$(srcdir)/org/tukaani/xz/XZFormatException.java \
	$(srcdir)/org/tukaani/xz/XZInputStream.java \
	$(srcdir)/org/tukaani/xz/XZIOException.java \
	$(srcdir)/org/tukaani/xz/XZOutputStream.java

xz_classes = \
	org/tukaani/xz/LZMA2Decoder.class \
	org/tukaani/xz/ARMOptions.class \
	org/tukaani/xz/ARMThumbOptions.class \
	org/tukaani/xz/BCJCoder.class \
	org/tukaani/xz/BCJDecoder.class \
	org/tukaani/xz/BCJEncoder.class \
	org/tukaani/xz/BCJOptions.class \
	org/tukaani/xz/BlockInputStream.class \
	org/tukaani/xz/BlockOutputStream.class \
	org/tukaani/xz/check/Check.class \
	org/tukaani/xz/check/CRC32.class \
	org/tukaani/xz/check/CRC64.class \
	org/tukaani/xz/check/None.class \
	org/tukaani/xz/check/SHA256.class \
	org/tukaani/xz/common/DecoderUtil.class \
	org/tukaani/xz/common/EncoderUtil.class \
	org/tukaani/xz/common/StreamFlags.class \
	org/tukaani/xz/common/Util.class \
	org/tukaani/xz/CorruptedInputException.class \
	org/tukaani/xz/CountingInputStream.class \
	org/tukaani/xz/CountingOutputStream.class \
	org/tukaani/xz/delta/DeltaCoder.class \
	org/tukaani/xz/delta/DeltaDecoder.class \
	org/tukaani/xz/delta/DeltaEncoder.class \
	org/tukaani/xz/DeltaCoder.class \
	org/tukaani/xz/DeltaDecoder.class \
	org/tukaani/xz/DeltaEncoder.class \
	org/tukaani/xz/DeltaInputStream.class \
	org/tukaani/xz/DeltaOptions.class \
	org/tukaani/xz/DeltaOutputStream.class \
	org/tukaani/xz/FilterCoder.class \
	org/tukaani/xz/FilterDecoder.class \
	org/tukaani/xz/FilterEncoder.class \
	org/tukaani/xz/FilterOptions.class \
	org/tukaani/xz/FinishableOutputStream.class \
	org/tukaani/xz/FinishableWrapperOutputStream.class \
	org/tukaani/xz/IA64Options.class \
	org/tukaani/xz/index/BlockInfo.class \
	org/tukaani/xz/index/IndexBase.class \
	org/tukaani/xz/index/IndexDecoder.class \
	org/tukaani/xz/index/IndexEncoder.class \
	org/tukaani/xz/index/IndexHash.class \
	org/tukaani/xz/index/IndexRecord.class \
	org/tukaani/xz/IndexIndicatorException.class \
	org/tukaani/xz/lz/BT4.class \
	org/tukaani/xz/lz/CRC32Hash.class \
	org/tukaani/xz/lz/Hash234.class \
	org/tukaani/xz/lz/HC4.class \
	org/tukaani/xz/lz/LZDecoder.class \
	org/tukaani/xz/lz/LZEncoder.class \
	org/tukaani/xz/lz/Matches.class \
	org/tukaani/xz/lzma/LZMACoder.class \
	org/tukaani/xz/lzma/LZMADecoder.class \
	org/tukaani/xz/lzma/LZMAEncoder.class \
	org/tukaani/xz/lzma/LZMAEncoderFast.class \
	org/tukaani/xz/lzma/LZMAEncoderNormal.class \
	org/tukaani/xz/lzma/Optimum.class \
	org/tukaani/xz/lzma/State.class \
	org/tukaani/xz/LZMA2Coder.class \
	org/tukaani/xz/LZMA2Encoder.class \
	org/tukaani/xz/LZMA2InputStream.class \
	org/tukaani/xz/LZMA2Options.class \
	org/tukaani/xz/LZMA2OutputStream.class \
	org/tukaani/xz/LZMAInputStream.class \
	org/tukaani/xz/LZMAOutputStream.class \
	org/tukaani/xz/MemoryLimitException.class \
	org/tukaani/xz/PowerPCOptions.class \
	org/tukaani/xz/rangecoder/RangeCoder.class \
	org/tukaani/xz/rangecoder/RangeDecoder.class \
	org/tukaani/xz/rangecoder/RangeDecoderFromBuffer.class \
	org/tukaani/xz/rangecoder/RangeDecoderFromStream.class \
	org/tukaani/xz/rangecoder/RangeEncoder.class \
	org/tukaani/xz/rangecoder/RangeEncoderToBuffer.class \
	org/tukaani/xz/rangecoder/RangeEncoderToStream.class \
	org/tukaani/xz/RawCoder.class \
	org/tukaani/xz/SeekableFileInputStream.class \
	org/tukaani/xz/SeekableInputStream.class \
	org/tukaani/xz/SeekableXZInputStream.class \
	org/tukaani/xz/simple/ARM.class \
	org/tukaani/xz/simple/ARMThumb.class \
	org/tukaani/xz/simple/IA64.class \
	org/tukaani/xz/simple/PowerPC.class \
	org/tukaani/xz/simple/SimpleFilter.class \
	org/tukaani/xz/simple/SPARC.class \
	org/tukaani/xz/simple/X86.class \
	org/tukaani/xz/SimpleInputStream.class \
	org/tukaani/xz/SimpleOutputStream.class \
	org/tukaani/xz/SingleXZInputStream.class \
	org/tukaani/xz/SPARCOptions.class \
	org/tukaani/xz/UncompressedLZMA2OutputStream.class \
	org/tukaani/xz/UnsupportedOptionsException.class \
	org/tukaani/xz/X86Options.class \
	org/tukaani/xz/XZ.class \
	org/tukaani/xz/XZFormatException.class \
	org/tukaani/xz/XZInputStream.class \
	org/tukaani/xz/XZIOException.class \
	org/tukaani/xz/XZOutputStream.class


javasources = \
	$(top_srcdir)/src/share-lib/java/share_java.java \
	$(top_srcdir)/src/share-lib/java/share_javaJNI.java \
	$(top_srcdir)/src/share-lib/java/SWIGTYPE_p_fd_set.java \
	$(top_srcdir)/src/share-lib/java/SWIGTYPE_p_hostent.java \
	$(top_srcdir)/src/share-lib/java/SWIGTYPE_p_long.java \
	$(top_srcdir)/src/share-lib/java/SWIGTYPE_p_p_char.java \
	$(top_srcdir)/src/share-lib/java/SWIGTYPE_p_p_shfs_t.java \
	$(top_srcdir)/src/share-lib/java/SWIGTYPE_p_p_shjson_t.java \
	$(top_srcdir)/src/share-lib/java/SWIGTYPE_p_p_shkey_t.java \
	$(top_srcdir)/src/share-lib/java/SWIGTYPE_p_p_shlock_t.java \
	$(top_srcdir)/src/share-lib/java/SWIGTYPE_p_p_shmeta_t.java \
	$(top_srcdir)/src/share-lib/java/SWIGTYPE_p_p_shpeer_t.java \
	$(top_srcdir)/src/share-lib/java/SWIGTYPE_p_p_shpool_t.java \
	$(top_srcdir)/src/share-lib/java/SWIGTYPE_p_p_unsigned_char.java \
	$(top_srcdir)/src/share-lib/java/SWIGTYPE_p_shbuf_t.java \
	$(top_srcdir)/src/share-lib/java/SWIGTYPE_p_shfs_ino_t.java \
	$(top_srcdir)/src/share-lib/java/SWIGTYPE_p_shfs_t.java \
	$(top_srcdir)/src/share-lib/java/SWIGTYPE_p_shjson_t.java \
	$(top_srcdir)/src/share-lib/java/SWIGTYPE_p_shkey_t.java \
	$(top_srcdir)/src/share-lib/java/SWIGTYPE_p_shlock_t.java \
	$(top_srcdir)/src/share-lib/java/SWIGTYPE_p_shmeta_t.java \
	$(top_srcdir)/src/share-lib/java/SWIGTYPE_p_shpeer_t.java \
	$(top_srcdir)/src/share-lib/java/SWIGTYPE_p_shpool_t.java \
	$(top_srcdir)/src/share-lib/java/SWIGTYPE_p_shsig_t.java \
	$(top_srcdir)/src/share-lib/java/SWIGTYPE_p_shsize_t.java \
	$(top_srcdir)/src/share-lib/java/SWIGTYPE_p_size_t.java \
	$(top_srcdir)/src/share-lib/java/SWIGTYPE_p_sockaddr.java \
	$(top_srcdir)/src/share-lib/java/SWIGTYPE_p_socklen_t.java \
	$(top_srcdir)/src/share-lib/java/SWIGTYPE_p_ssize_t.java \
	$(top_srcdir)/src/share-lib/java/SWIGTYPE_p_timeval.java \
	$(top_srcdir)/src/share-lib/java/SWIGTYPE_p_unsigned_char.java \
	$(top_srcdir)/src/share-lib/java/SWIGTYPE_p_unsigned_int.java \
	$(top_srcdir)/src/share-lib/java/SWIGTYPE_p_void.java

javaclasses = \
	net/sharelib/share_java.class \
	net/sharelib/share_javaJNI.class \
	net/sharelib/SWIGTYPE_p_fd_set.class \
	net/sharelib/SWIGTYPE_p_hostent.class \
	net/sharelib/SWIGTYPE_p_long.class \
	net/sharelib/SWIGTYPE_p_p_char.class \
	net/sharelib/SWIGTYPE_p_p_shfs_t.class \
	net/sharelib/SWIGTYPE_p_p_shjson_t.class \
	net/sharelib/SWIGTYPE_p_p_shkey_t.class \
	net/sharelib/SWIGTYPE_p_p_shlock_t.class \
	net/sharelib/SWIGTYPE_p_p_shmeta_t.class \
	net/sharelib/SWIGTYPE_p_p_shpeer_t.class \
	net/sharelib/SWIGTYPE_p_p_shpool_t.class \
	net/sharelib/SWIGTYPE_p_p_unsigned_char.class \
	net/sharelib/SWIGTYPE_p_shbuf_t.class \
	net/sharelib/SWIGTYPE_p_shfs_ino_t.class \
	net/sharelib/SWIGTYPE_p_shfs_t.class \
	net/sharelib/SWIGTYPE_p_shjson_t.class \
	net/sharelib/SWIGTYPE_p_shkey_t.class \
	net/sharelib/SWIGTYPE_p_shlock_t.class \
	net/sharelib/SWIGTYPE_p_shmeta_t.class \
	net/sharelib/SWIGTYPE_p_shpeer_t.class \
	net/sharelib/SWIGTYPE_p_shpool_t.class \
	net/sharelib/SWIGTYPE_p_shsig_t.class \
	net/sharelib/SWIGTYPE_p_shsize_t.class \
	net/sharelib/SWIGTYPE_p_size_t.class \
	net/sharelib/SWIGTYPE_p_sockaddr.class \
	net/sharelib/SWIGTYPE_p_socklen_t.class \
	net/sharelib/SWIGTYPE_p_ssize_t.class \
	net/sharelib/SWIGTYPE_p_timeval.class \
	net/sharelib/SWIGTYPE_p_unsigned_char.class \
	net/sharelib/SWIGTYPE_p_unsigned_int.class \
	net/sharelib/SWIGTYPE_p_void.class

common_includes = \
  $(top_srcdir)/src/share-lib/share.h \
  $(top_srcdir)/src/share-lib/sherr.h \
  $(top_srcdir)/src/share-lib/share_base.h \
  $(top_srcdir)/src/share-lib/shpeer.h \
  $(top_srcdir)/src/share-lib/shtime.h \
  $(top_srcdir)/src/share-lib/shcrc.h \
  $(top_srcdir)/src/share-lib/mem/shmem.h \
  $(top_srcdir)/src/share-lib/fs/shfs.h \
  $(top_srcdir)/src/share-lib/shpref.h \
  $(top_srcdir)/src/share-lib/net/shnet.h

api_sources = \
	$(srcdir)/net/sharelib/Share.java \
	$(srcdir)/net/sharelib/SHTime.java \
	$(srcdir)/net/sharelib/SHCRC64.java \
	$(srcdir)/net/sharelib/mem/SHKey.java \
	$(srcdir)/net/sharelib/mem/SHBuffer.java \
	$(srcdir)/net/sharelib/mem/SHBufferInputStream.java \
	$(srcdir)/net/sharelib/mem/SHBufferOutputStream.java \
	$(srcdir)/net/sharelib/fs/SHInode.java

api_classes = \
	net/sharelib/Share.class \
	net/sharelib/SHTime.class \
	net/sharelib/SHCRC64.class \
	net/sharelib/mem/SHKey.class \
	net/sharelib/mem/SHBuffer.class \
	net/sharelib/mem/SHBufferInputStream.class \
	net/sharelib/mem/SHBufferOutputStream.class \
	net/sharelib/fs/SHInode.class

libshare.so:
	$(LN_S) -f $(top_builddir)/src/share-lib/.libs/libshare.so

libshare.jar: libshare.so
	$(JAVAC) $(JAVAC_OPT) $(javasources) $(api_sources) test_libshare_java.java
	$(JAR) cf libshare.jar $(javaclasses) $(api_classes)

endif

clean-local:
	rm -f net/sharelib/*.class net/sharelib/*/*.class libshare.jar libshare_java.so *.class .stamp $(xz_classes)
