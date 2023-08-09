Name:           libshare
Version:        6.5
Release:        1%{?dist}
Summary:        The share library suite.

Group:          System Environment/Libraries
License:        GPLv3+
URL:            http://www.sharelib.net/
Source0:        ftp://ftp.sharelib.net/release/libshare/libshare-6.5.tar.gz

#BuildRequires:  gcc-java, java-1.8.0-openjdk-devel, swig, help2man, doxygen
#Requires:       java-1.8.0-openjdk

%description


%package        devel
Summary:        Development files for %{name}
Group:          Development/Libraries
Requires:       %{name} = %{version}-%{release}

%description    devel
The %{name}-devel package contains libraries and header files for
developing applications that use %{name}.


%prep
%setup -q


%build
%configure
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
find $RPM_BUILD_ROOT -name '*.la' -exec rm -f {} ';'


%check
make check


%clean
rm -rf $RPM_BUILD_ROOT


%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig


%files
%defattr(-,root,root,-)
%doc
%{_libdir}/*.so.*
%{_bindir}/readsexe
%{_bindir}/shattr
%{_bindir}/shcat
%{_bindir}/shcp
%{_bindir}/shdelta
%{_bindir}/shdiff
%{_bindir}/shinfo
%{_bindir}/shln
%{_bindir}/shls
%{_bindir}/shpasswd
%{_bindir}/shpatch
%{_bindir}/shpref
%{_bindir}/shrev
%{_bindir}/shrm
%{_bindir}/shstat
%{_bindir}/sx
%{_bindir}/sxc
%{_bindir}/sxsh
%{_bindir}/static_sx
%{_bindir}/static_sxc
%{_bindir}/shcert
%{_bindir}/shdb
%{_bindir}/shfsck
%{_bindir}/shpkg
%{_bindir}/shalg
%{_bindir}/shgeo
%{_bindir}/shz
%{_bindir}/shapp
%{_docdir}/libshare/libshare_html.tar.gz
%{_mandir}/man1/readsexe.1.gz
%{_mandir}/man1/shattr.1.gz
%{_mandir}/man1/shcat.1.gz
%{_mandir}/man1/shcp.1.gz
%{_mandir}/man1/shdelta.1.gz
%{_mandir}/man1/shdiff.1.gz
%{_mandir}/man1/shinfo.1.gz
%{_mandir}/man1/shalg.1.gz
%{_mandir}/man1/shgeo.1.gz
%{_mandir}/man1/shz.1.gz
%{_mandir}/man1/shln.1.gz
%{_mandir}/man1/shls.1.gz
%{_mandir}/man1/shpasswd.1.gz
%{_mandir}/man1/shpatch.1.gz
%{_mandir}/man1/shpref.1.gz
%{_mandir}/man1/shrev.1.gz
%{_mandir}/man1/shrm.1.gz
%{_mandir}/man1/shstat.1.gz
%{_mandir}/man1/sx.1.gz
%{_mandir}/man1/sxc.1.gz
%{_mandir}/man1/sxsh.1.gz
%{_mandir}/man1/shcert.1.gz
%{_mandir}/man1/shdb.1.gz
%{_mandir}/man1/shfsck.1.gz
%{_mandir}/man1/shpkg.1.gz
%{_mandir}/man3/ashkey_num.3.gz
%{_mandir}/man3/ashkey_str.3.gz
%{_mandir}/man3/libshare.3.gz
%{_mandir}/man3/libshare_fs.3.gz
%{_mandir}/man3/libshare_mem.3.gz
%{_mandir}/man3/libshare_net.3.gz
%{_mandir}/man3/shbuf_cat.3.gz
%{_mandir}/man3/shbuf_catstr.3.gz
%{_mandir}/man3/shbuf_clear.3.gz
%{_mandir}/man3/shbuf_free.3.gz
%{_mandir}/man3/shbuf_init.3.gz
%{_mandir}/man3/shbuf_size.3.gz
%{_mandir}/man3/shbuf_trim.3.gz
%{_mandir}/man3/shfs_unlink.3.gz
%{_mandir}/man3/shkey_bin.3.gz
%{_mandir}/man3/shkey_free.3.gz
%{_mandir}/man3/shkey_num.3.gz
%{_mandir}/man3/shkey_print.3.gz
%{_mandir}/man3/shkey_str.3.gz
%{_mandir}/man3/shkey_uniq.3.gz
%{_mandir}/man3/shlock_close.3.gz
%{_mandir}/man3/shlock_open.3.gz
%{_mandir}/man3/shlock_tryopen.3.gz
%{_mandir}/man3/shmeta_free.3.gz
%{_mandir}/man3/shmeta_get.3.gz
%{_mandir}/man3/shmeta_get_str.3.gz
%{_mandir}/man3/shmeta_get_void.3.gz
%{_mandir}/man3/shmeta_init.3.gz
%{_mandir}/man3/shmeta_print.3.gz
%{_mandir}/man3/shmeta_set.3.gz
%{_mandir}/man3/shmeta_set_str.3.gz
%{_mandir}/man3/shmeta_set_void.3.gz
%{_mandir}/man3/shmeta_unset_str.3.gz
%{_mandir}/man3/shmeta_unset_void.3.gz
%{_mandir}/man3/shmsg_read.3.gz
%{_mandir}/man3/shmsg_write.3.gz
%{_mandir}/man3/shmsgctl.3.gz
%{_mandir}/man3/shmsgget.3.gz
%{_mandir}/man3/shmsgrcv.3.gz
%{_mandir}/man3/shmsgsnd.3.gz
%{_mandir}/man3/shconnect.3.gz
%{_mandir}/man3/shconnect_host.3.gz
%{_mandir}/man3/shconnect_peer.3.gz
%{_mandir}/man3/shclose.3.gz
%{_mandir}/man3/shnet_accept.3.gz
%{_mandir}/man3/shnet_bind.3.gz
%{_mandir}/man3/shnet_bindsk.3.gz
%{_mandir}/man3/shnet_fcntl.3.gz
%{_mandir}/man3/shnet_gethostbyname.3.gz
%{_mandir}/man3/shnet_peer.3.gz
%{_mandir}/man3/shnet_read.3.gz
%{_mandir}/man3/shnet_select.3.gz
%{_mandir}/man3/shnet_sk.3.gz
%{_mandir}/man3/shnet_socket.3.gz
%{_mandir}/man3/shnet_verify.3.gz
%{_mandir}/man3/shnet_write.3.gz
%{_mandir}/man3/shpool_free.3.gz
%{_mandir}/man3/shpool_get.3.gz
%{_mandir}/man3/shpool_get_index.3.gz
%{_mandir}/man3/shpool_grow.3.gz
%{_mandir}/man3/shpool_init.3.gz
%{_mandir}/man3/shpool_put.3.gz
%{_mandir}/man3/shpool_size.3.gz
%{_mandir}/man3/shfs_block_format.3.gz
%{_mandir}/man3/shfs_block_stat.3.gz
%{_mandir}/man3/shfs_block_type.3.gz
%{_mandir}/man3/shfs_crc.3.gz
%{_mandir}/man3/shfs_crc_init.3.gz
%{_mandir}/man3/shfs_filename.3.gz
%{_mandir}/man3/shfs_filename_set.3.gz
%{_mandir}/man3/shfs_format.3.gz
%{_mandir}/man3/shfs_format_set.3.gz
%{_mandir}/man3/shfs_format_str.3.gz
%{_mandir}/man3/shfs_fstat.3.gz
%{_mandir}/man3/shfs_inode.3.gz
%{_mandir}/man3/shfs_inode_block_print.3.gz
%{_mandir}/man3/shfs_inode_id.3.gz
%{_mandir}/man3/shfs_inode_load.3.gz
%{_mandir}/man3/shfs_inode_parent.3.gz
%{_mandir}/man3/shfs_inode_path.3.gz
%{_mandir}/man3/shfs_inode_peer.3.gz
%{_mandir}/man3/shfs_inode_print.3.gz
%{_mandir}/man3/shfs_inode_read_block.3.gz
%{_mandir}/man3/shfs_inode_remove.3.gz
%{_mandir}/man3/shfs_inode_size_str.3.gz
%{_mandir}/man3/shfs_inode_token_init.3.gz
%{_mandir}/man3/shfs_inode_tree.3.gz
%{_mandir}/man3/shfs_inode_write.3.gz
%{_mandir}/man3/shfs_inode_write_block.3.gz
%{_mandir}/man3/shfs_inode_write_entity.3.gz
%{_mandir}/man3/shfs_size.3.gz
%{_mandir}/man3/shfs_type.3.gz
%{_mandir}/man3/shfs_type_char.3.gz
%{_mandir}/man3/shfs_type_str.3.gz
%{_mandir}/man3/shgeo_set.3.gz
%{_mandir}/man3/shgeo_loc.3.gz
%{_mandir}/man3/shgeo_lifespan.3.gz
%{_mandir}/man3/shgeo_tag.3.gz
%{_mandir}/man3/shgeo_cmp.3.gz
%{_mandir}/man3/shgeo_radius.3.gz
%{_mandir}/man3/shgeo_dim.3.gz
%{_mandir}/man3/shgeo_local.3.gz
%{_mandir}/man3/shgeo_local_set.3.gz
%{_mandir}/man3/shgeodb_scan.3.gz
%{_mandir}/man3/shgeodb_place.3.gz
%{_mandir}/man3/shgeodb_host.3.gz
%{_mandir}/man3/shgeodb_loc.3.gz
%{_mandir}/man3/shgeodb_loc_set.3.gz
%{_mandir}/man3/shgeodb_rowid.3.gz
%{_mandir}/man3/shgeodb_name.3.gz
%{_mandir}/man3/shgeo_place_desc.3.gz
%{_mandir}/man3/shgeo_place_prec.3.gz
%{_mandir}/man3/shgeo_place_codes.3.gz
%{_mandir}/man3/ashdecode.3.gz
%{_mandir}/man3/ashencode.3.gz
%{_mandir}/man3/shctime.3.gz
%{_mandir}/man3/shdecode.3.gz
%{_mandir}/man3/shdecode_str.3.gz
%{_mandir}/man3/shdecrypt.3.gz
%{_mandir}/man3/shdecrypt_derive.3.gz
%{_mandir}/man3/shdecrypt_derive_verify.3.gz
%{_mandir}/man3/shdecrypt_verify.3.gz
%{_mandir}/man3/shencode.3.gz
%{_mandir}/man3/shencode_str.3.gz
%{_mandir}/man3/shencrypt.3.gz
%{_mandir}/man3/sherr.3.gz
%{_mandir}/man3/shgettime.3.gz
%{_mandir}/man3/shinfo.3.gz
%{_mandir}/man3/shlog.3.gz
%{_mandir}/man3/shlog_level.3.gz
%{_mandir}/man3/shlog_level_set.3.gz
%{_mandir}/man3/shlog_path.3.gz
%{_mandir}/man3/shlog_path_set.3.gz
%{_mandir}/man3/shmktime.3.gz
%{_mandir}/man3/shstrtime.3.gz
%{_mandir}/man3/shtime.3.gz
%{_mandir}/man3/shtime_adj.3.gz
%{_mandir}/man3/shtime_after.3.gz
%{_mandir}/man3/shtime_before.3.gz
%{_mandir}/man3/shtimef.3.gz
%{_mandir}/man3/shtimems.3.gz
%{_mandir}/man3/shtimeu.3.gz
%{_mandir}/man3/shutimef.3.gz
%{_mandir}/man3/shwarn.3.gz



%files devel
%defattr(-,root,root,-)
%doc
%{_includedir}/*
%{_libdir}/*.so
%{_libdir}/*.a


%changelog
*  Fri Aug 04 2023 Neo Natura <support@neo-natura.com> - 6.5
- The RPM release of the libshare software suite.
