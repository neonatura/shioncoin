AM_CFLAGS = -DDATADIR=\"$(datadir)\"

htmldir = html 

dist_docdir = $(datadir)/@PACKAGE@

if HAVE_DOXYGEN
dist_doc_DATA = libshare_html.tar.gz

dist_man_MANS = \
	man/man3/libshare.3 \
	man/man3/libshare_mem.3 \
	man/man3/libshare_fs.3 \
	man/man3/libshare_net.3 \
	man/man3/shbuf_init.3 \
	man/man3/shbuf_catstr.3 \
	man/man3/shbuf_cat.3 \
	man/man3/shbuf_size.3 \
	man/man3/shbuf_clear.3 \
	man/man3/shbuf_trim.3 \
	man/man3/shbuf_free.3 \
	man/man3/shmeta_init.3 \
	man/man3/shmeta_free.3 \
	man/man3/shmeta_set.3 \
	man/man3/shmeta_set_str.3 \
	man/man3/shmeta_unset_str.3 \
	man/man3/shmeta_set_void.3 \
	man/man3/shmeta_unset_void.3 \
	man/man3/shmeta_get_str.3 \
	man/man3/shmeta_get_void.3 \
	man/man3/shmeta_get.3 \
	man/man3/shmeta_print.3 \
	man/man3/ashencode.3 \
	man/man3/shencode.3 \
	man/man3/shencode_str.3 \
	man/man3/ashdecode.3 \
	man/man3/shdecode.3 \
	man/man3/shdecode_str.3 \
	man/man3/shencrypt.3 \
	man/man3/shdecrypt.3 \
	man/man3/shdecrypt_verify.3 \
	man/man3/shdecrypt_derive.3 \
	man/man3/shdecrypt_derive_verify.3 \
	man/man3/shkey_bin.3 \
	man/man3/shkey_str.3 \
	man/man3/shkey_num.3 \
	man/man3/shkey_uniq.3 \
	man/man3/shkey_free.3 \
	man/man3/shkey_print.3 \
	man/man3/ashkey_str.3 \
	man/man3/ashkey_num.3 \
	man/man3/shlock_open.3 \
	man/man3/shlock_tryopen.3 \
	man/man3/shlock_close.3 \
	man/man3/shpool_init.3 \
	man/man3/shpool_size.3 \
	man/man3/shpool_grow.3 \
	man/man3/shpool_get.3 \
	man/man3/shpool_get_index.3 \
	man/man3/shpool_put.3 \
	man/man3/shpool_free.3 \
	man/man3/shconnect.3 \
	man/man3/shconnect_peer.3 \
	man/man3/shconnect_host.3 \
	man/man3/shclose.3 \
	man/man3/shnet_accept.3 \
	man/man3/shnet_bindsk.3 \
	man/man3/shnet_bind.3 \
	man/man3/shnet_fcntl.3 \
	man/man3/shnet_gethostbyname.3 \
	man/man3/shnet_peer.3 \
	man/man3/shnet_read.3 \
	man/man3/shnet_verify.3 \
	man/man3/shnet_select.3 \
	man/man3/shnet_sk.3 \
	man/man3/shnet_socket.3 \
	man/man3/shnet_write.3 \
	man/man3/shmsgget.3 \
	man/man3/shmsgsnd.3 \
	man/man3/shmsg_write.3 \
	man/man3/shmsgrcv.3 \
	man/man3/shmsg_read.3 \
	man/man3/shmsgctl.3 \
	man/man3/shfs_inode.3 \
	man/man3/shfs_inode_load.3 \
	man/man3/shfs_inode_tree.3 \
	man/man3/shfs_inode_peer.3 \
	man/man3/shfs_inode_parent.3 \
	man/man3/shfs_inode_write_entity.3 \
	man/man3/shfs_size.3 \
	man/man3/shfs_inode_write.3 \
	man/man3/shfs_inode_write_block.3 \
	man/man3/shfs_inode_read_block.3 \
	man/man3/shfs_inode_token_init.3 \
	man/man3/shfs_filename_set.3 \
	man/man3/shfs_filename.3 \
	man/man3/shfs_inode_path.3 \
	man/man3/shfs_inode_id.3 \
	man/man3/shfs_inode_print.3 \
	man/man3/shfs_inode_block_print.3 \
	man/man3/shfs_inode_size_str.3 \
	man/man3/shfs_crc_init.3 \
	man/man3/shfs_crc.3 \
	man/man3/shfs_block_type.3 \
	man/man3/shfs_type.3 \
	man/man3/shfs_block_format.3 \
	man/man3/shfs_format.3 \
	man/man3/shfs_format_set.3 \
	man/man3/shfs_type_str.3 \
	man/man3/shfs_type_char.3 \
	man/man3/shfs_format_str.3 \
	man/man3/shfs_block_stat.3 \
	man/man3/shfs_fstat.3 \
	man/man3/shfs_inode_remove.3 \
	man/man3/shfs_unlink.3 \
	man/man3/shgeo_set.3 \
	man/man3/shgeo_loc.3 \
	man/man3/shgeo_lifespan.3 \
	man/man3/shgeo_tag.3 \
	man/man3/shgeo_cmp.3 \
	man/man3/shgeo_radius.3 \
	man/man3/shgeo_dim.3 \
	man/man3/shgeo_local.3 \
	man/man3/shgeo_local_set.3 \
	man/man3/shgeodb_scan.3 \
	man/man3/shgeodb_place.3 \
	man/man3/shgeodb_host.3 \
	man/man3/shgeodb_loc.3 \
	man/man3/shgeodb_loc_set.3 \
	man/man3/shgeodb_rowid.3 \
	man/man3/shgeodb_name.3 \
	man/man3/shgeo_place_desc.3 \
	man/man3/shgeo_place_prec.3 \
	man/man3/shgeo_place_codes.3 \
	man/man3/shlog.3 \
	man/man3/sherr.3 \
	man/man3/shwarn.3 \
	man/man3/shinfo.3 \
	man/man3/shlog_path.3 \
	man/man3/shlog_path_set.3 \
	man/man3/shlog_level.3 \
	man/man3/shlog_level_set.3 \
	man/man3/shtimef.3 \
	man/man3/shtime.3 \
	man/man3/shtimeu.3 \
	man/man3/shtimems.3 \
	man/man3/shctime.3 \
	man/man3/shutimef.3 \
	man/man3/shstrtime.3 \
	man/man3/shtime_adj.3 \
	man/man3/shgettime.3 \
	man/man3/shtime_after.3 \
	man/man3/shtime_before.3 \
	man/man3/shmktime.3

man/man3/libshare.3: doxyfile.stamp
man/man3/libshare_mem.3: doxyfile.stamp
man/man3/libshare_fs.3: doxyfile.stamp
man/man3/libshare_net.3: doxyfile.stamp
man/man3/shbuf_init.3: doxyfile.stamp
man/man3/shbuf_catstr.3: doxyfile.stamp
man/man3/shbuf_cat.3: doxyfile.stamp
man/man3/shbuf_size.3: doxyfile.stamp
man/man3/shbuf_clear.3: doxyfile.stamp
man/man3/shbuf_trim.3: doxyfile.stamp
man/man3/shbuf_free.3: doxyfile.stamp
man/man3/shmeta_init.3: doxyfile.stamp
man/man3/shmeta_free.3: doxyfile.stamp
man/man3/shmeta_set.3: doxyfile.stamp
man/man3/shmeta_set_str.3: doxyfile.stamp
man/man3/shmeta_unset_str.3: doxyfile.stamp
man/man3/shmeta_set_void.3: doxyfile.stamp
man/man3/shmeta_unset_void.3: doxyfile.stamp
man/man3/shmeta_get_str.3: doxyfile.stamp
man/man3/shmeta_get_void.3: doxyfile.stamp
man/man3/shmeta_get.3: doxyfile.stamp
man/man3/shmeta_print.3: doxyfile.stamp
man/man3/ashencode.3: doxyfile.stamp
man/man3/shencode.3: doxyfile.stamp
man/man3/shencode_str.3: doxyfile.stamp
man/man3/ashdecode.3: doxyfile.stamp
man/man3/shdecode.3: doxyfile.stamp
man/man3/shdecode_str.3: doxyfile.stamp
man/man3/shencrypt.3: doxyfile.stamp
man/man3/shdecrypt.3: doxyfile.stamp
man/man3/shdecrypt_verify.3: doxyfile.stamp
man/man3/shdecrypt_derive.3: doxyfile.stamp
man/man3/shdecrypt_derive_verify.3: doxyfile.stamp
man/man3/shkey_bin.3: doxyfile.stamp
man/man3/shkey_str.3: doxyfile.stamp
man/man3/shkey_num.3: doxyfile.stamp
man/man3/shkey_uniq.3: doxyfile.stamp
man/man3/shkey_free.3: doxyfile.stamp
man/man3/shkey_print.3: doxyfile.stamp
man/man3/ashkey_str.3: doxyfile.stamp
man/man3/ashkey_num.3: doxyfile.stamp
man/man3/shlock_open.3: doxyfile.stamp
man/man3/shlock_tryopen.3: doxyfile.stamp
man/man3/shlock_close.3: doxyfile.stamp
man/man3/shpool_init.3: doxyfile.stamp
man/man3/shpool_size.3: doxyfile.stamp
man/man3/shpool_grow.3: doxyfile.stamp
man/man3/shpool_get.3: doxyfile.stamp
man/man3/shpool_get_index.3: doxyfile.stamp
man/man3/shpool_size.3: doxyfile.stamp
man/man3/shpool_grow.3: doxyfile.stamp
man/man3/shpool_put.3: doxyfile.stamp
man/man3/shpool_free.3: doxyfile.stamp
man/man3/shfs_sig_verify.3: doxyfile.stamp
man/man3/shmsgget.3: doxyfile.stamp
man/man3/shmsgsnd.3: doxyfile.stamp
man/man3/shmsg_write.3: doxyfile.stamp
man/man3/shmsgrcv.3: doxyfile.stamp
man/man3/shmsg_read.3: doxyfile.stamp
man/man3/shmsgctl.3: doxyfile.stamp
man/man3/shconnect.3: doxyfile.stamp
man/man3/shconnect_host.3: doxyfile.stamp
man/man3/shconnect_peer.3: doxyfile.stamp
man/man3/shclose.3: doxyfile.stamp
man/man3/shnet_accept.3: doxyfile.stamp
man/man3/shnet_bindsk.3: doxyfile.stamp
man/man3/shnet_bind.3: doxyfile.stamp
man/man3/shnet_fcntl.3: doxyfile.stamp
man/man3/shnet_gethostbyname.3: doxyfile.stamp
man/man3/shnet_peer.3: doxyfile.stamp
man/man3/shnet_read.3: doxyfile.stamp
man/man3/shnet_verify.3: doxyfile.stamp
man/man3/shnet_select.3: doxyfile.stamp
man/man3/shnet_sk.3: doxyfile.stamp
man/man3/shnet_socket.3: doxyfile.stamp
man/man3/shnet_write.3: doxyfile.stamp
man/man3/shmsgget.3: doxyfile.stamp
man/man3/shmsgsnd.3: doxyfile.stamp
man/man3/shmsg_write.3: doxyfile.stamp
man/man3/shmsgrcv.3: doxyfile.stamp
man/man3/shmsg_read.3: doxyfile.stamp
man/man3/shmsgctl.3: doxyfile.stamp
man/man3/shfs_inode.3: doxyfile.stamp
man/man3/shfs_inode_load.3: doxyfile.stamp
man/man3/shfs_inode_tree.3: doxyfile.stamp
man/man3/shfs_inode_peer.3: doxyfile.stamp
man/man3/shfs_inode_parent.3: doxyfile.stamp
man/man3/shfs_inode_write_entity.3: doxyfile.stamp
man/man3/shfs_size.3: doxyfile.stamp
man/man3/shfs_inode_write.3: doxyfile.stamp
man/man3/shfs_inode_write_block.3: doxyfile.stamp
man/man3/shfs_inode_read_block.3: doxyfile.stamp
man/man3/shfs_inode_token_init.3: doxyfile.stamp
man/man3/shfs_filename_set.3: doxyfile.stamp
man/man3/shfs_filename.3: doxyfile.stamp
man/man3/shfs_inode_path.3: doxyfile.stamp
man/man3/shfs_inode_id.3: doxyfile.stamp
man/man3/shfs_inode_print.3: doxyfile.stamp
man/man3/shfs_inode_block_print.3: doxyfile.stamp
man/man3/shfs_inode_size_str.3: doxyfile.stamp
man/man3/shfs_crc_init.3: doxyfile.stamp
man/man3/shfs_crc.3: doxyfile.stamp
man/man3/shfs_block_type.3: doxyfile.stamp
man/man3/shfs_type.3: doxyfile.stamp
man/man3/shfs_block_format.3: doxyfile.stamp
man/man3/shfs_format.3: doxyfile.stamp
man/man3/shfs_format_set.3: doxyfile.stamp
man/man3/shfs_type_str.3: doxyfile.stamp
man/man3/shfs_type_char.3: doxyfile.stamp
man/man3/shfs_format_str.3: doxyfile.stamp
man/man3/shfs_block_stat.3: doxyfile.stamp
man/man3/shfs_fstat.3: doxyfile.stamp
man/man3/shfs_inode_remove.3: doxyfile.stamp
man/man3/shfs_unlink.3: doxyfile.stamp
man/man3/shgeo_set.3: doxyfile.stamp
man/man3/shgeo_loc.3: doxyfile.stamp
man/man3/shgeo_lifespan.3: doxyfile.stamp
man/man3/shgeo_tag.3: doxyfile.stamp
man/man3/shgeo_cmp.3: doxyfile.stamp
man/man3/shgeo_radius.3: doxyfile.stamp
man/man3/shgeo_dim.3: doxyfile.stamp
man/man3/shgeo_local.3: doxyfile.stamp
man/man3/shgeo_local_set.3: doxyfile.stamp
man/man3/shgeodb_scan.3: doxyfile.stamp
man/man3/shgeodb_place.3: doxyfile.stamp
man/man3/shgeodb_host.3: doxyfile.stamp
man/man3/shgeodb_loc.3: doxyfile.stamp
man/man3/shgeodb_loc_set.3: doxyfile.stamp
man/man3/shgeodb_rowid.3: doxyfile.stamp
man/man3/shgeodb_name.3: doxyfile.stamp
man/man3/shgeo_place_desc.3: doxyfile.stamp
man/man3/shgeo_place_prec.3: doxyfile.stamp
man/man3/shgeo_place_codes.3: doxyfile.stamp
man/man3/shlog.3: doxyfile.stamp
man/man3/sherr.3: doxyfile.stamp
man/man3/shwarn.3: doxyfile.stamp
man/man3/shinfo.3: doxyfile.stamp
man/man3/shlog_path.3: doxyfile.stamp
man/man3/shlog_path_set.3: doxyfile.stamp
man/man3/shlog_level.3: doxyfile.stamp
man/man3/shlog_level_set.3: doxyfile.stamp
man/man3/shtimef.3: doxyfile.stamp
man/man3/shtime.3: doxyfile.stamp
man/man3/shtimeu.3: doxyfile.stamp
man/man3/shtimems.3: doxyfile.stamp
man/man3/shctime.3: doxyfile.stamp
man/man3/shutimef.3: doxyfile.stamp
man/man3/shstrtime.3: doxyfile.stamp
man/man3/shtime_adj.3: doxyfile.stamp
man/man3/shgettime.3: doxyfile.stamp
man/man3/shtime_after.3: doxyfile.stamp
man/man3/shtime_before.3: doxyfile.stamp
man/man3/shmktime.3: doxyfile.stamp

$(htmldir): doxyfile.stamp

#	mkdir -p $(top_srcdir)/build-aux/man
#	cp -fr man/* $(top_srcdir)/build-aux/man
doxyfile.stamp:
	mkdir -p html man
	$(DOXYGEN) doxygen.conf
	cp -f man/man3/libshare_membuf.3 man/man3/shbuf_init.3
	cp -f man/man3/libshare_membuf.3 man/man3/shbuf_catstr.3
	cp -f man/man3/libshare_membuf.3 man/man3/shbuf_cat.3
	cp -f man/man3/libshare_membuf.3 man/man3/shbuf_size.3
	cp -f man/man3/libshare_membuf.3 man/man3/shbuf_grow.3
	cp -f man/man3/libshare_membuf.3 man/man3/shbuf_clear.3
	cp -f man/man3/libshare_membuf.3 man/man3/shbuf_trim.3
	cp -f man/man3/libshare_membuf.3 man/man3/shbuf_free.3
	cp -f man/man3/libshare_memmeta.3 man/man3/shmeta_init.3
	cp -f man/man3/libshare_memmeta.3 man/man3/shmeta_free.3
	cp -f man/man3/libshare_memmeta.3 man/man3/shmeta_set.3
	cp -f man/man3/libshare_memmeta.3 man/man3/shmeta_set_str.3
	cp -f man/man3/libshare_memmeta.3 man/man3/shmeta_unset_str.3
	cp -f man/man3/libshare_memmeta.3 man/man3/shmeta_set_void.3
	cp -f man/man3/libshare_memmeta.3 man/man3/shmeta_unset_void.3
	cp -f man/man3/libshare_memmeta.3 man/man3/shmeta_get_str.3
	cp -f man/man3/libshare_memmeta.3 man/man3/shmeta_get_void.3
	cp -f man/man3/libshare_memmeta.3 man/man3/shmeta_get.3
	cp -f man/man3/libshare_memmeta.3 man/man3/shmeta_print.3
	cp -f man/man3/libshare_memcrypt.3 man/man3/ashencode.3
	cp -f man/man3/libshare_memcrypt.3 man/man3/shencode.3
	cp -f man/man3/libshare_memcrypt.3 man/man3/shencode_str.3
	cp -f man/man3/libshare_memcrypt.3 man/man3/ashdecode.3
	cp -f man/man3/libshare_memcrypt.3 man/man3/shdecode.3
	cp -f man/man3/libshare_memcrypt.3 man/man3/shdecode_str.3
	cp -f man/man3/libshare_memcrypt.3 man/man3/shencrypt.3
	cp -f man/man3/libshare_memcrypt.3 man/man3/shdecrypt.3
	cp -f man/man3/libshare_memcrypt.3 man/man3/shdecrypt_verify.3
	cp -f man/man3/libshare_memcrypt.3 man/man3/shdecrypt_derive.3
	cp -f man/man3/libshare_memcrypt.3 man/man3/shdecrypt_derive_verify.3
	cp -f man/man3/libshare_memkey.3 man/man3/shkey_bin.3
	cp -f man/man3/libshare_memkey.3 man/man3/shkey_str.3
	cp -f man/man3/libshare_memkey.3 man/man3/shkey_num.3
	cp -f man/man3/libshare_memkey.3 man/man3/shkey_uniq.3
	cp -f man/man3/libshare_memkey.3 man/man3/shkey_free.3
	cp -f man/man3/libshare_memkey.3 man/man3/shkey_print.3
	cp -f man/man3/libshare_memkey.3 man/man3/ashkey_str.3
	cp -f man/man3/libshare_memkey.3 man/man3/ashkey_num.3
	cp -f man/man3/libshare_memlock.3 man/man3/shlock_open.3
	cp -f man/man3/libshare_memlock.3 man/man3/shlock_tryopen.3
	cp -f man/man3/libshare_memlock.3 man/man3/shlock_close.3
	cp -f man/man3/libshare_mempool.3 man/man3/shpool_init.3
	cp -f man/man3/libshare_mempool.3 man/man3/shpool_size.3
	cp -f man/man3/libshare_mempool.3 man/man3/shpool_grow.3
	cp -f man/man3/libshare_mempool.3 man/man3/shpool_get.3
	cp -f man/man3/libshare_mempool.3 man/man3/shpool_get_index.3
	cp -f man/man3/libshare_mempool.3 man/man3/shpool_size.3
	cp -f man/man3/libshare_mempool.3 man/man3/shpool_grow.3
	cp -f man/man3/libshare_mempool.3 man/man3/shpool_put.3
	cp -f man/man3/libshare_mempool.3 man/man3/shpool_free.3
	cp -f man/man3/libshare_net.3 man/man3/shconnect.3
	cp -f man/man3/libshare_net.3 man/man3/shconnect_host.3
	cp -f man/man3/libshare_net.3 man/man3/shconnect_peer.3
	cp -f man/man3/libshare_net.3 man/man3/shclose.3
	cp -f man/man3/libshare_net.3 man/man3/shnet_accept.3
	cp -f man/man3/libshare_net.3 man/man3/shnet_bindsk.3
	cp -f man/man3/libshare_net.3 man/man3/shnet_bind.3
	cp -f man/man3/libshare_net.3 man/man3/shnet_fcntl.3
	cp -f man/man3/libshare_net.3 man/man3/shnet_gethostbyname.3
	cp -f man/man3/libshare_net.3 man/man3/shnet_peer.3
	cp -f man/man3/libshare_net.3 man/man3/shnet_read.3
	cp -f man/man3/libshare_net.3 man/man3/shnet_verify.3
	cp -f man/man3/libshare_net.3 man/man3/shnet_select.3
	cp -f man/man3/libshare_net.3 man/man3/shnet_sk.3
	cp -f man/man3/libshare_net.3 man/man3/shnet_socket.3
	cp -f man/man3/libshare_net.3 man/man3/shnet_write.3
	cp -f man/man3/libshare_fs.3 man/man3/shmsgget.3
	cp -f man/man3/libshare_fs.3 man/man3/shmsgsnd.3
	cp -f man/man3/libshare_fs.3 man/man3/shmsg_write.3
	cp -f man/man3/libshare_fs.3 man/man3/shmsgrcv.3
	cp -f man/man3/libshare_fs.3 man/man3/shmsg_read.3
	cp -f man/man3/libshare_fs.3 man/man3/shmsgctl.3
	cp -f man/man3/libshare_fsinode.3 man/man3/shfs_inode.3
	cp -f man/man3/libshare_fsinode.3 man/man3/shfs_inode_load.3
	cp -f man/man3/libshare_fsinode.3 man/man3/shfs_inode_tree.3
	cp -f man/man3/libshare_fsinode.3 man/man3/shfs_inode_peer.3
	cp -f man/man3/libshare_fsinode.3 man/man3/shfs_inode_parent.3
	cp -f man/man3/libshare_fsinode.3 man/man3/shfs_inode_write_entity.3
	cp -f man/man3/libshare_fsinode.3 man/man3/shfs_size.3
	cp -f man/man3/libshare_fsinode.3 man/man3/shfs_inode_write.3
	cp -f man/man3/libshare_fsinode.3 man/man3/shfs_inode_write_block.3
	cp -f man/man3/libshare_fsinode.3 man/man3/shfs_inode_read_block.3
	cp -f man/man3/libshare_fsinode.3 man/man3/shfs_inode_token_init.3
	cp -f man/man3/libshare_fsinode.3 man/man3/shfs_filename_set.3
	cp -f man/man3/libshare_fsinode.3 man/man3/shfs_filename.3
	cp -f man/man3/libshare_fsinode.3 man/man3/shfs_inode_path.3
	cp -f man/man3/libshare_fsinode.3 man/man3/shfs_inode_id.3
	cp -f man/man3/libshare_fsinode.3 man/man3/shfs_inode_print.3
	cp -f man/man3/libshare_fsinode.3 man/man3/shfs_inode_block_print.3
	cp -f man/man3/libshare_fsinode.3 man/man3/shfs_inode_size_str.3
	cp -f man/man3/libshare_fsinode.3 man/man3/shfs_crc_init.3
	cp -f man/man3/libshare_fsinode.3 man/man3/shfs_crc.3
	cp -f man/man3/libshare_fsinode.3 man/man3/shfs_block_type.3
	cp -f man/man3/libshare_fsinode.3 man/man3/shfs_type.3
	cp -f man/man3/libshare_fsinode.3 man/man3/shfs_block_format.3
	cp -f man/man3/libshare_fsinode.3 man/man3/shfs_format.3
	cp -f man/man3/libshare_fsinode.3 man/man3/shfs_format_set.3
	cp -f man/man3/libshare_fsinode.3 man/man3/shfs_type_str.3
	cp -f man/man3/libshare_fsinode.3 man/man3/shfs_type_char.3
	cp -f man/man3/libshare_fsinode.3 man/man3/shfs_format_str.3
	cp -f man/man3/libshare_fsinode.3 man/man3/shfs_block_stat.3
	cp -f man/man3/libshare_fsinode.3 man/man3/shfs_fstat.3
	cp -f man/man3/libshare_fsinode.3 man/man3/shfs_inode_remove.3
	cp -f man/man3/libshare_fsinode.3 man/man3/shfs_unlink.3
	cp -f man/man3/libshare_sysgeo.3 man/man3/shgeo_set.3
	cp -f man/man3/libshare_sysgeo.3 man/man3/shgeo_loc.3
	cp -f man/man3/libshare_sysgeo.3 man/man3/shgeo_lifespan.3
	cp -f man/man3/libshare_sysgeo.3 man/man3/shgeo_tag.3
	cp -f man/man3/libshare_sysgeo.3 man/man3/shgeo_cmp.3
	cp -f man/man3/libshare_sysgeo.3 man/man3/shgeo_radius.3
	cp -f man/man3/libshare_sysgeo.3 man/man3/shgeo_dim.3
	cp -f man/man3/libshare_sysgeo.3 man/man3/shgeo_local.3
	cp -f man/man3/libshare_sysgeo.3 man/man3/shgeo_local_set.3
	cp -f man/man3/libshare_sysgeo.3 man/man3/shgeodb_scan.3
	cp -f man/man3/libshare_sysgeo.3 man/man3/shgeodb_place.3
	cp -f man/man3/libshare_sysgeo.3 man/man3/shgeodb_host.3
	cp -f man/man3/libshare_sysgeo.3 man/man3/shgeodb_loc.3
	cp -f man/man3/libshare_sysgeo.3 man/man3/shgeodb_loc_set.3
	cp -f man/man3/libshare_sysgeo.3 man/man3/shgeodb_rowid.3
	cp -f man/man3/libshare_sysgeo.3 man/man3/shgeodb_name.3
	cp -f man/man3/libshare_sysgeo.3 man/man3/shgeo_place_desc.3
	cp -f man/man3/libshare_sysgeo.3 man/man3/shgeo_place_prec.3
	cp -f man/man3/libshare_sysgeo.3 man/man3/shgeo_place_codes.3
	cp -f man/man3/libshare_syslog.3 man/man3/shlog.3
	cp -f man/man3/libshare_syslog.3 man/man3/sherr.3
	cp -f man/man3/libshare_syslog.3 man/man3/shwarn.3
	cp -f man/man3/libshare_syslog.3 man/man3/shinfo.3
	cp -f man/man3/libshare_syslog.3 man/man3/shlog_path.3
	cp -f man/man3/libshare_syslog.3 man/man3/shlog_path_set.3
	cp -f man/man3/libshare_syslog.3 man/man3/shlog_level.3
	cp -f man/man3/libshare_syslog.3 man/man3/shlog_level_set.3
	cp -f man/man3/libshare_time.3 man/man3/shtimef.3
	cp -f man/man3/libshare_time.3 man/man3/shtime.3
	cp -f man/man3/libshare_time.3 man/man3/shtimeu.3
	cp -f man/man3/libshare_time.3 man/man3/shtimems.3
	cp -f man/man3/libshare_time.3 man/man3/shctime.3
	cp -f man/man3/libshare_time.3 man/man3/shutimef.3
	cp -f man/man3/libshare_time.3 man/man3/shstrtime.3
	cp -f man/man3/libshare_time.3 man/man3/shtime_adj.3
	cp -f man/man3/libshare_time.3 man/man3/shgettime.3
	cp -f man/man3/libshare_time.3 man/man3/shtime_after.3
	cp -f man/man3/libshare_time.3 man/man3/shtime_before.3
	cp -f man/man3/libshare_time.3 man/man3/shmktime.3
	echo Timestamp > doxyfile.stamp

libshare_html.tar.gz: doxyfile.stamp
	rm -f libshare_html.tar.gz
	tar -cpf libshare_html.tar $(htmldir)
	gzip libshare_html.tar
	rm -f libshare_html.tar

else

doxyfile.stamp:
	mkdir -p man
	cp -fdR $(top_srcdir)/build-aux/man/* ./man
	echo Timestamp > doxyfile.stamp

endif


EXTRA_DIST = $(htmldir)

all-local: doxyfile.stamp
clean-local:
	rm -f doxyfile.stamp
	rm -rf $(builddir)/man
	rm -rf $(builddir)/$(htmldir)


