

noinst_LIBRARIES = libcrypto.a

OPENSSL_DIR=openssl-1.0.1g
SSL_DIR = $(srcdir)/$(OPENSSL_DIR)

bn_sources = \
	$(SSL_DIR)/crypto/bn/bn_add.c \
	$(SSL_DIR)/crypto/bn/bn_asm.c \
	$(SSL_DIR)/crypto/bn/bn_blind.c \
	$(SSL_DIR)/crypto/bn/bn_const.c \
	$(SSL_DIR)/crypto/bn/bn_ctx.c \
	$(SSL_DIR)/crypto/bn/bn_depr.c \
	$(SSL_DIR)/crypto/bn/bn_div.c \
	$(SSL_DIR)/crypto/bn/bn_err.c \
	$(SSL_DIR)/crypto/bn/bn_exp2.c \
	$(SSL_DIR)/crypto/bn/bn_exp.c \
	$(SSL_DIR)/crypto/bn/bn_gcd.c \
	$(SSL_DIR)/crypto/bn/bn_gf2m.c \
	$(SSL_DIR)/crypto/bn/bn_kron.c \
	$(SSL_DIR)/crypto/bn/bn_lcl.h \
	$(SSL_DIR)/crypto/bn/bn_lib.c \
	$(SSL_DIR)/crypto/bn/bn_mod.c \
	$(SSL_DIR)/crypto/bn/bn_mont.c \
	$(SSL_DIR)/crypto/bn/bn_mpi.c \
	$(SSL_DIR)/crypto/bn/bn_mul.c \
	$(SSL_DIR)/crypto/bn/bn_nist.c \
	$(SSL_DIR)/crypto/bn/bn_prime.c \
	$(SSL_DIR)/crypto/bn/bn_prime.h \
	$(SSL_DIR)/crypto/bn/bn_print.c \
	$(SSL_DIR)/crypto/bn/bn_rand.c \
	$(SSL_DIR)/crypto/bn/bn_recp.c \
	$(SSL_DIR)/crypto/bn/bn_shift.c \
	$(SSL_DIR)/crypto/bn/bn_sqr.c \
	$(SSL_DIR)/crypto/bn/bn_sqrt.c \
	$(SSL_DIR)/crypto/bn/bn_word.c

bio_sources = \
	$(SSL_DIR)/crypto/bio/b_dump.c \
	$(SSL_DIR)/crypto/bio/bf_buff.c \
	$(SSL_DIR)/crypto/bio/bf_nbio.c \
	$(SSL_DIR)/crypto/bio/bf_null.c \
	$(SSL_DIR)/crypto/bio/bio_cb.c \
	$(SSL_DIR)/crypto/bio/bio_err.c \
	$(SSL_DIR)/crypto/bio/bio_lib.c \
	$(SSL_DIR)/crypto/bio/b_print.c \
	$(SSL_DIR)/crypto/bio/b_sock.c \
	$(SSL_DIR)/crypto/bio/bss_acpt.c \
	$(SSL_DIR)/crypto/bio/bss_bio.c \
	$(SSL_DIR)/crypto/bio/bss_conn.c \
	$(SSL_DIR)/crypto/bio/bss_dgram.c \
	$(SSL_DIR)/crypto/bio/bss_fd.c \
	$(SSL_DIR)/crypto/bio/bss_file.c \
	$(SSL_DIR)/crypto/bio/bss_log.c \
	$(SSL_DIR)/crypto/bio/bss_mem.c \
	$(SSL_DIR)/crypto/bio/bss_null.c \
	$(SSL_DIR)/crypto/bio/bss_sock.c

buffer_sources = \
	$(SSL_DIR)/crypto/buffer/buffer.c \
	$(SSL_DIR)/crypto/buffer/buf_str.c \
	$(SSL_DIR)/crypto/buffer/buf_err.c

sha_sources = \
	$(SSL_DIR)/crypto/sha/sha_dgst.c $(SSL_DIR)/crypto/sha/sha1dgst.c \
	$(SSL_DIR)/crypto/sha/sha_one.c $(SSL_DIR)/crypto/sha/sha1_one.c $(SSL_DIR)/crypto/sha/sha256.c $(SSL_DIR)/crypto/sha/sha512.c 

aes_sources = \
	$(SSL_DIR)/crypto/aes/aes_cfb.c \
	$(SSL_DIR)/crypto/aes/aes_ctr.c \
	$(SSL_DIR)/crypto/aes/aes_ecb.c \
	$(SSL_DIR)/crypto/aes/aes_ige.c \
	$(SSL_DIR)/crypto/aes/aes_misc.c \
	$(SSL_DIR)/crypto/aes/aes_ofb.c \
	$(SSL_DIR)/crypto/aes/aes_wrap.c


ec_sources = \
	$(SSL_DIR)/crypto/ec/ec_lib.c \
	$(SSL_DIR)/crypto/ec/ec_err.c \
	$(SSL_DIR)/crypto/ec/ec_asn1.c \
	$(SSL_DIR)/crypto/ec/ec_key.c \
	$(SSL_DIR)/crypto/ec/ec_ameth.c \
	$(SSL_DIR)/crypto/ec/ec_pmeth.c \
	$(SSL_DIR)/crypto/ec/ec_curve.c \
	$(SSL_DIR)/crypto/ec/ec_mult.c \
	$(SSL_DIR)/crypto/ec/ec_cvt.c \
	$(SSL_DIR)/crypto/ec/ec_print.c \
	$(SSL_DIR)/crypto/ec/ec_oct.c \
	$(SSL_DIR)/crypto/ec/ec2_smpl.c \
	$(SSL_DIR)/crypto/ec/ecp_nist.c \
	$(SSL_DIR)/crypto/ec/ecp_smpl.c \
	$(SSL_DIR)/crypto/ec/ecp_mont.c \
	$(SSL_DIR)/crypto/ec/ecp_oct.c \
	$(SSL_DIR)/crypto/ec/eck_prn.c \
	$(SSL_DIR)/crypto/ecdsa/ecs_lib.c \
	$(SSL_DIR)/crypto/ecdsa/ecs_sign.c \
	$(SSL_DIR)/crypto/ecdsa/ecs_ossl.c \
	$(SSL_DIR)/crypto/ecdsa/ecs_asn1.c \
	$(SSL_DIR)/crypto/ecdsa/ecs_vrf.c

rand_sources = \
	$(SSL_DIR)/crypto/rand/rand_lib.c $(SSL_DIR)/crypto/rand/rand_err.c $(SSL_DIR)/crypto/rand/rand_egd.c $(SSL_DIR)/crypto/rand/rand_win.c $(SSL_DIR)/crypto/rand/rand_unix.c $(SSL_DIR)/crypto/rand/rand_os2.c $(SSL_DIR)/crypto/rand/rand_nw.c \
	$(SSL_DIR)/crypto/rand/md_rand.c 

#engine_sources = \
#	$(SSL_DIR)/crypto/engine/eng_err.c $(SSL_DIR)/crypto/engine/eng_lib.c $(SSL_DIR)/crypto/engine/eng_list.c $(SSL_DIR)/crypto/engine/eng_init.c $(SSL_DIR)/crypto/engine/eng_ctrl.c $(SSL_DIR)/crypto/engine/eng_table.c $(SSL_DIR)/crypto/engine/eng_pkey.c $(SSL_DIR)/crypto/engine/eng_fat.c $(SSL_DIR)/crypto/engine/eng_all.c $(SSL_DIR)/crypto/engine/tb_rsa.c $(SSL_DIR)/crypto/engine/tb_dsa.c $(SSL_DIR)/crypto/engine/tb_ecdsa.c $(SSL_DIR)/crypto/engine/tb_dh.c $(SSL_DIR)/crypto/engine/tb_ecdh.c $(SSL_DIR)/crypto/engine/tb_rand.c $(SSL_DIR)/crypto/engine/tb_store.c $(SSL_DIR)/crypto/engine/tb_cipher.c $(SSL_DIR)/crypto/engine/tb_digest.c $(SSL_DIR)/crypto/engine/tb_pkmeth.c $(SSL_DIR)/crypto/engine/tb_asnmth.c $(SSL_DIR)/crypto/engine/eng_openssl.c $(SSL_DIR)/crypto/engine/eng_cnf.c $(SSL_DIR)/crypto/engine/eng_dyn.c $(SSL_DIR)/crypto/engine/eng_cryptodev.c $(SSL_DIR)/crypto/engine/eng_rsax.c $(SSL_DIR)/crypto/engine/eng_rdrand.c


evp_sources = \
	$(SSL_DIR)/crypto/evp/evp_lib.c \
	$(SSL_DIR)/crypto/evp/p_dec.c \
	$(SSL_DIR)/crypto/evp/p_enc.c \
	$(SSL_DIR)/crypto/evp/p_lib.c \
	$(SSL_DIR)/crypto/evp/p_open.c \
	$(SSL_DIR)/crypto/evp/p_seal.c \
	$(SSL_DIR)/crypto/evp/p_sign.c \
	$(SSL_DIR)/crypto/evp/p_verify.c \
	$(SSL_DIR)/crypto/evp/evp_err.c \
	$(SSL_DIR)/crypto/evp/pmeth_lib.c $(SSL_DIR)/crypto/evp/pmeth_fn.c $(SSL_DIR)/crypto/evp/pmeth_gn.c \
	$(SSL_DIR)/crypto/evp/digest.c \
	$(SSL_DIR)/crypto/evp/evp_enc.c \
	$(SSL_DIR)/crypto/evp/names.c \
	$(SSL_DIR)/crypto/evp/evp_pbe.c \
	$(SSL_DIR)/crypto/evp/p5_crpt.c \
	$(SSL_DIR)/crypto/evp/p5_crpt2.c \
	$(SSL_DIR)/crypto/evp/evp_pkey.c \
	$(SSL_DIR)/crypto/evp/m_dss1.c \
	$(SSL_DIR)/crypto/evp/m_dss.c \
	$(SSL_DIR)/crypto/evp/m_ecdsa.c \
	$(SSL_DIR)/crypto/evp/m_md2.c \
	$(SSL_DIR)/crypto/evp/m_md4.c \
	$(SSL_DIR)/crypto/evp/m_md5.c \
	$(SSL_DIR)/crypto/evp/m_mdc2.c \
	$(SSL_DIR)/crypto/evp/m_null.c \
	$(SSL_DIR)/crypto/evp/m_ripemd.c \
	$(SSL_DIR)/crypto/evp/m_sha1.c \
	$(SSL_DIR)/crypto/evp/m_sha.c \
	$(SSL_DIR)/crypto/evp/m_sigver.c \
	$(SSL_DIR)/crypto/evp/m_wp.c \
	$(SSL_DIR)/crypto/evp/bio_b64.c \
	$(SSL_DIR)/crypto/evp/bio_enc.c \
	$(SSL_DIR)/crypto/evp/bio_md.c \
	$(SSL_DIR)/crypto/evp/bio_ok.c



#	$(SSL_DIR)/crypto/evp/e_seed.c $(SSL_DIR)/crypto/evp/evp_err.c $(SSL_DIR)/crypto/evp/encode.c $(SSL_DIR)/crypto/evp/digest.c $(SSL_DIR)/crypto/evp/evp_enc.c $(SSL_DIR)/crypto/evp/evp_key.c $(SSL_DIR)/crypto/evp/evp_acnf.c $(SSL_DIR)/crypto/evp/evp_cnf.c $(SSL_DIR)/crypto/evp/e_des.c $(SSL_DIR)/crypto/evp/e_bf.c $(SSL_DIR)/crypto/evp/e_idea.c $(SSL_DIR)/crypto/evp/e_des3.c $(SSL_DIR)/crypto/evp/e_camellia.c $(SSL_DIR)/crypto/evp/e_rc4.c $(SSL_DIR)/crypto/evp/e_aes.c $(SSL_DIR)/crypto/evp/names.c $(SSL_DIR)/crypto/evp/e_seed.c $(SSL_DIR)/crypto/evp/e_xcbc_d.c $(SSL_DIR)/crypto/evp/e_rc2.c $(SSL_DIR)/crypto/evp/e_cast.c $(SSL_DIR)/crypto/evp/e_rc5.c $(SSL_DIR)/crypto/evp/m_null.c $(SSL_DIR)/crypto/evp/m_md2.c $(SSL_DIR)/crypto/evp/m_md4.c $(SSL_DIR)/crypto/evp/m_md5.c $(SSL_DIR)/crypto/evp/m_sha.c $(SSL_DIR)/crypto/evp/m_sha1.c $(SSL_DIR)/crypto/evp/m_wp.c $(SSL_DIR)/crypto/evp/m_dss.c $(SSL_DIR)/crypto/evp/m_dss1.c $(SSL_DIR)/crypto/evp/m_mdc2.c $(SSL_DIR)/crypto/evp/m_ripemd.c $(SSL_DIR)/crypto/evp/m_ecdsa.c $(SSL_DIR)/crypto/evp/p_open.c $(SSL_DIR)/crypto/evp/p_seal.c $(SSL_DIR)/crypto/evp/p_sign.c $(SSL_DIR)/crypto/evp/p_verify.c $(SSL_DIR)/crypto/evp/evp_lib.c $(SSL_DIR)/crypto/evp/p_lib.c $(SSL_DIR)/crypto/ocsp/ocsp_lib.c $(SSL_DIR)/crypto/srp/srp_lib.c $(SSL_DIR)/crypto/evp/evp_enc.c $(SSL_DIR)/crypto/evp/p_enc.c $(SSL_DIR)/crypto/evp/p_dec.c $(SSL_DIR)/crypto/evp/bio_md.c $(SSL_DIR)/crypto/evp/bio_b64.c $(SSL_DIR)/crypto/evp/bio_enc.c $(SSL_DIR)/crypto/evp/evp_err.c $(SSL_DIR)/crypto/evp/e_null.c $(SSL_DIR)/crypto/evp/c_all.c $(SSL_DIR)/crypto/evp/c_allc.c $(SSL_DIR)/crypto/evp/c_alld.c $(SSL_DIR)/crypto/evp/evp_lib.c $(SSL_DIR)/crypto/evp/bio_ok.c $(SSL_DIR)/crypto/evp/evp_pkey.c $(SSL_DIR)/crypto/evp/evp_pbe.c

# $(SSL_DIR)/crypto/evp/p5_crpt.c $(SSL_DIR)/crypto/evp/p5_crpt2.c $(SSL_DIR)/crypto/evp/e_old.c $(SSL_DIR)/crypto/evp/pmeth_lib.c $(SSL_DIR)/crypto/evp/pmeth_fn.c $(SSL_DIR)/crypto/evp/pmeth_gn.c $(SSL_DIR)/crypto/evp/m_sigver.c $(SSL_DIR)/crypto/evp/evp_fips.c $(SSL_DIR)/crypto/evp/e_aes_cbc_hmac_sha1.c $(SSL_DIR)/crypto/evp/e_rc4_hmac_md5.c

obj_sources = \
	$(SSL_DIR)/crypto/objects/obj_lib.c \
	$(SSL_DIR)/crypto/objects/obj_dat.c \
	$(SSL_DIR)/crypto/objects/obj_xref.c \
	$(SSL_DIR)/crypto/objects/o_names.c

#	$(SSL_DIR)/crypto/objects/o_names.c $(SSL_DIR)/crypto/objects/obj_dat.c $(SSL_DIR)/crypto/objects/obj_lib.c $(SSL_DIR)/crypto/objects/obj_err.c $(SSL_DIR)/crypto/objects/obj_xref.c

asn1_sources = \
	$(SSL_DIR)/crypto/asn1/a_bitstr.c \
	$(SSL_DIR)/crypto/asn1/a_bool.c \
	$(SSL_DIR)/crypto/asn1/a_bytes.c \
	$(SSL_DIR)/crypto/asn1/a_d2i_fp.c \
	$(SSL_DIR)/crypto/asn1/a_digest.c \
	$(SSL_DIR)/crypto/asn1/a_dup.c \
	$(SSL_DIR)/crypto/asn1/a_enum.c \
	$(SSL_DIR)/crypto/asn1/a_gentm.c \
	$(SSL_DIR)/crypto/asn1/a_i2d_fp.c \
	$(SSL_DIR)/crypto/asn1/a_int.c \
	$(SSL_DIR)/crypto/asn1/a_mbstr.c \
	$(SSL_DIR)/crypto/asn1/ameth_lib.c \
	$(SSL_DIR)/crypto/asn1/a_object.c \
	$(SSL_DIR)/crypto/asn1/a_octet.c \
	$(SSL_DIR)/crypto/asn1/a_print.c \
	$(SSL_DIR)/crypto/asn1/a_set.c \
	$(SSL_DIR)/crypto/asn1/a_sign.c \
	$(SSL_DIR)/crypto/asn1/asn1_err.c \
	$(SSL_DIR)/crypto/asn1/asn1_gen.c \
	$(SSL_DIR)/crypto/asn1/asn1_lib.c \
	$(SSL_DIR)/crypto/asn1/asn1_par.c \
	$(SSL_DIR)/crypto/asn1/asn_mime.c \
	$(SSL_DIR)/crypto/asn1/asn_moid.c \
	$(SSL_DIR)/crypto/asn1/asn_pack.c \
	$(SSL_DIR)/crypto/asn1/a_strex.c \
	$(SSL_DIR)/crypto/asn1/a_strnid.c \
	$(SSL_DIR)/crypto/asn1/a_time.c \
	$(SSL_DIR)/crypto/asn1/a_type.c \
	$(SSL_DIR)/crypto/asn1/a_utctm.c \
	$(SSL_DIR)/crypto/asn1/a_utf8.c \
	$(SSL_DIR)/crypto/asn1/a_verify.c \
	$(SSL_DIR)/crypto/asn1/bio_asn1.c \
	$(SSL_DIR)/crypto/asn1/bio_ndef.c \
	$(SSL_DIR)/crypto/asn1/d2i_pr.c \
	$(SSL_DIR)/crypto/asn1/d2i_pu.c \
	$(SSL_DIR)/crypto/asn1/evp_asn1.c \
	$(SSL_DIR)/crypto/asn1/f_enum.c \
	$(SSL_DIR)/crypto/asn1/f_int.c \
	$(SSL_DIR)/crypto/asn1/f_string.c \
	$(SSL_DIR)/crypto/asn1/i2d_pr.c \
	$(SSL_DIR)/crypto/asn1/i2d_pu.c \
	$(SSL_DIR)/crypto/asn1/n_pkey.c \
	$(SSL_DIR)/crypto/asn1/nsseq.c \
	$(SSL_DIR)/crypto/asn1/p5_pbe.c \
	$(SSL_DIR)/crypto/asn1/p5_pbev2.c \
	$(SSL_DIR)/crypto/asn1/p8_pkey.c \
	$(SSL_DIR)/crypto/asn1/tasn_dec.c \
	$(SSL_DIR)/crypto/asn1/tasn_enc.c \
	$(SSL_DIR)/crypto/asn1/tasn_fre.c \
	$(SSL_DIR)/crypto/asn1/tasn_new.c \
	$(SSL_DIR)/crypto/asn1/tasn_prn.c \
	$(SSL_DIR)/crypto/asn1/tasn_typ.c \
	$(SSL_DIR)/crypto/asn1/tasn_utl.c \
	$(SSL_DIR)/crypto/asn1/t_bitst.c \
	$(SSL_DIR)/crypto/asn1/t_crl.c \
	$(SSL_DIR)/crypto/asn1/t_pkey.c \
	$(SSL_DIR)/crypto/asn1/t_req.c \
	$(SSL_DIR)/crypto/asn1/t_spki.c \
	$(SSL_DIR)/crypto/asn1/t_x509a.c \
	$(SSL_DIR)/crypto/asn1/t_x509.c \
	$(SSL_DIR)/crypto/asn1/x_algor.c \
	$(SSL_DIR)/crypto/asn1/x_attrib.c \
	$(SSL_DIR)/crypto/asn1/x_bignum.c \
	$(SSL_DIR)/crypto/asn1/x_crl.c \
	$(SSL_DIR)/crypto/asn1/x_exten.c \
	$(SSL_DIR)/crypto/asn1/x_info.c \
	$(SSL_DIR)/crypto/asn1/x_long.c \
	$(SSL_DIR)/crypto/asn1/x_name.c \
	$(SSL_DIR)/crypto/asn1/x_nx509.c \
	$(SSL_DIR)/crypto/asn1/x_pkey.c \
	$(SSL_DIR)/crypto/asn1/x_pubkey.c \
	$(SSL_DIR)/crypto/asn1/x_req.c \
	$(SSL_DIR)/crypto/asn1/x_sig.c \
	$(SSL_DIR)/crypto/asn1/x_spki.c \
	$(SSL_DIR)/crypto/asn1/x_val.c \
	$(SSL_DIR)/crypto/asn1/x_x509a.c \
	$(SSL_DIR)/crypto/asn1/x_x509.c

cmac_sources = \
	$(SSL_DIR)/crypto/cmac/cmac.c \
	$(SSL_DIR)/crypto/cmac/cm_ameth.c \
	$(SSL_DIR)/crypto/cmac/cm_pmeth.c

hmac_sources = \
	$(SSL_DIR)/crypto/hmac/hmac.c \
	$(SSL_DIR)/crypto/hmac/hm_ameth.c \
	$(SSL_DIR)/crypto/hmac/hm_pmeth.c

pkcs12_sources = \
	$(SSL_DIR)/crypto/pkcs12/p12_add.c \
	$(SSL_DIR)/crypto/pkcs12/p12_asn.c \
	$(SSL_DIR)/crypto/pkcs12/p12_attr.c \
	$(SSL_DIR)/crypto/pkcs12/p12_crpt.c \
	$(SSL_DIR)/crypto/pkcs12/p12_crt.c \
	$(SSL_DIR)/crypto/pkcs12/p12_decr.c \
	$(SSL_DIR)/crypto/pkcs12/p12_init.c \
	$(SSL_DIR)/crypto/pkcs12/p12_key.c \
	$(SSL_DIR)/crypto/pkcs12/p12_kiss.c \
	$(SSL_DIR)/crypto/pkcs12/p12_mutl.c \
	$(SSL_DIR)/crypto/pkcs12/p12_npas.c \
	$(SSL_DIR)/crypto/pkcs12/p12_p8d.c \
	$(SSL_DIR)/crypto/pkcs12/p12_p8e.c \
	$(SSL_DIR)/crypto/pkcs12/p12_utl.c \
	$(SSL_DIR)/crypto/pkcs12/pk12err.c

x509_sources = \
	$(SSL_DIR)/crypto/x509/x509_att.c \
	$(SSL_DIR)/crypto/x509/x509_cmp.c \
	$(SSL_DIR)/crypto/x509/x509cset.c \
	$(SSL_DIR)/crypto/x509/x509_d2.c \
	$(SSL_DIR)/crypto/x509/x509_def.c \
	$(SSL_DIR)/crypto/x509/x509_err.c \
	$(SSL_DIR)/crypto/x509/x509_ext.c \
	$(SSL_DIR)/crypto/x509/x509_lu.c \
	$(SSL_DIR)/crypto/x509/x509name.c \
	$(SSL_DIR)/crypto/x509/x509_obj.c \
	$(SSL_DIR)/crypto/x509/x509_r2x.c \
	$(SSL_DIR)/crypto/x509/x509_req.c \
	$(SSL_DIR)/crypto/x509/x509rset.c \
	$(SSL_DIR)/crypto/x509/x509_set.c \
	$(SSL_DIR)/crypto/x509/x509spki.c \
	$(SSL_DIR)/crypto/x509/x509_trs.c \
	$(SSL_DIR)/crypto/x509/x509_txt.c \
	$(SSL_DIR)/crypto/x509/x509type.c \
	$(SSL_DIR)/crypto/x509/x509_v3.c \
	$(SSL_DIR)/crypto/x509/x509_vfy.c \
	$(SSL_DIR)/crypto/x509/x509_vpm.c \
	$(SSL_DIR)/crypto/x509/x_all.c \
	$(SSL_DIR)/crypto/x509v3/v3_addr.c \
	$(SSL_DIR)/crypto/x509v3/v3_akeya.c \
	$(SSL_DIR)/crypto/x509v3/v3_akey.c \
	$(SSL_DIR)/crypto/x509v3/v3_alt.c \
	$(SSL_DIR)/crypto/x509v3/v3_asid.c \
	$(SSL_DIR)/crypto/x509v3/v3_bcons.c \
	$(SSL_DIR)/crypto/x509v3/v3_bitst.c \
	$(SSL_DIR)/crypto/x509v3/v3_conf.c \
	$(SSL_DIR)/crypto/x509v3/v3_cpols.c \
	$(SSL_DIR)/crypto/x509v3/v3_crld.c \
	$(SSL_DIR)/crypto/x509v3/v3_enum.c \
	$(SSL_DIR)/crypto/x509v3/v3err.c \
	$(SSL_DIR)/crypto/x509v3/v3_extku.c \
	$(SSL_DIR)/crypto/x509v3/v3_genn.c \
	$(SSL_DIR)/crypto/x509v3/v3_ia5.c \
	$(SSL_DIR)/crypto/x509v3/v3_info.c \
	$(SSL_DIR)/crypto/x509v3/v3_int.c \
	$(SSL_DIR)/crypto/x509v3/v3_lib.c \
	$(SSL_DIR)/crypto/x509v3/v3_ncons.c \
	$(SSL_DIR)/crypto/x509v3/v3_ocsp.c \
	$(SSL_DIR)/crypto/x509v3/v3_pcia.c \
	$(SSL_DIR)/crypto/x509v3/v3_pci.c \
	$(SSL_DIR)/crypto/x509v3/v3_pcons.c \
	$(SSL_DIR)/crypto/x509v3/v3_pku.c \
	$(SSL_DIR)/crypto/x509v3/v3_pmaps.c \
	$(SSL_DIR)/crypto/x509v3/v3_prn.c \
	$(SSL_DIR)/crypto/x509v3/v3_purp.c \
	$(SSL_DIR)/crypto/x509v3/v3_skey.c \
	$(SSL_DIR)/crypto/x509v3/v3_sxnet.c \
	$(SSL_DIR)/crypto/x509v3/v3_utl.c \
	$(SSL_DIR)/crypto/x509v3/pcy_cache.c \
	$(SSL_DIR)/crypto/x509v3/pcy_node.c \
	$(SSL_DIR)/crypto/x509v3/pcy_data.c \
	$(SSL_DIR)/crypto/x509v3/pcy_map.c \
	$(SSL_DIR)/crypto/x509v3/pcy_tree.c \
	$(SSL_DIR)/crypto/x509v3/pcy_lib.c

pkcs7_sources = \
	$(SSL_DIR)/crypto/pkcs7/bio_pk7.c \
	$(SSL_DIR)/crypto/pkcs7/pk7_asn1.c \
	$(SSL_DIR)/crypto/pkcs7/pk7_attr.c \
	$(SSL_DIR)/crypto/pkcs7/pk7_doit.c \
	$(SSL_DIR)/crypto/pkcs7/pk7_lib.c \
	$(SSL_DIR)/crypto/pkcs7/pk7_mime.c \
	$(SSL_DIR)/crypto/pkcs7/pk7_smime.c \
	$(SSL_DIR)/crypto/pkcs7/pkcs7err.c

conf_sources = \
	$(SSL_DIR)/crypto/conf/conf_api.c \
	$(SSL_DIR)/crypto/conf/conf_def.c \
	$(SSL_DIR)/crypto/conf/conf_err.c \
	$(SSL_DIR)/crypto/conf/conf_lib.c \
	$(SSL_DIR)/crypto/conf/conf_mall.c \
	$(SSL_DIR)/crypto/conf/conf_mod.c \
	$(SSL_DIR)/crypto/conf/conf_sap.c

dso_sources = \
	$(SSL_DIR)/crypto/dso/dso_beos.c \
	$(SSL_DIR)/crypto/dso/dso_dl.c \
	$(SSL_DIR)/crypto/dso/dso_dlfcn.c \
	$(SSL_DIR)/crypto/dso/dso_err.c \
	$(SSL_DIR)/crypto/dso/dso_lib.c \
	$(SSL_DIR)/crypto/dso/dso_null.c \
	$(SSL_DIR)/crypto/dso/dso_openssl.c \
	$(SSL_DIR)/crypto/dso/dso_vms.c \
	$(SSL_DIR)/crypto/dso/dso_win32.c

rsa_sources = \
	$(SSL_DIR)/crypto/rsa/rsa_ameth.c \
	$(SSL_DIR)/crypto/rsa/rsa_asn1.c \
	$(SSL_DIR)/crypto/rsa/rsa_chk.c \
	$(SSL_DIR)/crypto/rsa/rsa_crpt.c \
	$(SSL_DIR)/crypto/rsa/rsa_depr.c \
	$(SSL_DIR)/crypto/rsa/rsa_eay.c \
	$(SSL_DIR)/crypto/rsa/rsa_err.c \
	$(SSL_DIR)/crypto/rsa/rsa_gen.c \
	$(SSL_DIR)/crypto/rsa/rsa_lib.c \
	$(SSL_DIR)/crypto/rsa/rsa_none.c \
	$(SSL_DIR)/crypto/rsa/rsa_null.c \
	$(SSL_DIR)/crypto/rsa/rsa_oaep.c \
	$(SSL_DIR)/crypto/rsa/rsa_pk1.c \
	$(SSL_DIR)/crypto/rsa/rsa_pmeth.c \
	$(SSL_DIR)/crypto/rsa/rsa_prn.c \
	$(SSL_DIR)/crypto/rsa/rsa_pss.c \
	$(SSL_DIR)/crypto/rsa/rsa_saos.c \
	$(SSL_DIR)/crypto/rsa/rsa_sign.c \
	$(SSL_DIR)/crypto/rsa/rsa_ssl.c \
	$(SSL_DIR)/crypto/rsa/rsa_x931.c

dsa_sources = \
	$(SSL_DIR)/crypto/dsa/dsa_ameth.c \
	$(SSL_DIR)/crypto/dsa/dsa_asn1.c \
	$(SSL_DIR)/crypto/dsa/dsa_depr.c \
	$(SSL_DIR)/crypto/dsa/dsa_err.c \
	$(SSL_DIR)/crypto/dsa/dsa_gen.c \
	$(SSL_DIR)/crypto/dsa/dsa_key.c \
	$(SSL_DIR)/crypto/dsa/dsa_lib.c \
	$(SSL_DIR)/crypto/dsa/dsa_ossl.c \
	$(SSL_DIR)/crypto/dsa/dsa_pmeth.c \
	$(SSL_DIR)/crypto/dsa/dsa_prn.c \
	$(SSL_DIR)/crypto/dsa/dsa_sign.c \
	$(SSL_DIR)/crypto/dsa/dsa_vrf.c

md5_sources = \
	$(SSL_DIR)/crypto/md5/md5.c \
	$(SSL_DIR)/crypto/md5/md5_dgst.c \
	$(SSL_DIR)/crypto/md5/md5_one.c

ecdh_sources = \
	$(SSL_DIR)/crypto/ecdh/ecdhtest.c \
	$(SSL_DIR)/crypto/ecdh/ech_err.c \
	$(SSL_DIR)/crypto/ecdh/ech_key.c \
	$(SSL_DIR)/crypto/ecdh/ech_lib.c \
	$(SSL_DIR)/crypto/ecdh/ech_ossl.c

pem_sources = \
	$(SSL_DIR)/crypto/pem/pem_all.c \
	$(SSL_DIR)/crypto/pem/pem_err.c \
	$(SSL_DIR)/crypto/pem/pem_info.c \
	$(SSL_DIR)/crypto/pem/pem_lib.c \
	$(SSL_DIR)/crypto/pem/pem_oth.c \
	$(SSL_DIR)/crypto/pem/pem_pk8.c \
	$(SSL_DIR)/crypto/pem/pem_pkey.c \
	$(SSL_DIR)/crypto/pem/pem_seal.c \
	$(SSL_DIR)/crypto/pem/pem_sign.c \
	$(SSL_DIR)/crypto/pem/pem_x509.c \
	$(SSL_DIR)/crypto/pem/pem_xaux.c \
	$(SSL_DIR)/crypto/pem/pvkfmt.c


libcrypto_sources = \
	$(SSL_DIR)/crypto/cversion.c \
	$(SSL_DIR)/crypto/mem_clr.c \
	$(SSL_DIR)/crypto/cryptlib.c $(SSL_DIR)/crypto/mem.c $(SSL_DIR)/crypto/mem_dbg.c $(SSL_DIR)/crypto/ex_data.c $(SSL_DIR)/crypto/cpt_err.c $(SSL_DIR)/crypto/ebcdic.c $(SSL_DIR)/crypto/uid.c $(SSL_DIR)/crypto/o_time.c $(SSL_DIR)/crypto/o_str.c $(SSL_DIR)/crypto/o_dir.c $(SSL_DIR)/crypto/o_fips.c $(SSL_DIR)/crypto/o_init.c $(SSL_DIR)/crypto/fips_ers.c \
	$(SSL_DIR)/crypto/err/err.c \
	$(SSL_DIR)/crypto/err/err_all.c \
	$(SSL_DIR)/crypto/err/err_prn.c \
	$(SSL_DIR)/crypto/stack/stack.c \
	$(SSL_DIR)/crypto/lhash/lhash.c $(SSL_DIR)/crypto/lhash/lh_stats.c \
	$(conf_sources) \
	$(dso_sources) \
	$(bio_sources) \
	$(buffer_sources) \
	$(evp_sources) \
	$(rand_sources) \
	$(obj_sources) \
	$(asn1_sources) \
	$(hmac_sources) \
	$(pkcs12_sources) \
	$(x509_sources) \
	$(pem_sources) \
	$(cmac_sources) \
	$(rsa_sources) \
	$(dsa_sources) \
	$(md5_sources) \
	$(sha_sources) \
	$(aes_sources) \
	$(ec_sources) \
	$(ecdh_sources) \
	$(pkcs7_sources) \
	$(bn_sources) \
	$(SSL_DIR)/crypto/ripemd/rmd_dgst.c $(SSL_DIR)/crypto/ripemd/rmd_one.c

libcrypto2_sources = \
	$(SSL_DIR)/crypto/cryptlib.c $(SSL_DIR)/crypto/bio/bss_mem.c $(SSL_DIR)/crypto/mem.c $(SSL_DIR)/crypto/mem_dbg.c $(SSL_DIR)/crypto/cversion.c $(SSL_DIR)/crypto/ex_data.c $(SSL_DIR)/crypto/cpt_err.c $(SSL_DIR)/crypto/ebcdic.c $(SSL_DIR)/crypto/uid.c $(SSL_DIR)/crypto/o_time.c $(SSL_DIR)/crypto/o_str.c $(SSL_DIR)/crypto/o_dir.c $(SSL_DIR)/crypto/o_fips.c $(SSL_DIR)/crypto/o_init.c $(SSL_DIR)/crypto/fips_ers.c $(SSL_DIR)/crypto/x86_64cpuid.s $(SSL_DIR)/crypto/objects/o_names.c $(SSL_DIR)/crypto/objects/obj_dat.c $(SSL_DIR)/crypto/objects/obj_lib.c $(SSL_DIR)/crypto/objects/obj_err.c $(SSL_DIR)/crypto/objects/obj_xref.c $(SSL_DIR)/crypto/md4/md4_dgst.c $(SSL_DIR)/crypto/md4/md4_one.c $(SSL_DIR)/crypto/md5/md5_dgst.c $(SSL_DIR)/crypto/md5/md5_one.c $(SSL_DIR)/crypto/md5/md5-x86_64.s $(SSL_DIR)/crypto/sha/sha_dgst.c $(SSL_DIR)/crypto/sha/sha1dgst.c $(SSL_DIR)/crypto/sha/sha1-x86_64.s $(SSL_DIR)/crypto/sha/sha_one.c $(SSL_DIR)/crypto/sha/sha1_one.c $(SSL_DIR)/crypto/sha/sha256.c $(SSL_DIR)/crypto/sha/sha512.c \
	$(SSL_DIR)/crypto/sha/sha256-x86_64.s $(SSL_DIR)/crypto/sha/sha512-x86_64.s $(SSL_DIR)/crypto/mdc2/mdc2dgst.c $(SSL_DIR)/crypto/mdc2/mdc2_one.c $(SSL_DIR)/crypto/hmac/hmac.c $(SSL_DIR)/crypto/hmac/hm_ameth.c $(SSL_DIR)/crypto/hmac/hm_pmeth.c $(SSL_DIR)/crypto/ripemd/rmd_dgst.c $(SSL_DIR)/crypto/ripemd/rmd_one.c $(SSL_DIR)/crypto/whrlpool/wp_dgst.c $(SSL_DIR)/crypto/whrlpool/wp-x86_64.s $(SSL_DIR)/crypto/des/set_key.c $(SSL_DIR)/crypto/des/ecb_enc.c $(SSL_DIR)/crypto/des/cbc_enc.c $(SSL_DIR)/crypto/des/pcbc_enc.c $(SSL_DIR)/crypto/des/xcbc_enc.c $(SSL_DIR)/crypto/des/ecb3_enc.c $(SSL_DIR)/crypto/des/cfb64enc.c $(SSL_DIR)/crypto/des/cfb64ede.c $(SSL_DIR)/crypto/des/cfb_enc.c $(SSL_DIR)/crypto/des/ofb64ede.c $(SSL_DIR)/crypto/des/enc_read.c $(SSL_DIR)/crypto/des/enc_writ.c $(SSL_DIR)/crypto/des/ofb64enc.c $(SSL_DIR)/crypto/des/ofb_enc.c $(SSL_DIR)/crypto/des/str2key.c $(SSL_DIR)/crypto/des/pcbc_enc.c $(SSL_DIR)/crypto/des/qud_cksm.c $(SSL_DIR)/crypto/des/rand_key.c $(SSL_DIR)/crypto/des/des_enc.c $(SSL_DIR)/crypto/des/fcrypt_b.c $(SSL_DIR)/crypto/des/fcrypt.c $(SSL_DIR)/crypto/des/xcbc_enc.c $(SSL_DIR)/crypto/des/rpc_enc.c $(SSL_DIR)/crypto/des/cbc_cksm.c $(SSL_DIR)/crypto/des/ede_cbcm_enc.c $(SSL_DIR)/crypto/des/des_old.c $(SSL_DIR)/crypto/des/des_old2.c $(SSL_DIR)/crypto/des/read2pwd.c \
	$(SSL_DIR)/crypto/rc2/rc2_ecb.c $(SSL_DIR)/crypto/rc2/rc2_skey.c $(SSL_DIR)/crypto/rc2/rc2_cbc.c $(SSL_DIR)/crypto/rc2/rc2cfb64.c $(SSL_DIR)/crypto/rc2/rc2ofb64.c $(SSL_DIR)/crypto/rc4/rc4-x86_64.s $(SSL_DIR)/crypto/rc4/rc4-md5-x86_64.s $(SSL_DIR)/crypto/rc4/rc4_utl.c $(SSL_DIR)/crypto/idea/i_cbc.c $(SSL_DIR)/crypto/idea/i_cfb64.c $(SSL_DIR)/crypto/idea/i_ofb64.c $(SSL_DIR)/crypto/idea/i_ecb.c $(SSL_DIR)/crypto/idea/i_skey.c $(SSL_DIR)/crypto/bf/bf_skey.c $(SSL_DIR)/crypto/bf/bf_ecb.c $(SSL_DIR)/crypto/bf/bf_enc.c $(SSL_DIR)/crypto/bf/bf_cfb64.c $(SSL_DIR)/crypto/bf/bf_ofb64.c $(SSL_DIR)/crypto/cast/c_skey.c $(SSL_DIR)/crypto/cast/c_ecb.c $(SSL_DIR)/crypto/cast/c_enc.c $(SSL_DIR)/crypto/des/cbc_enc.c $(SSL_DIR)/crypto/des/pcbc_enc.c $(SSL_DIR)/crypto/des/rpc_enc.c $(SSL_DIR)/crypto/des/xcbc_enc.c $(SSL_DIR)/crypto/cast/c_cfb64.c $(SSL_DIR)/crypto/cast/c_ofb64.c $(SSL_DIR)/crypto/camellia/cmll_ecb.c $(SSL_DIR)/crypto/camellia/cmll_ofb.c $(SSL_DIR)/crypto/camellia/cmll_cfb.c $(SSL_DIR)/crypto/camellia/cmll_ctr.c $(SSL_DIR)/crypto/camellia/cmll_utl.c $(SSL_DIR)/crypto/camellia/cmll-x86_64.s $(SSL_DIR)/crypto/camellia/cmll_misc.c \
	$(SSL_DIR)/crypto/seed/seed.c $(SSL_DIR)/crypto/seed/seed_ofb.c $(SSL_DIR)/crypto/seed/seed_ecb.c $(SSL_DIR)/crypto/seed/seed_cbc.c $(SSL_DIR)/crypto/seed/seed_cfb.c $(SSL_DIR)/crypto/seed/seed_ofb.c $(SSL_DIR)/crypto/modes/cbc128.c $(SSL_DIR)/crypto/modes/ctr128.c $(SSL_DIR)/crypto/modes/cts128.c $(SSL_DIR)/crypto/modes/cfb128.c $(SSL_DIR)/crypto/modes/ofb128.c $(SSL_DIR)/crypto/modes/gcm128.c $(SSL_DIR)/crypto/modes/ccm128.c $(SSL_DIR)/crypto/modes/xts128.c $(SSL_DIR)/crypto/modes/ghash-x86_64.s \
	$(SSL_DIR)/crypto/bn/bn_asm.c $(SSL_DIR)/crypto/bn/bn_add.c $(SSL_DIR)/crypto/bn/bn_div.c $(SSL_DIR)/crypto/bn/bn_exp.c $(SSL_DIR)/crypto/bn/bn_lib.c $(SSL_DIR)/crypto/bn/bn_ctx.c $(SSL_DIR)/crypto/bn/bn_mul.c $(SSL_DIR)/crypto/bn/bn_mod.c $(SSL_DIR)/crypto/bn/bn_print.c $(SSL_DIR)/crypto/bn/bn_rand.c $(SSL_DIR)/crypto/bn/bn_shift.c $(SSL_DIR)/crypto/bn/bn_word.c $(SSL_DIR)/crypto/bn/bn_blind.c $(SSL_DIR)/crypto/bn/bn_kron.c $(SSL_DIR)/crypto/bn/bn_sqrt.c $(SSL_DIR)/crypto/bn/bn_gcd.c $(SSL_DIR)/crypto/bn/bn_prime.c $(SSL_DIR)/crypto/bn/bn_err.c $(SSL_DIR)/crypto/bn/bn_sqr.c $(SSL_DIR)/crypto/bn/x86_64-mont.s $(SSL_DIR)/crypto/bn/x86_64-mont5.s $(SSL_DIR)/crypto/bn/x86_64-gf2m.s $(SSL_DIR)/crypto/bn/modexp512-x86_64.s $(SSL_DIR)/crypto/bn/bn_recp.c $(SSL_DIR)/crypto/bn/bn_mont.c $(SSL_DIR)/crypto/bn/bn_mpi.c $(SSL_DIR)/crypto/bn/bn_exp2.c $(SSL_DIR)/crypto/bn/bn_gf2m.c $(SSL_DIR)/crypto/bn/bn_nist.c $(SSL_DIR)/crypto/bn/bn_depr.c $(SSL_DIR)/crypto/bn/bn_const.c $(SSL_DIR)/crypto/bn/bn_x931p.c $(SSL_DIR)/crypto/ec/ec_lib.c $(SSL_DIR)/crypto/ec/ecp_smpl.c $(SSL_DIR)/crypto/ec/ecp_mont.c $(SSL_DIR)/crypto/ec/ecp_nist.c $(SSL_DIR)/crypto/ec/ec_cvt.c $(SSL_DIR)/crypto/ec/ec_mult.c $(SSL_DIR)/crypto/ec/ec_err.c $(SSL_DIR)/crypto/ec/ec_curve.c $(SSL_DIR)/crypto/ec/ec_check.c $(SSL_DIR)/crypto/ec/ec_print.c $(SSL_DIR)/crypto/ec/ec_asn1.c $(SSL_DIR)/crypto/ec/ec_key.c $(SSL_DIR)/crypto/ec/ec2_smpl.c $(SSL_DIR)/crypto/ec/ec2_mult.c $(SSL_DIR)/crypto/ec/ec_ameth.c $(SSL_DIR)/crypto/ec/ec_pmeth.c $(SSL_DIR)/crypto/ec/eck_prn.c $(SSL_DIR)/crypto/ec/ecp_nistp224.c $(SSL_DIR)/crypto/ec/ecp_nistp256.c $(SSL_DIR)/crypto/ec/ecp_nistp521.c $(SSL_DIR)/crypto/ec/ecp_nistputil.c $(SSL_DIR)/crypto/ec/ecp_oct.c $(SSL_DIR)/crypto/ec/ec2_oct.c $(SSL_DIR)/crypto/ec/ec_oct.c $(SSL_DIR)/crypto/rsa/rsa_eay.c $(SSL_DIR)/crypto/rsa/rsa_gen.c $(SSL_DIR)/crypto/rsa/rsa_lib.c $(SSL_DIR)/crypto/rsa/rsa_sign.c $(SSL_DIR)/crypto/rsa/rsa_saos.c $(SSL_DIR)/crypto/rsa/rsa_err.c $(SSL_DIR)/crypto/rsa/rsa_pk1.c $(SSL_DIR)/crypto/rsa/rsa_ssl.c $(SSL_DIR)/crypto/rsa/rsa_none.c $(SSL_DIR)/crypto/rsa/rsa_oaep.c $(SSL_DIR)/crypto/rsa/rsa_chk.c $(SSL_DIR)/crypto/rsa/rsa_null.c $(SSL_DIR)/crypto/rsa/rsa_pss.c $(SSL_DIR)/crypto/rsa/rsa_x931.c $(SSL_DIR)/crypto/rsa/rsa_asn1.c $(SSL_DIR)/crypto/rsa/rsa_depr.c $(SSL_DIR)/crypto/rsa/rsa_ameth.c $(SSL_DIR)/crypto/rsa/rsa_prn.c $(SSL_DIR)/crypto/rsa/rsa_pmeth.c $(SSL_DIR)/crypto/rsa/rsa_crpt.c $(SSL_DIR)/crypto/dsa/dsa_gen.c $(SSL_DIR)/crypto/dsa/dsa_key.c $(SSL_DIR)/crypto/dsa/dsa_lib.c $(SSL_DIR)/crypto/dsa/dsa_asn1.c $(SSL_DIR)/crypto/dsa/dsa_vrf.c $(SSL_DIR)/crypto/dsa/dsa_sign.c $(SSL_DIR)/crypto/dsa/dsa_err.c $(SSL_DIR)/crypto/dsa/dsa_ossl.c $(SSL_DIR)/crypto/dsa/dsa_depr.c $(SSL_DIR)/crypto/dsa/dsa_ameth.c $(SSL_DIR)/crypto/dsa/dsa_pmeth.c $(SSL_DIR)/crypto/dsa/dsa_prn.c $(SSL_DIR)/crypto/ecdsa/ecs_lib.c $(SSL_DIR)/crypto/ecdsa/ecs_asn1.c $(SSL_DIR)/crypto/ecdsa/ecs_ossl.c $(SSL_DIR)/crypto/ecdsa/ecs_sign.c $(SSL_DIR)/crypto/ecdsa/ecs_vrf.c $(SSL_DIR)/crypto/ecdsa/ecs_err.c $(SSL_DIR)/crypto/dh/dh_asn1.c $(SSL_DIR)/crypto/dh/dh_gen.c $(SSL_DIR)/crypto/dh/dh_key.c $(SSL_DIR)/crypto/dh/dh_lib.c $(SSL_DIR)/crypto/dh/dh_check.c $(SSL_DIR)/crypto/dh/dh_err.c $(SSL_DIR)/crypto/dh/dh_depr.c $(SSL_DIR)/crypto/dh/dh_ameth.c $(SSL_DIR)/crypto/dh/dh_pmeth.c $(SSL_DIR)/crypto/dh/dh_prn.c $(SSL_DIR)/crypto/ecdh/ech_lib.c $(SSL_DIR)/crypto/ecdh/ech_ossl.c $(SSL_DIR)/crypto/ecdh/ech_key.c $(SSL_DIR)/crypto/ecdh/ech_err.c $(SSL_DIR)/crypto/dso/dso_dl.c $(SSL_DIR)/crypto/dso/dso_dlfcn.c $(SSL_DIR)/crypto/dso/dso_err.c $(SSL_DIR)/crypto/dso/dso_lib.c $(SSL_DIR)/crypto/dso/dso_null.c $(SSL_DIR)/crypto/dso/dso_openssl.c $(SSL_DIR)/crypto/dso/dso_win32.c $(SSL_DIR)/crypto/dso/dso_vms.c $(SSL_DIR)/crypto/dso/dso_beos.c $(SSL_DIR)/crypto/engine/eng_err.c $(SSL_DIR)/crypto/engine/eng_lib.c $(SSL_DIR)/crypto/engine/eng_list.c $(SSL_DIR)/crypto/engine/eng_init.c $(SSL_DIR)/crypto/engine/eng_ctrl.c $(SSL_DIR)/crypto/engine/eng_table.c $(SSL_DIR)/crypto/engine/eng_pkey.c $(SSL_DIR)/crypto/engine/eng_fat.c $(SSL_DIR)/crypto/engine/eng_all.c $(SSL_DIR)/crypto/engine/tb_rsa.c $(SSL_DIR)/crypto/engine/tb_dsa.c $(SSL_DIR)/crypto/engine/tb_ecdsa.c $(SSL_DIR)/crypto/engine/tb_dh.c $(SSL_DIR)/crypto/engine/tb_ecdh.c $(SSL_DIR)/crypto/engine/tb_rand.c $(SSL_DIR)/crypto/engine/tb_store.c $(SSL_DIR)/crypto/engine/tb_cipher.c $(SSL_DIR)/crypto/engine/tb_digest.c $(SSL_DIR)/crypto/engine/tb_pkmeth.c $(SSL_DIR)/crypto/engine/tb_asnmth.c $(SSL_DIR)/crypto/engine/eng_openssl.c $(SSL_DIR)/crypto/engine/eng_cnf.c $(SSL_DIR)/crypto/engine/eng_dyn.c $(SSL_DIR)/crypto/engine/eng_cryptodev.c $(SSL_DIR)/crypto/engine/eng_rsax.c $(SSL_DIR)/crypto/engine/eng_rdrand.c $(SSL_DIR)/crypto/buffer/buffer.c $(SSL_DIR)/crypto/buffer/buf_str.c $(SSL_DIR)/crypto/buffer/buf_err.c $(SSL_DIR)/crypto/bio/bio_lib.c $(SSL_DIR)/crypto/bio/bio_cb.c $(SSL_DIR)/crypto/bio/bio_err.c $(SSL_DIR)/crypto/bio/bss_mem.c $(SSL_DIR)/crypto/bio/bss_null.c $(SSL_DIR)/crypto/bio/bss_fd.c $(SSL_DIR)/crypto/bio/bss_file.c $(SSL_DIR)/crypto/bio/bss_sock.c $(SSL_DIR)/crypto/bio/bss_conn.c $(SSL_DIR)/crypto/bio/bf_null.c $(SSL_DIR)/crypto/bio/bf_buff.c $(SSL_DIR)/crypto/bio/b_print.c $(SSL_DIR)/crypto/bio/b_dump.c $(SSL_DIR)/crypto/bio/b_sock.c $(SSL_DIR)/crypto/bio/bss_acpt.c $(SSL_DIR)/crypto/bio/bf_nbio.c $(SSL_DIR)/crypto/bio/bss_log.c $(SSL_DIR)/crypto/bio/bss_bio.c $(SSL_DIR)/crypto/bio/bss_dgram.c $(SSL_DIR)/crypto/stack/stack.c $(SSL_DIR)/crypto/lhash/lhash.c $(SSL_DIR)/crypto/lhash/lh_stats.c $(SSL_DIR)/crypto/rand/md_rand.c $(SSL_DIR)/crypto/rand/randfile.c $(SSL_DIR)/crypto/rand/rand_lib.c $(SSL_DIR)/crypto/rand/rand_err.c $(SSL_DIR)/crypto/rand/rand_egd.c $(SSL_DIR)/crypto/rand/rand_win.c $(SSL_DIR)/crypto/rand/rand_unix.c $(SSL_DIR)/crypto/rand/rand_os2.c $(SSL_DIR)/crypto/rand/rand_nw.c $(SSL_DIR)/crypto/asn1/asn1_err.c $(SSL_DIR)/crypto/bio/bio_err.c $(SSL_DIR)/crypto/bn/bn_err.c $(SSL_DIR)/crypto/buffer/buf_err.c $(SSL_DIR)/crypto/cms/cms_err.c $(SSL_DIR)/crypto/comp/comp_err.c $(SSL_DIR)/crypto/conf/conf_err.c $(SSL_DIR)/crypto/cpt_err.c $(SSL_DIR)/crypto/dh/dh_err.c $(SSL_DIR)/crypto/dsa/dsa_err.c $(SSL_DIR)/crypto/dso/dso_err.c $(SSL_DIR)/crypto/ec/ec_err.c $(SSL_DIR)/crypto/ecdh/ech_err.c $(SSL_DIR)/crypto/ecdsa/ecs_err.c $(SSL_DIR)/crypto/engine/eng_err.c $(SSL_DIR)/crypto/err/err.c $(SSL_DIR)/crypto/err/openssl.ec \
	$(SSL_DIR)/crypto/objects/obj_err.c $(SSL_DIR)/crypto/ocsp/ocsp_err.c $(SSL_DIR)/crypto/pem/pem_err.c $(SSL_DIR)/crypto/pkcs12/pk12err.c $(SSL_DIR)/crypto/pkcs7/pkcs7err.c $(SSL_DIR)/crypto/rand/rand_err.c $(SSL_DIR)/crypto/rsa/rsa_err.c $(SSL_DIR)/crypto/ts/ts_err.c $(SSL_DIR)/crypto/ui/ui_err.c $(SSL_DIR)/crypto/x509/x509_err.c $(SSL_DIR)/crypto/x509v3/v3err.c $(SSL_DIR)/engines/ccgost/e_gost_err.c $(SSL_DIR)/ssl/ssl_err.c $(SSL_DIR)/crypto/err/err_all.c $(SSL_DIR)/crypto/err/err_prn.c $(SSL_DIR)/crypto/asn1/a_digest.c $(SSL_DIR)/crypto/engine/tb_digest.c \
	$(SSL_DIR)/crypto/objects/o_names.c $(SSL_DIR)/crypto/ts/ts_rsp_sign.c $(SSL_DIR)/crypto/ts/ts_rsp_verify.c $(SSL_DIR)/crypto/comp/comp_lib.c $(SSL_DIR)/crypto/asn1/a_object.c $(SSL_DIR)/crypto/asn1/a_bitstr.c $(SSL_DIR)/crypto/asn1/a_utctm.c $(SSL_DIR)/crypto/asn1/a_gentm.c $(SSL_DIR)/crypto/asn1/a_time.c $(SSL_DIR)/crypto/asn1/a_int.c $(SSL_DIR)/crypto/asn1/a_octet.c $(SSL_DIR)/crypto/asn1/a_print.c $(SSL_DIR)/crypto/asn1/a_type.c $(SSL_DIR)/crypto/asn1/a_set.c $(SSL_DIR)/crypto/asn1/a_dup.c $(SSL_DIR)/crypto/asn1/a_d2i_fp.c $(SSL_DIR)/crypto/asn1/a_i2d_fp.c $(SSL_DIR)/crypto/asn1/a_enum.c $(SSL_DIR)/crypto/asn1/a_utf8.c $(SSL_DIR)/crypto/asn1/a_sign.c $(SSL_DIR)/crypto/dsa/dsa_sign.c $(SSL_DIR)/crypto/rsa/rsa_sign.c $(SSL_DIR)/crypto/asn1/a_digest.c $(SSL_DIR)/crypto/asn1/a_verify.c $(SSL_DIR)/crypto/asn1/a_mbstr.c $(SSL_DIR)/crypto/asn1/a_strex.c $(SSL_DIR)/crypto/asn1/x_algor.c $(SSL_DIR)/crypto/asn1/x_val.c $(SSL_DIR)/crypto/asn1/x_pubkey.c $(SSL_DIR)/crypto/asn1/x_sig.c $(SSL_DIR)/crypto/asn1/x_req.c $(SSL_DIR)/crypto/asn1/x_attrib.c $(SSL_DIR)/crypto/asn1/x_bignum.c $(SSL_DIR)/crypto/asn1/x_long.c $(SSL_DIR)/crypto/asn1/x_name.c $(SSL_DIR)/crypto/asn1/x_x509.c $(SSL_DIR)/crypto/asn1/x_x509a.c $(SSL_DIR)/crypto/asn1/x_crl.c $(SSL_DIR)/crypto/asn1/x_info.c $(SSL_DIR)/crypto/asn1/x_spki.c $(SSL_DIR)/crypto/asn1/nsseq.c $(SSL_DIR)/crypto/asn1/x_nx509.c $(SSL_DIR)/crypto/asn1/d2i_pu.c $(SSL_DIR)/crypto/asn1/d2i_pr.c $(SSL_DIR)/crypto/asn1/i2d_pu.c $(SSL_DIR)/crypto/asn1/i2d_pr.c $(SSL_DIR)/crypto/asn1/t_req.c $(SSL_DIR)/crypto/asn1/t_x509.c $(SSL_DIR)/crypto/asn1/t_x509a.c $(SSL_DIR)/crypto/asn1/t_crl.c $(SSL_DIR)/crypto/asn1/t_pkey.c $(SSL_DIR)/crypto/asn1/t_spki.c $(SSL_DIR)/crypto/asn1/t_bitst.c $(SSL_DIR)/crypto/asn1/tasn_new.c $(SSL_DIR)/crypto/asn1/tasn_fre.c $(SSL_DIR)/crypto/asn1/tasn_enc.c $(SSL_DIR)/crypto/asn1/tasn_dec.c $(SSL_DIR)/crypto/asn1/tasn_utl.c $(SSL_DIR)/crypto/asn1/tasn_typ.c $(SSL_DIR)/crypto/asn1/tasn_prn.c $(SSL_DIR)/crypto/asn1/ameth_lib.c $(SSL_DIR)/crypto/asn1/f_int.c $(SSL_DIR)/crypto/asn1/f_string.c $(SSL_DIR)/crypto/asn1/n_pkey.c $(SSL_DIR)/crypto/asn1/f_enum.c $(SSL_DIR)/crypto/asn1/x_pkey.c $(SSL_DIR)/crypto/asn1/a_bool.c $(SSL_DIR)/crypto/asn1/x_exten.c $(SSL_DIR)/crypto/asn1/bio_asn1.c $(SSL_DIR)/crypto/asn1/bio_ndef.c $(SSL_DIR)/crypto/asn1/asn_mime.c $(SSL_DIR)/crypto/asn1/asn1_gen.c $(SSL_DIR)/crypto/asn1/asn1_par.c $(SSL_DIR)/crypto/asn1/asn1_lib.c $(SSL_DIR)/crypto/asn1/asn1_err.c $(SSL_DIR)/crypto/asn1/a_bytes.c $(SSL_DIR)/crypto/asn1/a_strnid.c $(SSL_DIR)/crypto/asn1/evp_asn1.c $(SSL_DIR)/crypto/asn1/asn_pack.c $(SSL_DIR)/crypto/asn1/p5_pbe.c $(SSL_DIR)/crypto/asn1/p5_pbev2.c $(SSL_DIR)/crypto/asn1/p8_pkey.c $(SSL_DIR)/crypto/asn1/asn_moid.c $(SSL_DIR)/crypto/pem/pem_sign.c $(SSL_DIR)/crypto/pem/pem_seal.c $(SSL_DIR)/crypto/pem/pem_info.c $(SSL_DIR)/crypto/pem/pem_lib.c $(SSL_DIR)/crypto/pem/pem_all.c $(SSL_DIR)/crypto/pem/pem_err.c $(SSL_DIR)/crypto/pem/pem_x509.c $(SSL_DIR)/crypto/pem/pem_xaux.c $(SSL_DIR)/crypto/pem/pem_oth.c $(SSL_DIR)/crypto/pem/pem_pk8.c $(SSL_DIR)/crypto/pem/pem_pkey.c $(SSL_DIR)/crypto/pem/pvkfmt.c $(SSL_DIR)/crypto/x509/x509_def.c $(SSL_DIR)/crypto/x509/x509_d2.c $(SSL_DIR)/crypto/x509/x509_r2x.c $(SSL_DIR)/crypto/x509/x509_cmp.c $(SSL_DIR)/crypto/x509/x509_obj.c $(SSL_DIR)/crypto/x509/x509_req.c $(SSL_DIR)/crypto/x509/x509spki.c $(SSL_DIR)/crypto/x509/x509_vfy.c $(SSL_DIR)/crypto/x509/x509_set.c $(SSL_DIR)/crypto/x509/x509cset.c $(SSL_DIR)/crypto/x509/x509rset.c $(SSL_DIR)/crypto/x509/x509_err.c $(SSL_DIR)/crypto/x509/x509name.c $(SSL_DIR)/crypto/x509/x509_v3.c $(SSL_DIR)/crypto/x509/x509_ext.c $(SSL_DIR)/crypto/x509/x509_att.c $(SSL_DIR)/crypto/x509/x509type.c $(SSL_DIR)/crypto/x509/x509_lu.c $(SSL_DIR)/crypto/x509/x_all.c $(SSL_DIR)/crypto/x509/x509_txt.c $(SSL_DIR)/crypto/x509/x509_trs.c $(SSL_DIR)/crypto/x509/by_file.c $(SSL_DIR)/crypto/x509/by_dir.c $(SSL_DIR)/crypto/x509/x509_vpm.c $(SSL_DIR)/crypto/x509v3/v3_bcons.c $(SSL_DIR)/crypto/x509v3/v3_bitst.c $(SSL_DIR)/crypto/x509v3/v3_conf.c $(SSL_DIR)/crypto/x509v3/v3_extku.c $(SSL_DIR)/crypto/x509v3/v3_ia5.c $(SSL_DIR)/crypto/x509v3/v3_lib.c $(SSL_DIR)/crypto/x509v3/v3_prn.c $(SSL_DIR)/crypto/x509v3/v3_utl.c $(SSL_DIR)/crypto/x509v3/v3err.c $(SSL_DIR)/crypto/x509v3/v3_genn.c $(SSL_DIR)/crypto/x509v3/v3_alt.c $(SSL_DIR)/crypto/x509v3/v3_skey.c $(SSL_DIR)/crypto/x509v3/v3_akey.c $(SSL_DIR)/crypto/x509v3/v3_pku.c $(SSL_DIR)/crypto/x509v3/v3_int.c $(SSL_DIR)/crypto/x509v3/v3_enum.c $(SSL_DIR)/crypto/x509v3/v3_sxnet.c $(SSL_DIR)/crypto/x509v3/v3_cpols.c $(SSL_DIR)/crypto/x509v3/v3_crld.c $(SSL_DIR)/crypto/x509v3/v3_purp.c $(SSL_DIR)/crypto/x509v3/v3_info.c $(SSL_DIR)/crypto/x509v3/v3_ocsp.c $(SSL_DIR)/crypto/x509v3/v3_akeya.c $(SSL_DIR)/crypto/x509v3/v3_pmaps.c $(SSL_DIR)/crypto/x509v3/v3_pcons.c $(SSL_DIR)/crypto/x509v3/v3_ncons.c $(SSL_DIR)/crypto/x509v3/v3_pcia.c $(SSL_DIR)/crypto/x509v3/v3_pci.c $(SSL_DIR)/crypto/x509v3/pcy_cache.c $(SSL_DIR)/crypto/x509v3/pcy_node.c $(SSL_DIR)/crypto/x509v3/pcy_data.c $(SSL_DIR)/crypto/x509v3/pcy_map.c $(SSL_DIR)/crypto/x509v3/pcy_tree.c $(SSL_DIR)/crypto/x509v3/pcy_lib.c $(SSL_DIR)/crypto/x509v3/v3_asid.c $(SSL_DIR)/crypto/x509v3/v3_addr.c $(SSL_DIR)/crypto/conf/conf_err.c $(SSL_DIR)/crypto/conf/conf_lib.c $(SSL_DIR)/crypto/conf/conf_api.c $(SSL_DIR)/crypto/conf/conf_def.c $(SSL_DIR)/crypto/conf/conf_mod.c $(SSL_DIR)/crypto/conf/conf_mall.c $(SSL_DIR)/crypto/conf/conf_sap.c $(SSL_DIR)/crypto/txt_db/txt_db.c $(SSL_DIR)/crypto/pkcs7/pk7_asn1.c $(SSL_DIR)/crypto/pkcs7/pk7_lib.c $(SSL_DIR)/crypto/pkcs7/pkcs7err.c $(SSL_DIR)/crypto/pkcs7/pk7_doit.c $(SSL_DIR)/crypto/pkcs7/pk7_smime.c $(SSL_DIR)/crypto/pkcs7/pk7_attr.c $(SSL_DIR)/crypto/pkcs7/pk7_mime.c $(SSL_DIR)/crypto/pkcs7/bio_pk7.c $(SSL_DIR)/crypto/pkcs12/p12_add.c $(SSL_DIR)/crypto/pkcs12/p12_asn.c $(SSL_DIR)/crypto/pkcs12/p12_attr.c $(SSL_DIR)/crypto/pkcs12/p12_crpt.c $(SSL_DIR)/crypto/pkcs12/p12_crt.c $(SSL_DIR)/crypto/pkcs12/p12_decr.c $(SSL_DIR)/crypto/pkcs12/p12_init.c $(SSL_DIR)/crypto/pkcs12/p12_key.c $(SSL_DIR)/crypto/pkcs12/p12_kiss.c $(SSL_DIR)/crypto/pkcs12/p12_mutl.c $(SSL_DIR)/crypto/pkcs12/p12_utl.c $(SSL_DIR)/crypto/pkcs12/p12_npas.c $(SSL_DIR)/crypto/pkcs12/pk12err.c $(SSL_DIR)/crypto/pkcs12/p12_p8d.c $(SSL_DIR)/crypto/pkcs12/p12_p8e.c $(SSL_DIR)/crypto/comp/comp_lib.c $(SSL_DIR)/crypto/comp/comp_err.c $(SSL_DIR)/crypto/comp/c_rle.c $(SSL_DIR)/crypto/comp/c_zlib.c $(SSL_DIR)/crypto/ocsp/ocsp_asn.c $(SSL_DIR)/crypto/ocsp/ocsp_ext.c $(SSL_DIR)/crypto/ocsp/ocsp_ht.c $(SSL_DIR)/crypto/ocsp/ocsp_lib.c $(SSL_DIR)/crypto/ocsp/ocsp_cl.c $(SSL_DIR)/crypto/ocsp/ocsp_srv.c $(SSL_DIR)/crypto/ocsp/ocsp_prn.c $(SSL_DIR)/crypto/ocsp/ocsp_vfy.c $(SSL_DIR)/crypto/ocsp/ocsp_err.c $(SSL_DIR)/crypto/ui/ui_err.c $(SSL_DIR)/crypto/ui/ui_lib.c $(SSL_DIR)/crypto/ui/ui_openssl.c $(SSL_DIR)/crypto/ui/ui_util.c $(SSL_DIR)/crypto/ui/ui_compat.c $(SSL_DIR)/crypto/krb5/krb5_asn.c $(SSL_DIR)/crypto/cms/cms_lib.c $(SSL_DIR)/crypto/cms/cms_asn1.c $(SSL_DIR)/crypto/cms/cms_att.c $(SSL_DIR)/crypto/cms/cms_io.c $(SSL_DIR)/crypto/cms/cms_smime.c $(SSL_DIR)/crypto/cms/cms_err.c $(SSL_DIR)/crypto/cms/cms_sd.c $(SSL_DIR)/crypto/cms/cms_dd.c $(SSL_DIR)/crypto/cms/cms_cd.c $(SSL_DIR)/crypto/cms/cms_env.c $(SSL_DIR)/crypto/cms/cms_enc.c $(SSL_DIR)/crypto/cms/cms_ess.c $(SSL_DIR)/crypto/cms/cms_pwri.c $(SSL_DIR)/crypto/pqueue/pqueue.c $(SSL_DIR)/crypto/ts/ts_err.c $(SSL_DIR)/crypto/ts/ts_req_utils.c $(SSL_DIR)/crypto/ts/ts_req_print.c $(SSL_DIR)/crypto/ts/ts_rsp_utils.c $(SSL_DIR)/crypto/ts/ts_rsp_print.c $(SSL_DIR)/crypto/ts/ts_rsp_sign.c $(SSL_DIR)/crypto/ts/ts_rsp_verify.c $(SSL_DIR)/crypto/ts/ts_verify_ctx.c $(SSL_DIR)/crypto/ts/ts_lib.c $(SSL_DIR)/crypto/ts/ts_conf.c $(SSL_DIR)/crypto/ts/ts_asn1.c $(SSL_DIR)/crypto/srp/srp_lib.c $(SSL_DIR)/crypto/srp/srp_vfy.c $(SSL_DIR)/crypto/cmac/cmac.c $(SSL_DIR)/crypto/cmac/cm_ameth.c $(SSL_DIR)/crypto/cmac/cm_pmeth.c $(SSL_DIR)/engines/e_4758cca.c $(SSL_DIR)/engines/e_aep.c $(SSL_DIR)/engines/e_atalla.c $(SSL_DIR)/engines/e_cswift.c $(SSL_DIR)/engines/e_gmp.c $(SSL_DIR)/engines/e_chil.c $(SSL_DIR)/engines/e_nuron.c $(SSL_DIR)/engines/e_sureware.c $(SSL_DIR)/engines/e_ubsec.c $(SSL_DIR)/engines/e_padlock.c $(SSL_DIR)/engines/e_capi.c $(SSL_DIR)/engines/ccgost/e_gost_err.c $(SSL_DIR)/engines/ccgost/gost2001_keyx.c $(SSL_DIR)/engines/ccgost/gost2001.c $(SSL_DIR)/engines/ccgost/gost89.c $(SSL_DIR)/engines/ccgost/gost94_keyx.c $(SSL_DIR)/engines/ccgost/gost_ameth.c $(SSL_DIR)/engines/ccgost/gost_asn1.c $(SSL_DIR)/engines/ccgost/gost_crypt.c $(SSL_DIR)/engines/ccgost/gost_ctl.c $(SSL_DIR)/engines/ccgost/gost_eng.c $(SSL_DIR)/engines/ccgost/gosthash.c $(SSL_DIR)/engines/ccgost/gost_keywrap.c $(SSL_DIR)/engines/ccgost/gost_md.c $(SSL_DIR)/engines/ccgost/gost_params.c $(SSL_DIR)/engines/ccgost/gost_pmeth.c $(SSL_DIR)/engines/ccgost/gost_sign.c

#	$(SSL_DIR)/crypto/aes/aesni-sha1-x86_64.s $(SSL_DIR)/crypto/aes/aes_misc.c $(SSL_DIR)/crypto/aes/aes_ecb.c $(SSL_DIR)/crypto/aes/aes_cfb.c $(SSL_DIR)/crypto/aes/aes_ofb.c $(SSL_DIR)/crypto/aes/aes_ctr.c $(SSL_DIR)/crypto/aes/aes_ige.c $(SSL_DIR)/crypto/aes/aes_wrap.c $(SSL_DIR)/crypto/aes/aes-x86_64.s $(SSL_DIR)/crypto/aes/bsaes-x86_64.s $(SSL_DIR)/crypto/aes/vpaes-x86_64.s $(SSL_DIR)/crypto/aes/aesni-x86_64.s $(SSL_DIR)/crypto/aes/aesni-sha1-x86_64.s

#	-I$(SSL_DIR)/crypto/evp \
#	$(SSL_DIR)/crypto/evp/e_seed.c $(SSL_DIR)/crypto/evp/evp_err.c $(SSL_DIR)/crypto/evp/encode.c $(SSL_DIR)/crypto/evp/digest.c $(SSL_DIR)/crypto/evp/evp_enc.c $(SSL_DIR)/crypto/evp/evp_key.c $(SSL_DIR)/crypto/evp/evp_acnf.c $(SSL_DIR)/crypto/evp/evp_cnf.c $(SSL_DIR)/crypto/evp/e_des.c $(SSL_DIR)/crypto/evp/e_bf.c $(SSL_DIR)/crypto/evp/e_idea.c $(SSL_DIR)/crypto/evp/e_des3.c $(SSL_DIR)/crypto/evp/e_camellia.c $(SSL_DIR)/crypto/evp/e_rc4.c $(SSL_DIR)/crypto/evp/e_aes.c $(SSL_DIR)/crypto/evp/names.c $(SSL_DIR)/crypto/evp/e_seed.c $(SSL_DIR)/crypto/evp/e_xcbc_d.c $(SSL_DIR)/crypto/evp/e_rc2.c $(SSL_DIR)/crypto/evp/e_cast.c $(SSL_DIR)/crypto/evp/e_rc5.c $(SSL_DIR)/crypto/evp/m_null.c $(SSL_DIR)/crypto/evp/m_md2.c $(SSL_DIR)/crypto/evp/m_md4.c $(SSL_DIR)/crypto/evp/m_md5.c $(SSL_DIR)/crypto/evp/m_sha.c $(SSL_DIR)/crypto/evp/m_sha1.c $(SSL_DIR)/crypto/evp/m_wp.c $(SSL_DIR)/crypto/evp/m_dss.c $(SSL_DIR)/crypto/evp/m_dss1.c $(SSL_DIR)/crypto/evp/m_mdc2.c $(SSL_DIR)/crypto/evp/m_ripemd.c $(SSL_DIR)/crypto/evp/m_ecdsa.c $(SSL_DIR)/crypto/evp/p_open.c $(SSL_DIR)/crypto/evp/p_seal.c $(SSL_DIR)/crypto/evp/p_sign.c $(SSL_DIR)/crypto/evp/p_verify.c $(SSL_DIR)/crypto/evp/evp_lib.c $(SSL_DIR)/crypto/evp/p_lib.c $(SSL_DIR)/crypto/ocsp/ocsp_lib.c $(SSL_DIR)/crypto/srp/srp_lib.c $(SSL_DIR)/crypto/evp/evp_enc.c $(SSL_DIR)/crypto/evp/p_enc.c $(SSL_DIR)/crypto/evp/p_dec.c $(SSL_DIR)/crypto/evp/bio_md.c $(SSL_DIR)/crypto/evp/bio_b64.c $(SSL_DIR)/crypto/evp/bio_enc.c $(SSL_DIR)/crypto/evp/evp_err.c $(SSL_DIR)/crypto/evp/e_null.c $(SSL_DIR)/crypto/evp/c_all.c $(SSL_DIR)/crypto/evp/c_allc.c $(SSL_DIR)/crypto/evp/c_alld.c $(SSL_DIR)/crypto/evp/evp_lib.c $(SSL_DIR)/crypto/evp/bio_ok.c $(SSL_DIR)/crypto/evp/evp_pkey.c $(SSL_DIR)/crypto/evp/evp_pbe.c $(SSL_DIR)/crypto/evp/p5_crpt.c $(SSL_DIR)/crypto/evp/p5_crpt2.c $(SSL_DIR)/crypto/evp/e_old.c $(SSL_DIR)/crypto/evp/pmeth_lib.c $(SSL_DIR)/crypto/evp/pmeth_fn.c $(SSL_DIR)/crypto/evp/pmeth_gn.c $(SSL_DIR)/crypto/evp/m_sigver.c $(SSL_DIR)/crypto/evp/evp_fips.c $(SSL_DIR)/crypto/evp/e_aes_cbc_hmac_sha1.c $(SSL_DIR)/crypto/evp/e_rc4_hmac_md5.c 

libcrypto_a_SOURCES = \
	$(libcrypto_sources)

libcrypto_a_CFLAGS = \
	-I$(SSL_DIR)/include \
	-I$(SSL_DIR)/crypto \
	-I$(SSL_DIR)/crypto/asn1 \
	-I$(SSL_DIR)/crypto/modes \
	-I$(SSL_DIR)/ \
	-I$(SSL_DIR)/ssl \
	-DOPENSSL_THREADS -D_REENTRANT -DDSO_DLFCN -DHAVE_DLFCN_H \
	-DL_ENDIAN -DTERMIO -Wall -DOPENSSL_IA32_SSE2 \
	-DOPENSSL_NO_ENGINE -DOPENSSL_NO_DH \
	-DOPENSSL_NO_WHIRLPOOL -DOPENSSL_NO_SEED -DOPENSSL_NO_EC2M \
	-DOPENSSL_NO_ASN1_OLD -DOPENSSL_NO_CMS -DOPENSSL_NO_OCSP \
	-DOPENSSL_NO_ASM

#-DMD5_ASM -DAES_ASM -DVPAES_ASM -DBSAES_ASM -DWHIRLPOOL_ASM -DGHASH_ASM
#-DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 -DOPENSSL_BN_ASM_GF2m

