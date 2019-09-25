AUTOMAKE_OPTIONS = foreign

sbin_PROGRAMS = shcoind
TESTS = test_shcoind
check_PROGRAMS = test_shcoind

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/secp256k1/include \
	-I$(top_srcdir)/src/libdi3 \
	-I$(top_srcdir)/src/libcrypto/openssl-1.0.1g/include \
	-I$(top_srcdir)/src/share-lib \
	-I$(srcdir)/proto \
	-I$(srcdir)/fractal \
	-I$(srcdir)/server \
	-I$(srcdir)/server/ext \
	-I$(srcdir)/server/blockchain \
	-I$(srcdir)/server/rpc \
	-std=c++11

blockchain_sources = \
	$(srcdir)/blockchain/bc_arch.c \
	$(srcdir)/blockchain/bc_block.c \
	$(srcdir)/blockchain/bc_fmap.c \
	$(srcdir)/blockchain/bc_index.c \
	$(srcdir)/blockchain/bc_table.c \
	$(srcdir)/blockchain/bc_mutex.c \
	$(srcdir)/blockchain/bc.h \
	$(srcdir)/blockchain/bc_arch.h \
	$(srcdir)/blockchain/bc_block.h \
	$(srcdir)/blockchain/bc_fmap.h \
	$(srcdir)/blockchain/bc_index.h \
	$(srcdir)/blockchain/bc_mutex.h \
	$(srcdir)/blockchain/bc_table.h

proto_sources = \
	$(srcdir)/proto/coin_proto.c \
	$(srcdir)/proto/shc_proto.cpp \
	$(srcdir)/proto/emc2_proto.cpp \
	$(srcdir)/proto/test_proto.cpp \
	$(srcdir)/proto/ltc_proto.cpp \
	$(srcdir)/proto/testnet_proto.cpp \
	$(srcdir)/proto/color_proto.cpp \
	$(srcdir)/proto/coin_proto.h \
	$(srcdir)/proto/shc_proto.h \
	$(srcdir)/proto/emc2_proto.h \
	$(srcdir)/proto/test_proto.h \
	$(srcdir)/proto/ltc_proto.h \
	$(srcdir)/proto/testnet_proto.h \
	$(srcdir)/proto/color_proto.h


stratum_sources = \
	stratum/stratum.h \
	stratum/stratum_http.h \
	stratum/stratum_message.h \
	stratum/stratum_protocol.h \
	stratum/stratum_command.h \
	stratum/stratum_user.h \
	stratum/stratum_task.h \
	stratum/stratum_sync.h \
	stratum/stratum_api.h \
	stratum/stratum_miner.h \
	stratum/stratum_sha256d.h \
	stratum/stratum_keccak.h \
	stratum/stratum_x11.h \
	stratum/stratum_blake2s.h \
	stratum/stratum_qubit.h \
	stratum/stratum_groestl.h \
	stratum/stratum_skein.h \
	stratum/http/http.h \
	stratum/stratum.c \
	stratum/stratum_http.c \
	stratum/stratum_message.c \
	stratum/stratum_protocol.c \
	stratum/stratum_command.c \
	stratum/stratum_user.c \
	stratum/stratum_task.c \
	stratum/stratum_sync.c \
	stratum/stratum_api.cpp \
	stratum/stratum_api_faucet.cpp \
	stratum/stratum_miner.cpp \
	stratum/stratum_sha256d.c \
	stratum/stratum_keccak.c \
	stratum/stratum_x11.c \
	stratum/stratum_blake2s.c \
	stratum/stratum_qubit.c \
	stratum/stratum_groestl.c \
	stratum/stratum_skein.c \
	stratum/http/http.c \
	stratum/http/http_alias.c \
	stratum/http/http_coin.c \
	stratum/http/http_context.c \
	stratum/http/http_fractal.c \
	stratum/http/http_matrix.c \
	stratum/http/http_pool.c


#bn_sources = \
#	server/bn/bn_add.c \
#	server/bn/bn_asm.c \
#	server/bn/bn_blind.c \
#	server/bn/bn_const.c \
#	server/bn/bn_ctx.c \
#	server/bn/bn_depr.c \
#	server/bn/bn_div.c \
#	server/bn/bn_err.c \
#	server/bn/bn_exp2.c \
#	server/bn/bn_exp.c \
#	server/bn/bn_gcd.c \
#	server/bn/bn_gf2m.c \
#	server/bn/bn_kron.c \
#	server/bn/bn_lcl.h \
#	server/bn/bn_lib.c \
#	server/bn/bn_mod.c \
#	server/bn/bn_mpi.c \
#	server/bn/bn_mul.c \
#	server/bn/bn_prime.c \
#	server/bn/bn_prime.h \
#	server/bn/bn_print.c \
#	server/bn/bn_rand.c \
#	server/bn/bn_recp.c \
#	server/bn/bn_shift.c \
#	server/bn/bn_sqr.c \
#	server/bn/bn_sqrt.c \
#	server/bn/bn_word.c

common_includes = \
	$(top_builddir)/config.h \
	$(top_srcdir)/src/share-lib/share.h \
	$(top_srcdir)/src/share-lib/mem/shmem.h \
	$(top_srcdir)/src/share-lib/sherr.h \
	$(top_srcdir)/src/share-lib/share_base.h \
	$(top_srcdir)/src/share-lib/shpeer.h \
	$(top_srcdir)/src/share-lib/shtime.h \
	$(top_srcdir)/src/share-lib/shpref.h \
	$(top_srcdir)/src/share-lib/shcrc.h \
	$(top_srcdir)/src/share-lib/shfile.h \
	$(top_srcdir)/src/share-lib/fs/shfs.h \
	$(top_srcdir)/src/share-lib/delta/xdelta3.h \
	$(top_srcdir)/src/share-lib/net/shnet.h \
	unet/unet.h \
	server/bech32.h \
	server/coin.h \
	server/validation.h \
	server/chain.h \
	server/global.h \
	server/allocators.h \
	server/bignum.h \
	server/rpcalias_proto.h \
	server/rpccert_proto.h \
	server/rpccontext_proto.h \
	server/rpcexec_proto.h \
	server/rpcoffer_proto.h \
	server/compat.h \
	server/txidx.h \
	server/key.h \
	server/eckey.h \
	server/dikey.h \
	server/keystore.h \
	server/mruset.h \
	server/netbase.h \
	server/net.h \
	server/txsignature.h \
	server/versionbits.h \
	server/algobits.h \
	server/protocol.h \
	server/script.h \
	server/algo/blake2.h \
	server/algo/blake2s.h \
	server/algo/keccak.h \
	server/algo/qubit.h \
	server/algo/scrypt.h \
	server/algo/sha512.h \
	server/algo/hmac_sha512.h \
	server/algo/sph_blake.h \
	server/algo/sph_bmw.h \
	server/algo/sph_cubehash.h \
	server/algo/sph_echo.h \
	server/algo/sph_groestl.h \
	server/algo/sph_jh.h \
	server/algo/sph_keccak.h \
	server/algo/sph_luffa.h \
	server/algo/sph_shavite.h \
	server/algo/sph_simd.h \
	server/algo/sph_skein.h \
	server/algo/sph_types.h \
	server/algo/x11.h \
	server/serialize.h \
	server/strlcpy.h \
	server/sync.h \
	server/ui_interface.h \
	server/uint256.h \
	server/util.h \
	server/version.h \
	server/walletdb.h \
	server/wallet.h \
	server/account.h \
	server/txcreator.h \
	shcoind_version.h \
	server_iface.h \
	shcoind_rpc.h \
	shcoind_error.h \
	shcoind_log.h \
	shcoind_opt.h \
	shcoind_signal.h \
	shcoind_descriptor.h \
	shcoind.h

common_sources = \
	shcoind_rpc.c \
	shcoind_error.c \
	shcoind_log.c \
	shcoind_opt.c \
	shcoind_signal.c \
	shcoind_descriptor.c \
	unet/unet_accept.c \
	unet/unet_bind.c \
	unet/unet_thread.c \
	unet/unet.c \
	unet/unet_close.c \
	unet/unet_connect.c \
	unet/unet.h \
	unet/unet_io.c \
	unet/unet_timer.c \
	unet/unet_peerdb.c \
	unet/unet_event.c \
	unet/unet_local.c \
	server/mnemonic.cpp \
	server/netbase.cpp \
	server/version.cpp \
	server/util.cpp

testnet_sources = \
	server/testnet/testnet_netmsg.cpp \
	server/testnet/testnet_netmsg.h \
	server/testnet/testnet_block.cpp \
	server/testnet/testnet_block.h \
	server/testnet/testnet_wallet.cpp \
	server/testnet/testnet_wallet.h \
	server/testnet/testnet_txidx.cpp \
	server/testnet/testnet_txidx.h \
	server/testnet/testnet_pool.cpp \
	server/testnet/testnet_pool.h

# emc2 emulation service
emc2_sources = \
	server/emc2/emc2_txidx.cpp \
	server/emc2/emc2_txidx.h \
	server/emc2/emc2_block.cpp \
	server/emc2/emc2_block.h \
	server/emc2/emc2_wallet.cpp \
	server/emc2/emc2_wallet.h \
	server/emc2/emc2_netmsg.cpp \
	server/emc2/emc2_netmsg.h \
	server/emc2/emc2_pool.cpp \
	server/emc2/emc2_pool.h

server_sources = \
	$(blockchain_sources) \
	$(proto_sources) \
	server/txfeerate.cpp \
	fractal/fractal.c \
	fractal/fractal_bmp.c \
	server/bolo/bolo_validation03.cpp \
	server/bolo/bolo_validation03.h \
	server/test/test_wallet.cpp \
	server/test/test_wallet.h \
	server/test/test_block.cpp \
	server/test/test_block.h \
	server/test/test_pool.cpp \
	server/test/test_pool.h \
	server/test/test_pool.h \
	server/shc/shc_netmsg.cpp \
	server/shc/shc_netmsg.h \
	server/shc/shc_block.cpp \
	server/shc/shc_block.h \
	server/shc/shc_wallet.cpp \
	server/shc/shc_wallet.h \
	server/shc/shc_txidx.cpp \
	server/shc/shc_txidx.h \
	server/shc/shc_rpc.cpp \
	server/shc/shc_pool.cpp \
	server/shc/shc_pool.h \
	server/ltc/ltc_netmsg.cpp \
	server/ltc/ltc_netmsg.h \
	server/ltc/ltc_block.cpp \
	server/ltc/ltc_block.h \
	server/ltc/ltc_wallet.cpp \
	server/ltc/ltc_wallet.h \
	server/ltc/ltc_txidx.cpp \
	server/ltc/ltc_txidx.h \
	server/ltc/ltc_pool.cpp \
	server/ltc/ltc_pool.h \
	server/color/color_block.cpp \
	server/color/color_block.h \
	server/color/color_wallet.cpp \
	server/color/color_wallet.h \
	server/color/color_txidx.cpp \
	server/color/color_txidx.h \
	server/color/color_pool.cpp \
	server/color/color_pool.h \
	server/color/color_rpc.cpp \
	server/ext/txext.cpp \
	server/ext/txext.h \
	server/ext/ext_param.cpp \
	server/ext/ext_param.h \
	server/ext/alias.cpp \
	server/ext/alias.h \
	server/ext/certificate.cpp \
	server/ext/certificate.h \
	server/ext/offer.cpp \
	server/ext/offer.h \
	server/ext/asset.cpp \
	server/ext/asset.h \
	server/ext/exec.cpp \
	server/ext/exec.h \
	server/ext/context.cpp \
	server/ext/context.h \
	server/ext/altchain.cpp \
	server/ext/altchain.h \
	server/ext/altchain_color.c \
	server/ext/altchain_color.h \
	server/rpc/rpcalias_proto.cpp \
	server/rpc/rpccert_proto.cpp \
	server/rpc/rpccolor_proto.cpp \
	server/rpc/rpccontext_proto.cpp \
	server/rpc/rpcexec_proto.cpp \
	server/rpc/rpcoffer_proto.cpp \
	server/rpc/rpcdump.cpp \
	server/rpc/rpc_command.cpp \
	server/rpc/rpc_parse.cpp \
	server/rpc/rpc_wallet.cpp \
	server/rpc/rpc_wallet_addr.cpp \
	server/rpc/rpcrawtransaction.cpp \
	server/versionbits.cpp \
	server/algobits.cpp \
	server/txsignature.cpp \
	server/protocol.cpp \
	server/block.cpp \
	server/block.h \
	server/checkpoints.cpp \
	server/checkpoints.h \
	server/txmempool.cpp \
	server/txmempool.h \
	server/bech32.cpp \
	server/coin.cpp \
	server/validation.cpp \
	server/chain.cpp \
	server/matrix.cpp \
	server/spring.c \
	server/bloom.cpp \
	server/global.cpp \
	server/block_merkle.cpp \
	server/wit_merkle.cpp \
	server/sha256d_merkle.cpp \
	server/txidx.cpp \
	server/init.cpp \
	server/eckey.cpp \
	server/dikey.cpp \
	server/keystore.cpp \
	server/main.cpp \
	server/script.cpp \
	server/sync.cpp \
	server/walletdb.cpp \
	server/wallet.cpp \
	server/wallettx.cpp \
	server/account.cpp \
	server/txcreator.cpp \
	server/algo/blake2.c \
	server/algo/blake2s.c \
	server/algo/groestl.c \
	server/algo/keccak.c \
	server/algo/qubit.c \
	server/algo/scrypt.c \
	server/algo/sha512.cpp \
	server/algo/hmac_sha512.cpp \
	server/algo/skein.c \
	server/algo/sph_blake.c \
	server/algo/sph_bmw.c \
	server/algo/sph_cubehash.c \
	server/algo/sph_echo.c \
	server/algo/sph_groestl.c \
	server/algo/sph_jh.c \
	server/algo/sph_keccak.c \
	server/algo/sph_luffa.c \
	server/algo/sph_shavite.c \
	server/algo/sph_simd.c \
	server/algo/sph_skein.c \
	server/algo/x11.c \
	server/addrman.h \
	server/addrman.cpp \
	server/base58.h \
	server/base58.cpp \
	server/coinaddr.h \
	server/coinaddr.cpp \
	wallet_iface.cpp \
	block_iface.cpp \
	server_iface.cpp

if STRATUM_SERVICE
server_sources += $(stratum_sources)
endif

if EMC2_SERVICE
server_sources += $(emc2_sources)
endif

if TESTNET_SERVICE
server_sources += $(testnet_sources)
endif

shcoind_SOURCES = \
	$(common_includes) $(common_sources) \
	$(server_sources) \
	shcoind.c \
	shcoind_daemon.c \
	shcoind_daemon.h
if WINDOWS
shcoind_SOURCES += \
	shcoind_svc.c \
	shcoind_svc.h
endif

shcoind_LDADD = \
	$(top_builddir)/src/secp256k1/libsecp256k1.a \
	$(top_builddir)/src/libcrypto/libcrypto.a \
	$(top_builddir)/src/libdi3/libdi3.a
if STATIC_LIBSHARE
shcoind_LDADD += \
	$(LIBSHARE)/src/share-lib/libshare.a \
	$(LIBSHARE)/src/sexe/libshare_sexe.a
shcoind_CFLAGS = -I$(LIBSHARE)/include -I$(LIBSHARE)/../src/sexe

shcoind_CXXFLAGS = -I$(LIBSHARE)/include -I$(LIBSHARE)/../src/sexe
else
shcoind_LDADD += -lshare -lshare_sexe
endif
shcoind_LDADD += -lboost_system -lboost_filesystem -lboost_thread -ldb_cxx -lpthread -ldl



test_shcoind_SOURCES = \
	$(common_includes) $(common_sources) \
	$(server_sources) \
	test/CuTest.c \
	test/CuTest.h \
	test/test_shcoind.c \
	test/test_shcoind.h \
	test/test_init.cpp \
	test/testcoin_key.cpp \
	test/testcoin_coin.cpp \
	test/testcoin_bignum.cpp \
	test/testcoin_hash.cpp \
	test/testcoin_block.cpp \
	test/testcoin_json.cpp \
	test/testcoin_bloom.cpp \
	test/testcoin_algo.cpp \
	test/testcoin_account.cpp \
	test/testcoin_bip32.cpp \
	test/testcoin_sip5.cpp \
	test/testcoin_sip6.cpp \
	test/testcoin_sip10.cpp \
	test/testcoin_sip25.cpp \
	test/testcoin_sip33.cpp

test_shcoind_LDADD = \
	$(top_builddir)/src/secp256k1/libsecp256k1.a \
	$(top_builddir)/src/libcrypto/libcrypto.a \
	$(top_builddir)/src/libdi3/libdi3.a
test_shcoind_CFLAGS = -g -O0 -DTEST_SHCOIND
test_shcoind_CXXFLAGS = -g -O0 -DTEST_SHCOIND
if STATIC_LIBSHARE
test_shcoind_LDADD += \
	$(LIBSHARE)/src/share-lib/libshare.a \
	$(LIBSHARE)/src/sexe/libshare_sexe.a
test_shcoind_CFLAGS += -I$(LIBSHARE)/include -I$(LIBSHARE)/../src/sexe
test_shcoind_CXXFLAGS += -I$(LIBSHARE)/include -I$(LIBSHARE)/../src/sexe
else
test_shcoind_LDADD += -lshare -lshare_sexe
endif
test_shcoind_LDADD += -lboost_system -lboost_filesystem -lboost_thread -ldb_cxx -lpthread -ldl



if HAVE_SYSTEMCTL
SYSD_FILE = /lib/systemd/system/shcoind.service

install-exec-hook:
	mkdir -p /lib/systemd/system/
	rm -f /etc/systemd/system/shcoind.service
	echo "[Unit]" > $(SYSD_FILE) 
	echo "Description=ShionCoin" >> $(SYSD_FILE) 
	echo "Wants=network.target" >> $(SYSD_FILE) 
	echo "After=network.target" >> $(SYSD_FILE) 
	echo "[Service]" >> $(SYSD_FILE) 
	echo "ExecStart=$(sbindir)/shcoind -nf" >> $(SYSD_FILE)
	echo "[Install]" >> $(SYSD_FILE) 
	echo "WantedBy=sysinit.target" >> $(SYSD_FILE) 
	echo "Alias=shcoind.service" >> $(SYSD_FILE) 
	systemctl daemon-reload 
	systemctl enable shcoind

uninstall-hook:
	rm -f $(SYSD_FILE) /etc/systemd/system/shcoind.service
	systemctl daemon-reload 
endif

if DEBUG
CFLAGS += -g3 
CXXFLAGS += -g3 -Wno-write-strings
else
CFLAGS += -O2
CXXFLAGS += -O2 -Wno-write-strings
endif


