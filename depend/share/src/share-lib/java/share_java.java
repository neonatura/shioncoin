/* ----------------------------------------------------------------------------
 * This file was automatically generated by SWIG (http://www.swig.org).
 * Version 2.0.10
 *
 * Do not make changes to this file unless you know what you are doing--modify
 * the SWIG interface file instead.
 * ----------------------------------------------------------------------------- */

package net.sharelib;

public class share_java {
  public static int test_main() {
    return share_javaJNI.test_main();
  }

  public static String get_libshare_version() {
    return share_javaJNI.get_libshare_version();
  }

  public static String get_libshare_title() {
    return share_javaJNI.get_libshare_title();
  }

  public static String get_libshare_path() {
    return share_javaJNI.get_libshare_path();
  }

  public static SWIGTYPE_p_shpeer_t shpeer() {
    long cPtr = share_javaJNI.shpeer();
    return (cPtr == 0) ? null : new SWIGTYPE_p_shpeer_t(cPtr, false);
  }

  public static SWIGTYPE_p_shpeer_t ashpeer() {
    long cPtr = share_javaJNI.ashpeer();
    return (cPtr == 0) ? null : new SWIGTYPE_p_shpeer_t(cPtr, false);
  }

  public static void shpeer_free(SWIGTYPE_p_p_shpeer_t peer_p) {
    share_javaJNI.shpeer_free(SWIGTYPE_p_p_shpeer_t.getCPtr(peer_p));
  }

  public static void shpref_free() {
    share_javaJNI.shpref_free();
  }

  public static String shpref_get(String pref, String default_value) {
    return share_javaJNI.shpref_get(pref, default_value);
  }

  public static int shpref_set(String pref, String value) {
    return share_javaJNI.shpref_set(pref, value);
  }

  public static double shtimef(java.math.BigInteger stamp) {
    return share_javaJNI.shtimef(stamp);
  }

  public static java.math.BigInteger shtime() {
    return share_javaJNI.shtime();
  }

  public static java.math.BigInteger shtimeu(long unix_t) {
    return share_javaJNI.shtimeu(unix_t);
  }

  public static int shtimems(java.math.BigInteger t) {
    return share_javaJNI.shtimems(t);
  }

  public static String shctime(java.math.BigInteger t) {
    return share_javaJNI.shctime(t);
  }

  public static long shutime(java.math.BigInteger t) {
    return share_javaJNI.shutime(t);
  }

  public static String shstrtime(java.math.BigInteger t, String fmt) {
    return share_javaJNI.shstrtime(t, fmt);
  }

  public static java.math.BigInteger shtime_adj(java.math.BigInteger stamp, double secs) {
    return share_javaJNI.shtime_adj(stamp, secs);
  }

  public static java.math.BigInteger shgettime(SWIGTYPE_p_timeval tv) {
    return share_javaJNI.shgettime(SWIGTYPE_p_timeval.getCPtr(tv));
  }

  public static int shtime_after(java.math.BigInteger stamp, java.math.BigInteger cmp_stamp) {
    return share_javaJNI.shtime_after(stamp, cmp_stamp);
  }

  public static int shtime_before(java.math.BigInteger stamp, java.math.BigInteger cmp_stamp) {
    return share_javaJNI.shtime_before(stamp, cmp_stamp);
  }

  public static double shtime_diff(java.math.BigInteger stamp, java.math.BigInteger cmp_stamp) {
    return share_javaJNI.shtime_diff(stamp, cmp_stamp);
  }

  public static void shbuf_append(SWIGTYPE_p_shbuf_t from_buff, SWIGTYPE_p_shbuf_t to_buff) {
    share_javaJNI.shbuf_append(SWIGTYPE_p_shbuf_t.getCPtr(from_buff), SWIGTYPE_p_shbuf_t.getCPtr(to_buff));
  }

  public static SWIGTYPE_p_shbuf_t shbuf_clone(SWIGTYPE_p_shbuf_t buff) {
    long cPtr = share_javaJNI.shbuf_clone(SWIGTYPE_p_shbuf_t.getCPtr(buff));
    return (cPtr == 0) ? null : new SWIGTYPE_p_shbuf_t(cPtr, false);
  }

  public static void shbuf_memcpy(SWIGTYPE_p_shbuf_t buf, byte[] data) {
    share_javaJNI.shbuf_memcpy(SWIGTYPE_p_shbuf_t.getCPtr(buf), data);
  }

  public static SWIGTYPE_p_shbuf_t shbuf_init() {
    long cPtr = share_javaJNI.shbuf_init();
    return (cPtr == 0) ? null : new SWIGTYPE_p_shbuf_t(cPtr, false);
  }

  public static void shbuf_catstr(SWIGTYPE_p_shbuf_t buf, String data) {
    share_javaJNI.shbuf_catstr(SWIGTYPE_p_shbuf_t.getCPtr(buf), data);
  }

  public static void shbuf_cat(SWIGTYPE_p_shbuf_t buf, byte[] data) {
    share_javaJNI.shbuf_cat(SWIGTYPE_p_shbuf_t.getCPtr(buf), data);
  }

  public static long shbuf_size(SWIGTYPE_p_shbuf_t buf) {
    return share_javaJNI.shbuf_size(SWIGTYPE_p_shbuf_t.getCPtr(buf));
  }

  public static SWIGTYPE_p_unsigned_char shbuf_data(SWIGTYPE_p_shbuf_t buf) {
    long cPtr = share_javaJNI.shbuf_data(SWIGTYPE_p_shbuf_t.getCPtr(buf));
    return (cPtr == 0) ? null : new SWIGTYPE_p_unsigned_char(cPtr, false);
  }

  public static void shbuf_clear(SWIGTYPE_p_shbuf_t buf) {
    share_javaJNI.shbuf_clear(SWIGTYPE_p_shbuf_t.getCPtr(buf));
  }

  public static void shbuf_trim(SWIGTYPE_p_shbuf_t buf, long len) {
    share_javaJNI.shbuf_trim(SWIGTYPE_p_shbuf_t.getCPtr(buf), len);
  }

  public static void shbuf_dealloc(SWIGTYPE_p_shbuf_t buf) {
    share_javaJNI.shbuf_dealloc(SWIGTYPE_p_shbuf_t.getCPtr(buf));
  }

  public static void shbuf_truncate(SWIGTYPE_p_shbuf_t buf, long len) {
    share_javaJNI.shbuf_truncate(SWIGTYPE_p_shbuf_t.getCPtr(buf), len);
  }

  public static java.math.BigInteger shcrc(byte[] data) {
    return share_javaJNI.shcrc(data);
  }

  public static String shcrcstr(java.math.BigInteger crc) {
    return share_javaJNI.shcrcstr(crc);
  }

  public static java.math.BigInteger shcrcgen(String str) {
    return share_javaJNI.shcrcgen(str);
  }

  public static int shmsgget(SWIGTYPE_p_shpeer_t peer) {
    return share_javaJNI.shmsgget(SWIGTYPE_p_shpeer_t.getCPtr(peer));
  }

  public static int shmsgsnd(int msqid, SWIGTYPE_p_void msgp, long msgsz) {
    return share_javaJNI.shmsgsnd(msqid, SWIGTYPE_p_void.getCPtr(msgp), msgsz);
  }

  public static int shmsgrcv(int msqid, SWIGTYPE_p_void msgp, long msgsz) {
    return share_javaJNI.shmsgrcv(msqid, SWIGTYPE_p_void.getCPtr(msgp), msgsz);
  }

  public static int shmsgctl(int msg_qid, int cmd, int value) {
    return share_javaJNI.shmsgctl(msg_qid, cmd, value);
  }

  public static String shfs_app_name(String app_name) {
    return share_javaJNI.shfs_app_name(app_name);
  }

  public static java.math.BigInteger shfs_crc(SWIGTYPE_p_shfs_ino_t file) {
    return share_javaJNI.shfs_crc(SWIGTYPE_p_shfs_ino_t.getCPtr(file));
  }

  public static SWIGTYPE_p_shsize_t shfs_size(SWIGTYPE_p_shfs_ino_t file) {
    return new SWIGTYPE_p_shsize_t(share_javaJNI.shfs_size(SWIGTYPE_p_shfs_ino_t.getCPtr(file)), true);
  }

  public static SWIGTYPE_p_shfs_t shfs_init(SWIGTYPE_p_shpeer_t peer) {
    long cPtr = share_javaJNI.shfs_init(SWIGTYPE_p_shpeer_t.getCPtr(peer));
    return (cPtr == 0) ? null : new SWIGTYPE_p_shfs_t(cPtr, false);
  }

  public static void shfs_free(SWIGTYPE_p_p_shfs_t tree_p) {
    share_javaJNI.shfs_free(SWIGTYPE_p_p_shfs_t.getCPtr(tree_p));
  }

  public static SWIGTYPE_p_shfs_ino_t shfs_dir_base(SWIGTYPE_p_shfs_t tree) {
    long cPtr = share_javaJNI.shfs_dir_base(SWIGTYPE_p_shfs_t.getCPtr(tree));
    return (cPtr == 0) ? null : new SWIGTYPE_p_shfs_ino_t(cPtr, false);
  }

  public static SWIGTYPE_p_shfs_ino_t shfs_dir_parent(SWIGTYPE_p_shfs_ino_t inode) {
    long cPtr = share_javaJNI.shfs_dir_parent(SWIGTYPE_p_shfs_ino_t.getCPtr(inode));
    return (cPtr == 0) ? null : new SWIGTYPE_p_shfs_ino_t(cPtr, false);
  }

  public static SWIGTYPE_p_shfs_ino_t shfs_dir_entry(SWIGTYPE_p_shfs_ino_t inode, String fname) {
    long cPtr = share_javaJNI.shfs_dir_entry(SWIGTYPE_p_shfs_ino_t.getCPtr(inode), fname);
    return (cPtr == 0) ? null : new SWIGTYPE_p_shfs_ino_t(cPtr, false);
  }

  public static SWIGTYPE_p_shfs_ino_t shfs_dir_find(SWIGTYPE_p_shfs_t tree, String path) {
    long cPtr = share_javaJNI.shfs_dir_find(SWIGTYPE_p_shfs_t.getCPtr(tree), path);
    return (cPtr == 0) ? null : new SWIGTYPE_p_shfs_ino_t(cPtr, false);
  }

  public static String shfs_meta_get(SWIGTYPE_p_shfs_ino_t file, String def) {
    return share_javaJNI.shfs_meta_get(SWIGTYPE_p_shfs_ino_t.getCPtr(file), def);
  }

  public static int shfs_meta_perm(SWIGTYPE_p_shfs_ino_t file, String def, SWIGTYPE_p_shkey_t user) {
    return share_javaJNI.shfs_meta_perm(SWIGTYPE_p_shfs_ino_t.getCPtr(file), def, SWIGTYPE_p_shkey_t.getCPtr(user));
  }

  public static int shfs_meta_set(SWIGTYPE_p_shfs_ino_t file, String def, String value) {
    return share_javaJNI.shfs_meta_set(SWIGTYPE_p_shfs_ino_t.getCPtr(file), def, value);
  }

  public static int shfs_read_mem(String path, SWIGTYPE_p_p_char data_p, SWIGTYPE_p_size_t data_len_p) {
    return share_javaJNI.shfs_read_mem(path, SWIGTYPE_p_p_char.getCPtr(data_p), SWIGTYPE_p_size_t.getCPtr(data_len_p));
  }

  public static int shfs_write_mem(String path, byte[] data) {
    return share_javaJNI.shfs_write_mem(path, data);
  }

  public static SWIGTYPE_p_shfs_ino_t shfs_file_find(SWIGTYPE_p_shfs_t tree, String path) {
    long cPtr = share_javaJNI.shfs_file_find(SWIGTYPE_p_shfs_t.getCPtr(tree), path);
    return (cPtr == 0) ? null : new SWIGTYPE_p_shfs_ino_t(cPtr, false);
  }

  public static int shfs_file_pipe(SWIGTYPE_p_shfs_ino_t file, int fd) {
    return share_javaJNI.shfs_file_pipe(SWIGTYPE_p_shfs_ino_t.getCPtr(file), fd);
  }

  public static void sherr(int err_code, String log_str) {
    share_javaJNI.sherr(err_code, log_str);
  }

  public static void shwarn(String log_str) {
    share_javaJNI.shwarn(log_str);
  }

  public static void shinfo(String log_str) {
    share_javaJNI.shinfo(log_str);
  }

  public static int shnet_accept(int sockfd) {
    return share_javaJNI.shnet_accept(sockfd);
  }

  public static int shnet_bindsk(int sockfd, String hostname, long port) {
    return share_javaJNI.shnet_bindsk(sockfd, hostname, port);
  }

  public static int shnet_bind(int sockfd, SWIGTYPE_p_sockaddr addr, SWIGTYPE_p_socklen_t addrlen) {
    return share_javaJNI.shnet_bind(sockfd, SWIGTYPE_p_sockaddr.getCPtr(addr), SWIGTYPE_p_socklen_t.getCPtr(addrlen));
  }

  public static int shclose(int sk) {
    return share_javaJNI.shclose(sk);
  }

  public static int shnet_fcntl(int fd, int cmd, int arg) {
    return share_javaJNI.shnet_fcntl(fd, cmd, arg);
  }

  public static int shconnect_host(String host, int port, int flags) {
    return share_javaJNI.shconnect_host(host, port, flags);
  }

  public static SWIGTYPE_p_hostent shresolve(String hostname) {
    long cPtr = share_javaJNI.shresolve(hostname);
    return (cPtr == 0) ? null : new SWIGTYPE_p_hostent(cPtr, false);
  }

  public static SWIGTYPE_p_sockaddr shaddr(int sockfd) {
    long cPtr = share_javaJNI.shaddr(sockfd);
    return (cPtr == 0) ? null : new SWIGTYPE_p_sockaddr(cPtr, false);
  }

  public static String shaddr_print(SWIGTYPE_p_sockaddr addr) {
    return share_javaJNI.shaddr_print(SWIGTYPE_p_sockaddr.getCPtr(addr));
  }

  public static SWIGTYPE_p_ssize_t shnet_read(int fd, SWIGTYPE_p_void buf, long count) {
    return new SWIGTYPE_p_ssize_t(share_javaJNI.shnet_read(fd, SWIGTYPE_p_void.getCPtr(buf), count), true);
  }

  public static int shnet_sk() {
    return share_javaJNI.shnet_sk();
  }

  public static int shnet_socket(int domain, int type, int protocol) {
    return share_javaJNI.shnet_socket(domain, type, protocol);
  }

  public static SWIGTYPE_p_ssize_t shnet_write(int fd, SWIGTYPE_p_void buf, long count) {
    return new SWIGTYPE_p_ssize_t(share_javaJNI.shnet_write(fd, SWIGTYPE_p_void.getCPtr(buf), count), true);
  }

  public static int shnet_verify(SWIGTYPE_p_fd_set readfds, SWIGTYPE_p_fd_set writefds, SWIGTYPE_p_long millis) {
    return share_javaJNI.shnet_verify(SWIGTYPE_p_fd_set.getCPtr(readfds), SWIGTYPE_p_fd_set.getCPtr(writefds), SWIGTYPE_p_long.getCPtr(millis));
  }

  public static SWIGTYPE_p_shkey_t shkey_bin(String data, long data_len) {
    long cPtr = share_javaJNI.shkey_bin(data, data_len);
    return (cPtr == 0) ? null : new SWIGTYPE_p_shkey_t(cPtr, false);
  }

  public static SWIGTYPE_p_shkey_t shkey_str(String kvalue) {
    long cPtr = share_javaJNI.shkey_str(kvalue);
    return (cPtr == 0) ? null : new SWIGTYPE_p_shkey_t(cPtr, false);
  }

  public static SWIGTYPE_p_shkey_t shkey_num(int kvalue) {
    long cPtr = share_javaJNI.shkey_num(kvalue);
    return (cPtr == 0) ? null : new SWIGTYPE_p_shkey_t(cPtr, false);
  }

  public static SWIGTYPE_p_shkey_t shkey_uniq() {
    long cPtr = share_javaJNI.shkey_uniq();
    return (cPtr == 0) ? null : new SWIGTYPE_p_shkey_t(cPtr, false);
  }

  public static void shkey_free(SWIGTYPE_p_p_shkey_t key_p) {
    share_javaJNI.shkey_free(SWIGTYPE_p_p_shkey_t.getCPtr(key_p));
  }

  public static String shkey_print(SWIGTYPE_p_shkey_t key) {
    return share_javaJNI.shkey_print(SWIGTYPE_p_shkey_t.getCPtr(key));
  }

  public static SWIGTYPE_p_shkey_t ashkey_str(String name) {
    long cPtr = share_javaJNI.ashkey_str(name);
    return (cPtr == 0) ? null : new SWIGTYPE_p_shkey_t(cPtr, false);
  }

  public static SWIGTYPE_p_shkey_t ashkey_num(int num) {
    long cPtr = share_javaJNI.ashkey_num(num);
    return (cPtr == 0) ? null : new SWIGTYPE_p_shkey_t(cPtr, false);
  }

  public static int shkey_cmp(SWIGTYPE_p_shkey_t key_1, SWIGTYPE_p_shkey_t key_2) {
    return share_javaJNI.shkey_cmp(SWIGTYPE_p_shkey_t.getCPtr(key_1), SWIGTYPE_p_shkey_t.getCPtr(key_2));
  }

  public static SWIGTYPE_p_shkey_t shkey_clone(SWIGTYPE_p_shkey_t key) {
    long cPtr = share_javaJNI.shkey_clone(SWIGTYPE_p_shkey_t.getCPtr(key));
    return (cPtr == 0) ? null : new SWIGTYPE_p_shkey_t(cPtr, false);
  }

  public static SWIGTYPE_p_shkey_t shkey_cert(SWIGTYPE_p_shkey_t key, java.math.BigInteger crc, java.math.BigInteger stamp) {
    long cPtr = share_javaJNI.shkey_cert(SWIGTYPE_p_shkey_t.getCPtr(key), crc, stamp);
    return (cPtr == 0) ? null : new SWIGTYPE_p_shkey_t(cPtr, false);
  }

  public static int shkey_verify(SWIGTYPE_p_shkey_t sig, java.math.BigInteger crc, SWIGTYPE_p_shkey_t key, java.math.BigInteger stamp) {
    return share_javaJNI.shkey_verify(SWIGTYPE_p_shkey_t.getCPtr(sig), crc, SWIGTYPE_p_shkey_t.getCPtr(key), stamp);
  }

  public static SWIGTYPE_p_shkey_t shkey_gen(String hex_str) {
    long cPtr = share_javaJNI.shkey_gen(hex_str);
    return (cPtr == 0) ? null : new SWIGTYPE_p_shkey_t(cPtr, false);
  }

  public static SWIGTYPE_p_shpool_t shpool_init() {
    long cPtr = share_javaJNI.shpool_init();
    return (cPtr == 0) ? null : new SWIGTYPE_p_shpool_t(cPtr, false);
  }

  public static long shpool_size(SWIGTYPE_p_shpool_t pool) {
    return share_javaJNI.shpool_size(SWIGTYPE_p_shpool_t.getCPtr(pool));
  }

  public static void shpool_grow(SWIGTYPE_p_shpool_t pool) {
    share_javaJNI.shpool_grow(SWIGTYPE_p_shpool_t.getCPtr(pool));
  }

  public static SWIGTYPE_p_shbuf_t shpool_get(SWIGTYPE_p_shpool_t pool, SWIGTYPE_p_unsigned_int idx_p) {
    long cPtr = share_javaJNI.shpool_get(SWIGTYPE_p_shpool_t.getCPtr(pool), SWIGTYPE_p_unsigned_int.getCPtr(idx_p));
    return (cPtr == 0) ? null : new SWIGTYPE_p_shbuf_t(cPtr, false);
  }

  public static SWIGTYPE_p_shbuf_t shpool_get_index(SWIGTYPE_p_shpool_t pool, int index) {
    long cPtr = share_javaJNI.shpool_get_index(SWIGTYPE_p_shpool_t.getCPtr(pool), index);
    return (cPtr == 0) ? null : new SWIGTYPE_p_shbuf_t(cPtr, false);
  }

  public static void shpool_put(SWIGTYPE_p_shpool_t pool, SWIGTYPE_p_shbuf_t buff) {
    share_javaJNI.shpool_put(SWIGTYPE_p_shpool_t.getCPtr(pool), SWIGTYPE_p_shbuf_t.getCPtr(buff));
  }

  public static void shpool_free(SWIGTYPE_p_p_shpool_t pool_p) {
    share_javaJNI.shpool_free(SWIGTYPE_p_p_shpool_t.getCPtr(pool_p));
  }

  public static int ashencode(String data, SWIGTYPE_p_size_t data_len_p, SWIGTYPE_p_shkey_t key) {
    return share_javaJNI.ashencode(data, SWIGTYPE_p_size_t.getCPtr(data_len_p), SWIGTYPE_p_shkey_t.getCPtr(key));
  }

  public static int shencode(String data, long data_len, SWIGTYPE_p_p_unsigned_char data_p, SWIGTYPE_p_size_t data_len_p, SWIGTYPE_p_shkey_t key) {
    return share_javaJNI.shencode(data, data_len, SWIGTYPE_p_p_unsigned_char.getCPtr(data_p), SWIGTYPE_p_size_t.getCPtr(data_len_p), SWIGTYPE_p_shkey_t.getCPtr(key));
  }

  public static SWIGTYPE_p_shkey_t shencode_str(String data) {
    long cPtr = share_javaJNI.shencode_str(data);
    return (cPtr == 0) ? null : new SWIGTYPE_p_shkey_t(cPtr, false);
  }

  public static int ashdecode(SWIGTYPE_p_unsigned_char data, SWIGTYPE_p_size_t data_len_p, SWIGTYPE_p_shkey_t key) {
    return share_javaJNI.ashdecode(SWIGTYPE_p_unsigned_char.getCPtr(data), SWIGTYPE_p_size_t.getCPtr(data_len_p), SWIGTYPE_p_shkey_t.getCPtr(key));
  }

  public static int shdecode(SWIGTYPE_p_unsigned_char data, long data_len, SWIGTYPE_p_p_char data_p, SWIGTYPE_p_size_t data_len_p, SWIGTYPE_p_shkey_t key) {
    return share_javaJNI.shdecode(SWIGTYPE_p_unsigned_char.getCPtr(data), data_len, SWIGTYPE_p_p_char.getCPtr(data_p), SWIGTYPE_p_size_t.getCPtr(data_len_p), SWIGTYPE_p_shkey_t.getCPtr(key));
  }

  public static int shdecode_str(String data, SWIGTYPE_p_shkey_t key) {
    return share_javaJNI.shdecode_str(data, SWIGTYPE_p_shkey_t.getCPtr(key));
  }

  public static SWIGTYPE_p_shlock_t shlock_open(SWIGTYPE_p_shkey_t key, int flags) {
    long cPtr = share_javaJNI.shlock_open(SWIGTYPE_p_shkey_t.getCPtr(key), flags);
    return (cPtr == 0) ? null : new SWIGTYPE_p_shlock_t(cPtr, false);
  }

  public static int shlock_tryopen(SWIGTYPE_p_shkey_t key, int flags, SWIGTYPE_p_p_shlock_t lock_p) {
    return share_javaJNI.shlock_tryopen(SWIGTYPE_p_shkey_t.getCPtr(key), flags, SWIGTYPE_p_p_shlock_t.getCPtr(lock_p));
  }

  public static int shlock_close(SWIGTYPE_p_shkey_t key) {
    return share_javaJNI.shlock_close(SWIGTYPE_p_shkey_t.getCPtr(key));
  }

  public static void sh_sha256(SWIGTYPE_p_unsigned_char message, long len, SWIGTYPE_p_unsigned_char digest) {
    share_javaJNI.sh_sha256(SWIGTYPE_p_unsigned_char.getCPtr(message), len, SWIGTYPE_p_unsigned_char.getCPtr(digest));
  }

  public static String shdigest(SWIGTYPE_p_void data, int len) {
    return share_javaJNI.shdigest(SWIGTYPE_p_void.getCPtr(data), len);
  }

  public static String shjson_print(SWIGTYPE_p_shjson_t json) {
    return share_javaJNI.shjson_print(SWIGTYPE_p_shjson_t.getCPtr(json));
  }

  public static String shjson_str(SWIGTYPE_p_shjson_t json, String name, String def_str) {
    return share_javaJNI.shjson_str(SWIGTYPE_p_shjson_t.getCPtr(json), name, def_str);
  }

  public static String shjson_astr(SWIGTYPE_p_shjson_t json, String name, String def_str) {
    return share_javaJNI.shjson_astr(SWIGTYPE_p_shjson_t.getCPtr(json), name, def_str);
  }

  public static SWIGTYPE_p_shjson_t shjson_str_add(SWIGTYPE_p_shjson_t tree, String name, String val) {
    long cPtr = share_javaJNI.shjson_str_add(SWIGTYPE_p_shjson_t.getCPtr(tree), name, val);
    return (cPtr == 0) ? null : new SWIGTYPE_p_shjson_t(cPtr, false);
  }

  public static void shjson_free(SWIGTYPE_p_p_shjson_t tree_p) {
    share_javaJNI.shjson_free(SWIGTYPE_p_p_shjson_t.getCPtr(tree_p));
  }

  public static double shjson_num(SWIGTYPE_p_shjson_t json, String name, double def_d) {
    return share_javaJNI.shjson_num(SWIGTYPE_p_shjson_t.getCPtr(json), name, def_d);
  }

  public static SWIGTYPE_p_shjson_t shjson_num_add(SWIGTYPE_p_shjson_t tree, String name, double num) {
    long cPtr = share_javaJNI.shjson_num_add(SWIGTYPE_p_shjson_t.getCPtr(tree), name, num);
    return (cPtr == 0) ? null : new SWIGTYPE_p_shjson_t(cPtr, false);
  }

  public static SWIGTYPE_p_shjson_t shjson_init(String json_str) {
    long cPtr = share_javaJNI.shjson_init(json_str);
    return (cPtr == 0) ? null : new SWIGTYPE_p_shjson_t(cPtr, false);
  }

  public static SWIGTYPE_p_shjson_t shjson_array_add(SWIGTYPE_p_shjson_t tree, String name) {
    long cPtr = share_javaJNI.shjson_array_add(SWIGTYPE_p_shjson_t.getCPtr(tree), name);
    return (cPtr == 0) ? null : new SWIGTYPE_p_shjson_t(cPtr, false);
  }

  public static String shjson_array_str(SWIGTYPE_p_shjson_t json, String name, int idx) {
    return share_javaJNI.shjson_array_str(SWIGTYPE_p_shjson_t.getCPtr(json), name, idx);
  }

  public static String shjson_array_astr(SWIGTYPE_p_shjson_t json, String name, int idx) {
    return share_javaJNI.shjson_array_astr(SWIGTYPE_p_shjson_t.getCPtr(json), name, idx);
  }

  public static double shjson_array_num(SWIGTYPE_p_shjson_t json, String name, int idx) {
    return share_javaJNI.shjson_array_num(SWIGTYPE_p_shjson_t.getCPtr(json), name, idx);
  }

  public static SWIGTYPE_p_shjson_t shjson_obj(SWIGTYPE_p_shjson_t json, String name) {
    long cPtr = share_javaJNI.shjson_obj(SWIGTYPE_p_shjson_t.getCPtr(json), name);
    return (cPtr == 0) ? null : new SWIGTYPE_p_shjson_t(cPtr, false);
  }

  public static long shjson_strlen(SWIGTYPE_p_shjson_t json, String name) {
    return share_javaJNI.shjson_strlen(SWIGTYPE_p_shjson_t.getCPtr(json), name);
  }

  public static SWIGTYPE_p_shfs_ino_t shfs_inode(SWIGTYPE_p_shfs_ino_t parent, String name, int mode) {
    long cPtr = share_javaJNI.shfs_inode(SWIGTYPE_p_shfs_ino_t.getCPtr(parent), name, mode);
    return (cPtr == 0) ? null : new SWIGTYPE_p_shfs_ino_t(cPtr, false);
  }

  public static String shfs_filename(SWIGTYPE_p_shfs_ino_t inode) {
    return share_javaJNI.shfs_filename(SWIGTYPE_p_shfs_ino_t.getCPtr(inode));
  }

  public static int shfs_type(SWIGTYPE_p_shfs_ino_t inode) {
    return share_javaJNI.shfs_type(SWIGTYPE_p_shfs_ino_t.getCPtr(inode));
  }

  public static SWIGTYPE_p_shfs_ino_t shfs_inode_parent(SWIGTYPE_p_shfs_ino_t inode) {
    long cPtr = share_javaJNI.shfs_inode_parent(SWIGTYPE_p_shfs_ino_t.getCPtr(inode));
    return (cPtr == 0) ? null : new SWIGTYPE_p_shfs_ino_t(cPtr, false);
  }

  public static SWIGTYPE_p_shfs_ino_t shfs_inode_load(SWIGTYPE_p_shfs_ino_t parent, SWIGTYPE_p_shkey_t key) {
    long cPtr = share_javaJNI.shfs_inode_load(SWIGTYPE_p_shfs_ino_t.getCPtr(parent), SWIGTYPE_p_shkey_t.getCPtr(key));
    return (cPtr == 0) ? null : new SWIGTYPE_p_shfs_ino_t(cPtr, false);
  }

}
