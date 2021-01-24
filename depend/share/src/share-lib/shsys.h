
/*
 * @copyright
 *
 *  Copyright 2015 Neo Natura 
 *
 *  This file is part of the Share Library.
 *  (https://github.com/neonatura/share)
 *        
 *  The Share Library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version. 
 *
 *  The Share Library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with The Share Library.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  @endcopyright
*/  

#ifdef __cplusplus
extern "C" {
#endif

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif


#ifndef __MEM__SHSYS_H__
#define __MEM__SHSYS_H__



/**
 * Provides OS system functionality.
 * @ingroup libshare
 * @defgroup libshare_sys System-level Routines
 * @{
 */


/**
 * Perform geodetic calculations involving location metrics.
 * @ingroup libshare_sys
 * @defgroup libshare_sysgeo Geodetic Calculations
 * @{
 */

/** Location precision of a 'regional area'. Roughly 3000 square miles. */
#define SHGEO_PREC_REGION 0 /* 69 LAT * 44.35 LON = 3k sq-miles */
/** Location precision of a 'zone'. Roughly 30 square miles. */
#define SHGEO_PREC_ZONE 1 /* 6.9 LAT * 4.43 LON = 30.567 sq-miles  */
/** Location precision of a 'district of land'. Roughly 0.3 square miles. */
#define SHGEO_PREC_DISTRICT 2 /* 3643.2 LAT * 2339 LON = 8.5mil sq-feet */
/** Location precision of a 'land site'. Roughly 85,000 square feet. */
#define SHGEO_PREC_SITE 3 /* 364.32 LAT * 233.9 LON = 85k sq-feet */
/** Location precision of a 'section of area'. Roughly 800 square feet. */
#define SHGEO_PREC_SECTION 4 /* 36.43 LAT * 22.7 LON = 827 sq-feet */
/** Location precision of a 'spot of land'. Roughly 8 square feet. */
#define SHGEO_PREC_SPOT 5 /* 3.64 LAT * 2.27 LON = 8.2628 sq-feet */
/** Location precision of a single point. Roughly 10 square inches. */
#define SHGEO_PREC_POINT 6 /* 4 LAT * 2.72448 LON = 10.897 sq-inches */
/** The number of precision specifications available. */
#define SHGEO_MAX_PRECISION 6


/** The system-level geodetic database. */
#define SHGEO_SYSTEM_DATABASE_NAME "geo"
/** The user-level geodetic database. */
#define SHGEO_USER_DATABASE_NAME "geo.usr"

/** A database table containing common north-america zipcodes. */
#define SHGEO_ZIPCODE "sys_zipcode_NA"
/** A database table containing common north-america places. */
#define SHGEO_COMMON "sys_common_NA"
/** A database table containing common north-america IP address locations. */
#define SHGEO_NETWORK "sys_network_NA"
/** A database table containing common north-america city names. */
#define SHGEO_CITY "sys_city_NA"
#if 0
/** A database table containing user-supplied locations. */
#define SHGEO_USER "user"
#endif


/** A specific location with optional altitude and time-stamp. */
struct shgeo_t
{
  /** The time-stamp of when geodetic location was established. */
  shtime_t geo_stamp;
  /** A latitude position. */
  uint64_t geo_lat;
  /** A longitude position. */
  uint64_t geo_lon;
  /** An altitude (in feet) */
  uint32_t geo_alt;
  /** The timezone associated with the geodetic location. */
  uint32_t __reserved__;
};

typedef struct shgeo_t shgeo_t;


/** A contextual description of a specific location. */
struct shloc_t
{
  char loc_name[MAX_SHARE_NAME_LENGTH];
  char loc_summary[MAX_SHARE_NAME_LENGTH];
  char loc_locale[MAX_SHARE_NAME_LENGTH];
  char loc_zone[MAX_SHARE_NAME_LENGTH];
  char loc_type[MAX_SHARE_NAME_LENGTH];
  uint32_t loc_prec;
  uint32_t __reserved_0__;

  struct shgeo_t loc_geo;
};

typedef struct shloc_t shloc_t;


/**
 * Establish a geodetic location based off a latitude, longitude, and optional altitude.
 */
void shgeo_set(shgeo_t *geo, shnum_t lat, shnum_t lon, int alt);

/**
 * Obtain the latitude, longitude, and altitude for a geodetic location.
 */
void shgeo_loc(shgeo_t *geo, shnum_t *lat_p, shnum_t *lon_p, int *alt_p);

/**
 * The duration since the geodetic location was established in seconds.
 */
time_t shgeo_lifespan(shgeo_t *geo);

/**
 * A 'key tag' representing the geodetic location in reference to a particular precision.
 */
shkey_t *shgeo_tag(shgeo_t *geo, int prec);


/**
 * Compare two geodetic locations for overlap based on precision specified.
 */
int shgeo_cmp(shgeo_t *geo, shgeo_t *cmp_geo, int prec);

int shgeo_cmpf(shgeo_t *geo, double lat, double lon);

/** The combined latitude and longitude distances between two geodetic locations. */
double shgeo_radius(shgeo_t *f_geo, shgeo_t *t_geo);

/** Reduce the precision of a geodetic location. */
void shgeo_dim(shgeo_t *geo, int prec);

/**
 * Obtain the device's current location.
 */
void shgeo_local(shgeo_t *geo, int prec);


/**
 * Manually set the device's current location.
 */
void shgeo_local_set(shgeo_t *geo);


/** Search an area for a known geodetic location. */
int shgeodb_scan(shnum_t lat, shnum_t lon, shnum_t radius, shgeo_t *geo);

/** Search for a known geoetic location based on a location name. */
int shgeodb_place(const char *name, shgeo_t *geo);

/** Search for a known geodetic location given an IP or Host network address. */
int shgeodb_host(const char *name, shgeo_t *geo);

/** Search for a known geodetic location given an IP or Host network address. */
int shgeodb_loc(shgeo_t *geo, shloc_t *loc);

/** Set custom location information for a particular geodetic location. */
int shgeodb_loc_set(shgeo_t *geo, shloc_t *loc);

int shgeodb_loc_unset(shgeo_t *geo);


/** A formal description of a particular place code. */
const char *shgeo_place_desc(char *code);

/** The geometric precision for a particular place type. */
int shgeo_place_prec(char *code);

/** An array of codes signifying difference types of places. */
const char **shgeo_place_codes(void);


/** Obtain a rowid for a particular geodetic location in a given database. */
int shgeodb_rowid(shdb_t *db, const char *table, shgeo_t *geo, shdb_idx_t *rowid_p);

/** Obtain a geodetic location from a location name in a given database. */
int shgeodb_name(shdb_t *db, char *table, const char *name, shgeo_t *geo);


/**
 * @}
 */




/**
 * Provides capabilities for managing user accounts.
 * @ingroup libshare_sys
 * @defgroup libshare_syspam Permission Access Management
 * @{
 */

#define SHAUTH_SCOPE_LOCAL 0

#define SHAUTH_SCOPE_REMOTE 1

#define SHAUTH_SCOPE_2FA 2

#define SHAUTH_SCOPE_AUX 3

#define SHAUTH_MAX 4


#define SHSEED_SECRET_SIZE 64


/* may be used as for primary account validation */
#define SHAUTH_PRIMARY (1 << 0)

/* may be used as for secondary account validation (2fa) */
#define SHAUTH_SECONDARY (1 << 1)

/** public key is derived from local seed secret */
#define SHAUTH_SECRET (1 << 2)

/** authorization method provided via external (not local user) means */
#define SHAUTH_EXTERNAL (1 << 3)

/** the algorithm uses a relative time as the payload message to sign (2fa). */
#define SHAUTH_TIME (1 << 4)


#define SHPERM_READ (1 << 0)
#define SHPERM_WRITE (1 << 1)
#define SHPERM_CREATE (1 << 2)
#define SHPERM_VERIFY (1 << 3)
#define SHPERM_DELETE (1 << 4)

#define SHPERM_ADMIN \
  (SHPERM_READ | SHPERM_WRITE | SHPERM_CREATE | \
   SHPERM_VERIFY | SHPERM_DELETE)


#define SHPAM_DELETE (1 << 0)
#define SHPAM_EXPIRE (1 << 1)
#define SHPAM_LOCK (1 << 2)
#define SHPAM_STATUS (1 << 3)
#define SHPAM_SESSION (1 << 4)
#define SHPAM_UNLOCK (1 << 5)
#define SHPAM_UPDATE (1 << 6)
#define SHPAM_CREATE (1 << 7)


#define SHUSER_NAME 0
#define SHUSER_REALNAME 1
#define SHUSER_COINADDR 2
#define SHUSER_ZIPCODE 3 
#define SHUSER_GEO 4
#define SHUSER_CTIME 5
#define SHUSER_2FA 6


typedef struct shauth_t
{
  uint32_t auth_alg; /* SHALG_XX */
  uint32_t auth_flag; /* SHAUTH_XX */
  uint64_t auth_salt; /* random 64-bit number to perturb secret */
  shtime_t auth_stamp; /* original creation time-stamp */
  shtime_t auth_expire; /* when authorization expires */
  shalg_t auth_pub;
  shalg_t auth_sig;
} shauth_t;


struct shseed_t
{


  uint32_t __reserved_1__;

  uint32_t seed_perm;

  /* a reference to the account name. */
  uint64_t seed_uid;

  uint64_t __reserved_2__;

  shtime_t seed_stamp;
  shtime_t seed_expire;

  uint64_t seed_secret[8];

  /* the authorization methods available to validate the account. */
  shauth_t auth[SHAUTH_MAX];

};
typedef struct shseed_t shseed_t;



struct shadow_t 
{
  uint64_t sh_uid;

  /** Geodetic cordinates of the primary location. */
  shgeo_t sh_geo;

  /* An account name alias. */
  char sh_name[MAX_SHARE_NAME_LENGTH];

  /* A person name or organization. */
  char sh_realname[MAX_SHARE_NAME_LENGTH];

  /** A share-coin coin address. */
  char sh_sharecoin[MAX_SHARE_HASH_LENGTH];
};
typedef struct shadow_t shadow_t;


typedef struct shpriv_t
{
  uint64_t priv_uid;
  shkey_t priv_sess; 
} shpriv_t;


typedef struct shpam_t
{
	uint64_t uid;
	shkey_t ident;
	shfs_ino_t *file;
	shfs_t *fs;
} shpam_t;


/** A unique reference to a share account. */
uint64_t shpam_uid(char *username);

/** An identity key referencing an account for an application. */
shkey_t *shpam_ident_gen(uint64_t uid, shpeer_t *peer);

/** The 'root' identity for an application. */
shkey_t *shpam_ident_root(shpeer_t *peer);

/** Verify that an identity key references an application account. */
int shpam_ident_verify(shkey_t *id_key, uint64_t uid, shpeer_t *peer);



/** Generate a random salt to be used to perterb a password key. */
uint64_t shpam_salt(void);

/** The current user's system account name. */
const char *shpam_username_sys(void);





/* user funcs */

const char *shuser_self(void);
uint64_t shuser_id(char *acc_name);
uint64_t shuser_self_id(void);


/**
 * Create a new user account.
 * @param username The account name.
 * @param ret_sess A session key which can be used to perform priveleged operations on the user account created.
 * @returns A libshare error code.
 * @note The effective current user must have SHPERM_CREATE permission to peform this action.
 */
int shuser_create(char *acc_name, shpriv_t **priv_p);

int shuser_create_priv(char *acc_name, shpriv_t *priv, shpriv_t **priv_p);

int shuser_login_2fa(char *acc_name, char *passphrase, uint32_t code_2fa, shpriv_t **priv_p);

int shuser_login(char *acc_name, char *passphrase, shpriv_t **priv_p);

int shuser_pass_set(char *acc_name, shpriv_t *priv, char *passphrase);

int shuser_info_set(char *acc_name, shpriv_t *priv, int cmd, unsigned char *data, size_t data_len);

int shuser_remove(char *acc_name, shpriv_t *priv); 

int shuser_info(char *acc_name, int cmd, unsigned char *ret_data, size_t *ret_len_p);


shjson_t *shuser_json(char *acc_name);

int shuser_verify(char *acc_name);

/** Notify the shared daemon of an account. */
int shuser_inform(uint64_t uid);

int shuser_admin_default(char *acc_name, shpriv_t **priv_p);



/* pam - shadow */

shpam_t *shpam_open(uint64_t uid);
shpam_t *shpam_open_name(char *acc_name);
void shpam_close(shpam_t **pam_p);

int shpam_shadow_login(shfs_ino_t *file, char *acc_name, uint32_t code_2fa, unsigned char *pass_data, size_t pass_len, shpriv_t **priv_p);

int shpam_shadow_pass_set(shfs_ino_t *file, char *acc_name, shpriv_t *priv, unsigned char *pass_data, size_t pass_len);

int shpam_shadow_remove(shfs_ino_t *file, uint64_t uid, shpriv_t *priv);

int shpam_shadow_get(shfs_ino_t *file, uint64_t uid, int cmd, unsigned char *raw, size_t *raw_len_p);

int shpam_shadow_set(shfs_ino_t *file, uint64_t uid, shpriv_t *priv, int cmd, unsigned char *raw, size_t raw_len);

int shpam_shadow_uid_verify(shfs_ino_t *file, uint64_t uid);

shjson_t *shpam_shadow_json(shfs_ino_t *file, uint64_t uid);

int shpam_shadow_remote_set(shfs_ino_t *file, uint64_t uid, shauth_t *auth);

int shpam_shadow_priv_verify(shfs_ino_t *file, shpriv_t *priv);

int shpam_shadow_admin_login(shfs_ino_t *file, unsigned char *pass_data, size_t pass_len, shpriv_t **priv_p);

shpriv_t *shpam_shadow_admin_default(shfs_ino_t *file);

shtime_t shpam_shadow_ctime(shfs_ino_t *file, uint64_t uid);

int shpam_shadow_auth_load(shfs_ino_t *file, uint64_t uid, int scope, shauth_t *ret_auth);




/* pam - auth */

/** Generate a pass key from the username and pass code provided. */
int shpam_auth_set(shseed_t *seed, char *username, unsigned char *pass_data, size_t pass_len);

/** Verify a password seed references a username and password. */
int shpam_auth_verify(shseed_t *seed, char *username, unsigned char *pass_data, size_t pass_len);

/** Obtain the linux PAM salt used to "crypt" the passphrase. */
uint64_t shpam_salt_crypt(void);

int shpam_auth_alg_default(int scope);

int shpam_auth_init(uint64_t uid, shseed_t *seed);

int shpam_auth_2fa_verify(shseed_t *seed, char *username, uint32_t code_2fa);


/**
 * A checksum which is representative of the "secret data" associated with an account.
 */
uint64_t shpam_master_seed(shseed_t *seed);

uint64_t shpam_euid(void);



/* pam - app */

/** An application that is not intended to be publically accessible. */
#define SHAPP_LOCAL (1 << 0)

/** Indicates that the "soft" resource limitations set by OS should be utilized. */
#define SHAPP_RLIMIT (1 << 1) 


/**
 * Strips the absolute parent from @a app_name
 * @note "/test/one/two" becomes "two"
 * @param app_name The running application's executable path
 * @returns Relative filename of executable.
 */
char *shapp_name(char *app_name);

/**
 * Initialize the share library runtime for an application.
 * @param exec_path The process's executable path.
 * @param host The host that the app runs on or NULL for localhost.
 * @param flags application flags
 */
shpeer_t *shapp_init(char *exec_path, char *host, int flags);

int shapp_register(shpeer_t *peer);

int shapp_listen(int tx, shpeer_t *peer);

int shapp_account(const char *username, char *passphrase, shseed_t **seed_p);

int shapp_ident(uint64_t uid, shkey_t **id_key_p);

shkey_t *shapp_kpriv(shpeer_t *peer);

shkey_t *shapp_kpub(shpeer_t *peer);



/**
 * @}
 */





/**
 * Write informational, warnings, and error messages to a process specific log file.
 * @ingroup libshare_sys
 * @defgroup libshare_syslog Process Logging
 * @{
 */

#define SHLOG_NONE 0
#define SHLOG_INFO 1
#define SHLOG_WARNING 2
#define SHLOG_ERROR 3
#define SHLOG_RUSAGE 4

#define MAX_SHLOG_LEVEL 5

/** Perform a generic logging operation. */
int shlog(int level, int err_code, char *log_str);

/** Log a libshare error code (SHERR_XXX) and an error message. */
void sherr(int err_code, char *log_str);

/** Log a warning message. */
void shwarn(char *log_str);

/** Log a informational message.  */
void shinfo(char *log_str);

/** The directory where log files are written. */
const char *shlog_path(char *tag);

/** Set the directory where log files are written. */
int shlog_path_set(const char *path);

void shlog_level_set(int level);

int shlog_level(void);


/**
 * @}
 */




/**
 * Provides the capability to manage a libshare runtime message queue.
 * @ingroup libshare_sys
 * @defgroup libshare_sysmsg IPC Message Queue
 * @{
 */


#define MAX_MESSAGE_QUEUES 512
/** The maximum size of an individual libshare message queue. */
#define MESSAGE_QUEUE_SIZE 4096000
/** The maximum number of messages a message queue can contain. */
#define MAX_MESSAGES_PER_QUEUE 2048


/** remove a message queue's resources. */
#define SHMSGF_RMID (1 << 0)

/** discard stale messages when queue is full. */
#define SHMSGF_OVERFLOW (1 << 1)

/** allow for receiving messages sent by one self. */
#define SHMSGF_ANONYMOUS (1 << 2)

/** unused */
#define SHMSGF_AUTH (1 << 4)





struct shmsg_t 
{

  /** source peer of message. */
  shkey_t src_key;

  /** destination peer of message. */
  shkey_t dest_key;

  /** message queue id */
  uint32_t msg_qid;

  /** total size of message content */
  uint32_t msg_size;

  /** offset of message data */
  uint32_t msg_of;

  /** type of message */
  uint32_t __reserved_1__;

};

typedef struct shmsg_t shmsg_t;

typedef struct shmsgq_t {
  /** expiration of lock or 0 if unlocked. */
  shtime_t lock_t;

  /** message queue flags SHMSGF_XX */
  uint32_t flags;

  /* reserved for future use */
  uint32_t __reserved_1__;

  /** read msg seek offset */
  uint32_t read_idx;

  /** write msg seek offset */
  uint32_t write_idx;

  /** read data seek offset */
  uint32_t read_of;

  /** write data seek offset */
  uint32_t write_of;

  /** table of message definitions */
  shmsg_t msg[MAX_MESSAGES_PER_QUEUE];

  /** raw message content data */
  unsigned char data[0];
} shmsgq_t;

/**
 * Obtain the message queue id from a share library peer.
 * @param peer The destination peer message queue.
 */
int shmsgget(shpeer_t *peer);

/**
 * Send a message to a share library peer.
 * @param msg_qid The share library message queue id.
 * @param msg_type A non-zero user-defined categorical number.
 * @see shmsgget()
 */
int shmsgsnd(int msqid, const void *msgp, size_t msgsz);

/**
 * Send a message to a share library peer.
 * @param dest_key Peer key of message destination. Specifying NULL indicates to use the peer used to open the message queue.
 * @see shmsgget()
 */
int shmsg_write(int msg_qid, shbuf_t *msg_buff, shkey_t *dest_key);

/**
 * Receive a message from a share library peer.
 */
int shmsgrcv(int msqid, void *msgp, size_t msgsz);

/**
 * Receive a message from a share library peer.
 */
int shmsg_read(int msg_qid, shkey_t *src_key, shbuf_t *msg_buff);

/**
 * Set or retrieve message queue control attributes.
 */
int shmsgctl(int msg_qid, int cmd, int value);


/**
 * @}
 */




/**
 * Provides the capability to create, manage, and communicate with multiple processes running as spawned programs.
 * @ingroup libshare_sys
 * @defgroup libshare_sysproc Process Pool Management
 * @{
 */

#define SHPROC_NONE 0

#define SHPROC_IDLE 1

#define SHPROC_PEND 2

#define SHPROC_RUN 3

#define MAX_SHPROC_STATES 4


/** A control option which manages the maximum number of processes spawned. */
#define SHPROC_MAX 100
#define SHPROC_PRIO 101

/** The default maximum number of processes spawned. */
#define SHPROC_POOL_DEFAULT_SIZE 16

typedef int (*shproc_op_t)(int, shbuf_t *buff);

struct shproc_req_t 
{
  uint32_t state;
  uint32_t error;
  uint32_t crc;
  uint32_t data_len;
  uint32_t user_fd;
};
typedef struct shproc_req_t shproc_req_t;

struct shproc_t
{
  int proc_pid;
  int proc_state;
  int proc_fd;
  int proc_idx;
  int proc_error;
  int proc_prio;

  int user_fd;
  int dgram_fd;

  shproc_op_t proc_req;
  shproc_op_t proc_resp;
  shtime_t proc_stamp;
  shbuf_t *proc_buff;

  struct shproc_stat_t {
    int in_tot;
    int out_tot;
    double span_tot[MAX_SHPROC_STATES];
    int span_cnt[MAX_SHPROC_STATES];
  } stat;
};
typedef struct shproc_t shproc_t;


struct shproc_pool_t
{
  int pool_max;
  int pool_lim;
  int pool_prio;
  /* callbacks */
  shproc_op_t pool_req;
  shproc_op_t pool_resp;
  /* process list */
  shproc_t *proc;
};
typedef struct shproc_pool_t shproc_pool_t;

/**
 * Create a new pool to manage process workers.
 */
shproc_pool_t *shproc_init(shproc_op_t req_f, shproc_op_t resp_f);

/**
 * Configure a process pool's attributes.
 *  - SHPROC_MAX The maximum number of processes that can be spawned in the pool.
 *  - SHPROC_PRIO A value in the range -20  to  19. A lower priority indicates a more favorable scheduling. 
 *  @param type The configuration option value to set or get.
 *  @param val Zero to indicate a 'Get Value' request; otherwise the parameter specifies the value to the option to.
 */
int shproc_conf(shproc_pool_t *pool, int type, int val);

/**
 * Obtain currrent pool, if any, that has been initialized.
 */
shproc_pool_t *shproc_pool(void);

/**
 * Start a new process to handle worker requests.
 */
shproc_t *shproc_start(shproc_pool_t *pool);

/**
 * Terminate a running worker process.
 */
int shproc_stop(shproc_t *proc);

/**
 * Obtain a process slot from the pool based on process state.
 */
shproc_t *shproc_get(shproc_pool_t *pool, int state);

int shproc_schedule(shproc_t *proc, unsigned char *data, size_t data_len);

/**
 * Obtain a process from the pool that is ready for work.
 */
shproc_t *shproc_pull(shproc_pool_t *pool);

/**
 * Perform a request against a process ready for work.
 */
int shproc_push(shproc_pool_t *pool, int fd, unsigned char *data, size_t data_len);

/**
 * deallocate resources for a process pool
 */
void shproc_free(shproc_pool_t **pool_p);

/**
 * Set a custom signal handler for worker process.
 */
void shproc_signal(void *sig_f);

/**
 * Process pending communications with worker process(es).
 */
void shproc_poll(shproc_pool_t *pool);

void shproc_rlim_set(void);

uint64_t shproc_rlim(int mode);

/**
 * @}
 */






/**
 * Provides the ability to generate and manage authority certificates.
 * @ingroup libshare_sys
 * @defgroup libshare_syscert Authority Certification
 * @{
 */

#define SHENCRYPT_BLOCK_SIZE 8

#define SHESIG_VERSION htonl(3UL)

#define SHESIG_ALG_DEFAULT SHALG_ECDSA384R


int shesig_init(shesig_t *cert, char *entity, int alg, int flags);

int shesig_ca_init(shesig_t *cert, char *entity, int alg, int flags);

int shesig_sign(shesig_t *cert, shesig_t *parent, unsigned char *key_data, size_t key_len);

/** Insert a certificate from an external origin. */
int shesig_import(shesig_t *cert, char *iss, shalg_t iss_pub);

void shesig_free(shesig_t **cert_p);
char *shesig_id_hex(shesig_t *cert);
char *shesig_flag_str(int flags);
int shesig_id_verify(shesig_t *cert);
void shesig_id_gen(shesig_t *cert);
void shesig_print(shesig_t *cert, shbuf_t *pr_buff);
const char *shesig_serialno(shesig_t *cert);
int shesig_verify(shesig_t *cert, shesig_t *parent);



/* member field access */
void shesig_serial(shesig_t *cert, unsigned char *ret_data, size_t *ret_len_p);
void shesig_serial_set(shesig_t *cert, unsigned char *serial, size_t serial_len);
unsigned int shesig_version(shesig_t *cert);
void shesig_version_set(shesig_t *cert, unsigned int ver);
uint64_t shesig_uid(shesig_t *cert);
shkey_t *shesig_ctx(shesig_t *cert);
void shesig_ctx_name_set(shesig_t *cert, char *label);
void shesig_ctx_set(shesig_t *cert, shkey_t *ctx_name);
shtime_t shesig_expire(shesig_t *cert);
void shesig_expire_set(shesig_t *cert, shtime_t stamp);
shtime_t shesig_stamp(shesig_t *cert);
void shesig_stamp_set(shesig_t *cert, shtime_t stamp);
char *shesig_iss(shesig_t *cert);
void shesig_iss_set(shesig_t *cert, char *name);
char *shesig_ent(shesig_t *cert);
void shesig_ent_set(shesig_t *cert, char *name);



/* file i/o */
int shesig_load_alias(char *label, shesig_t **cert_p);
int shesig_load(shkey_t *id, shesig_t **cert_p);
int shesig_load_path(char *fname, shesig_t **cert_p);
int shesig_save(shesig_t *cert, shbuf_t *buff);
int shesig_remove_alias(char *label);
int shesig_remove_label(char *ref_path);






typedef struct shasset_t
{
  char host_url[MAX_SHARE_HASH_LENGTH]; /* [a-zA-Z]{2,3}(-([a-zA-Z]{2}|[0-9]{3}))? */

  /* external asset barcode reference */
  char ass_code[16];

  char ass_locale[16]; /* [a-zA-Z]{2,3}(-([a-zA-Z]{2}|[0-9]{3}))? */

  /** The certificate pertaining to this asset. */
  shkey_t ass_cert;

  /** The location where the asset resides. */
  shgeo_t ass_loc;

  /* identity key of originating creator */
  shkey_t ass_id;

  /* originating peer (priveleged key) */
  shkey_t ass_peer;

  /** A signature key verifying the underlying contents. */
  shkey_t ass_sig;

  /** Time-stamp of when asset was created. */
  shtime_t ass_birth;

  /** When the asset information invalidates. */
  shtime_t ass_expire;
} shasset_t;

/** A symbolic reference of with no systematic use. */
#define TXREF_SYMBOL 0 
/** A symbolic reference for testing-use only. */
#define TXREF_TEST 1
/* a sharenet transaction hash (u224) */
#define TXREF_TX 10
/* a SHC block-chain transaction hash (u256) */
#define TXREF_SHCTX 20
/* public key coin address (uint160) */
#define TXREF_PUBADDR 30
/* a certificate hash reference (uint160) */
#define TXREF_CERT 31

/**
 * A label tag for a particular key.
 */
typedef struct shref_t
{
  /** A plain-text name in reference to a key. */
  char ref_name[MAX_SHARE_NAME_LENGTH];

  /** The key/hash being referenced. */
  char ref_hash[MAX_SHARE_HASH_LENGTH];

  /** A key referencing the server which issued the reference. */
  shkey_t ref_peer;

  /** Auxillary context associated with the reference. */
  shkey_t ref_ctx;

  /** The time-stamp of when the reference is no longer valid. */
  shtime_t ref_expire;

  /* a particular type of reference (TXREF_XXX) */
  uint32_t ref_type;

  /* a sub-type specific to the reference type */
  uint32_t ref_level;
} shref_t;


/** The subject's public key from a share certificate. */
#define shesig_sub_pub(_cert) \
  ((_cert)->pub)

/** A signature of the parent certicate's public key. */
#define shesig_sub_sig(_cert) \
  ((_cert)->data_sig)

/** The share time-stamp of when the certificate subject's signature becomes valid. */
#define shesig_sub_stamp(_cert) \
  ((_cert)->stamp)

/** The share time-stamp of when the certificate subject's signature validicity expires. */
#define shesig_sub_expire(_cert) \
  ((_cert)->expire)

/** Obtain the subject's signature algorithm from a share certificate. */
#define shesig_sub_alg(_cert) \
  (ntohl((_cert)->alg))
#define shesig_sub_alg_set(_cert, _alg) \
  ((_cert)->alg = htonl(_alg))

/** Obtain the serial number of the certificate. */
#define shesig_sub_ser(_cert) \
  ((_cert)->ser)

/** Obtain the length of the context used to create the signature. */
#define shesig_sub_len(_cert) \
  (shalg_size((_cert)->data_sig)/2)


/* shsys_lic.c */

/**
 * Apply a licensing certificate to a shfs file.
 */
int shlic_apply(SHFL *file, shesig_t *cert, unsigned char *key_data, size_t key_len);

/**
 * Validates authorized licensing of a file.
 */
int shlic_validate(SHFL *file);

int shlic_sign(shlic_t *lic, shesig_t *parent, unsigned char *key_data, size_t key_len);

int shlic_set(SHFL *file, shlic_t *lic);

int shlic_get(SHFL *file, shlic_t *ret_lic);



/**
 * @}
 */







/**
 * Provides the capability to store and retrieve temporary named binary segments.
 * The time-to-live for cached content is configured by the "cache.expire" share preference. The value is specified in seconds and defaults to 3600 (one hour). 
 *
 * Example: shpref cache.expire 3600 
 *
 * @ingroup libshare_sys
 * @defgroup libshare_syscache Temporary Content Cache
 * @{
 */

char *shcache_path(const char *tag);

int shcache_write(const char *tag, shbuf_t *buff);

int shcache_read(const char *tag, shbuf_t *buff);

int shcache_fresh(const char *tag);

void shcache_purge(char *path);

time_t shcache_ttl(void);

/**
 * @}
 */





/**
 * Provides the capabilities for creating, signing, extracting, and certifying a set of files associated with a particular release distribution package.
 * @ingroup libshare_sys
 * @defgroup libshare_syspkg Project Distribution Packaging
 * @{
 */

#define SHPKGOP_EXTRACT &shpkg_extract_op
#define SHPKGOP_SIGN &shpkg_sign_op
#define SHPKGOP_UNSIGN &shpkg_unsign_op
#define SHPKGOP_REMOVE &shpkg_remove_op
#define SHPKGOP_LIST &shpkg_list_op

/**
 * A libshare package definition pertaining to a set of files and instructions on how to install those files.
 * @note Structure is the header for a '.spk' libshare package file.
 */
typedef struct shpkg_info_t
{
  /** The unique name of the package */
  char pkg_name[MAX_SHARE_NAME_LENGTH];
  /** The version number. */
  char pkg_ver[MAX_SHARE_NAME_LENGTH];
  /** The certificate used to license extracted files. */
  shesig_t pkg_cert;
  /** The originating peer which generated the package. */
  shpeer_t pkg_peer;
  /** The time-stamp of when the package was updated. */
  shtime_t pkg_stamp;
  /** The architecture the package is intended for. */
  uint32_t pkg_arch;
} shpkg_info_t;

typedef struct shpkg_t
{
  shfs_t *pkg_fs;
  shfs_ino_t *pkg_file;
  shpkg_info_t pkg;
  shbuf_t *pkg_buff;
} shpkg_t;

typedef int (*shpkg_op_t)(shpkg_t *, char *, shfs_ino_t *);


int shpkg_extract_op(shpkg_t *pkg, char *path, SHFL *file);
int shpkg_sign_op(shpkg_t *pkg, char *path, SHFL *file);
int shpkg_unsign_op(shpkg_t *pkg, char *path, SHFL *file);
int shpkg_remove_op(shpkg_t *pkg, char *path, SHFL *file);
int shpkg_list_op(shpkg_t *pkg, char *path, SHFL *file);
int shpkg_op_dir(shpkg_t *pkg, char *dir_name, char *fspec, shpkg_op_t op);


int shpkg_init(char *pkg_name, shpkg_t **pkg_p);

shkey_t *shpkg_sig(shpkg_t *pkg);

void shpkg_free(shpkg_t **pkg_p);

char *shpkg_version(shpkg_t *pkg);

void shpkg_version_set(shpkg_t *pkg, char *ver_text);

char *shpkg_name_filter(char *in_name);

char *shpkg_name(shpkg_t *pkg);

shpkg_t *shpkg_load(char *pkg_name, shkey_t *cert_sig);

int shpkg_sign_remove(shpkg_t *pkg);

int shpkg_extract(shpkg_t *pkg);

int shpkg_owner(shpkg_t *pkg);

int shpkg_cert_clear(shpkg_t *pkg);

int shpkg_remove(shpkg_t *pkg);

SHFL *shpkg_spec_file(shpkg_t *pkg);


int shpkg_sign(shpkg_t *pkg, shesig_t *parent, int flags, unsigned char *key_data, size_t key_len);

int shpkg_sign_name(shpkg_t *pkg, char *parent_alias, int flags, unsigned char *key_data, size_t key_len);


int shpkg_extract_files(shpkg_t *pkg, char *fspec);

int shpkg_file_license(shpkg_t *pkg, SHFL *file);

int shpkg_add(shpkg_t *pkg, SHFL *file);



/**
 * @}
 */












/**
 * Provides access to a database which holds auxiliary contextual information. The context name is stored as a 224-bit key. The context data is limited to 4096 bytes. Context records automatically expire after two years of their creation or last modification.
 *
 * Context records can be generated through the Share Coin project suite via the various "shc" utility program commands provided. These context records are automatically saved in the primary system database accessible by the libshare runtime functions described here.
 *
 * All context records are automatically distributed across the sharenet when the "shared" daemon is running locally.
 *
 * Although you may over-ride any context record locally, the context records received by a remote host will not over-ride the local system Context Database unless they originate from the same identity that created it.
 *
 * Certain context name prefixes have been reserved, or at least utilized, for specific purposes;
 * - "id:<email>" Specifies account information similar to the information stored in a shadow_t structure or recorded via the Share Coin identity management commands. The information is stored in JSON format.
 * - "geo:<lat>,<lon>" Descriptive and metric information relating to a particular geodetic location stored in JSON format.
 * - "loc:<name>" The name of a location which references a particular geodetic location. 
 * @ingroup libshare_sys
 * @defgroup libshare_sysctx Auxiliary Context Database
 * @{
 */

#define SHCTX_DEFAULT_EXPIRE_TIME 63072000 /* two years */ 

#define SHCTX_MAX_VALUE_SIZE 4096

#define SHCTX_TABLE_COMMON "common"

#define SHCTX_DATABASE_NAME "ctx"


typedef struct shctx_t
{

  /** An ident or coin-addr hash referencing the creator. */
  char ctx_iss[MAX_SHARE_HASH_LENGTH];

  /** A key referencing the context name. */
  shkey_t ctx_key;

  /** The creation date. */
  time_t ctx_stamp;

  /** The expiration date (2 years from creation). */
  time_t ctx_expire;

  uint64_t ctx_data_len;

  /** An allocated string of up to 4095 characters. */
  uint8_t *ctx_data;

} shctx_t;



/** Set an auxillary context. */
int shctx_set(char *name, unsigned char *data, size_t data_len);

/** Set an auxillary string context. */
int shctx_setstr(char *name, char *data);

/** Get an auxillary context. */
int shctx_get(char *name, shctx_t *ctx);

/** Store auxillary context via a share-key. */
int shctx_set_key(shkey_t *name_key, unsigned char *data, size_t data_len);

/** Retrieve auxillary context via a share-key. */
int shctx_get_key(shkey_t *name_key, shctx_t *ctx);

/** inform the shared daemon to relay a local context. */
int shctx_notify(shkey_t *name_key);

/**
 * A (shr160 / ripemd32) share key referencing the textual name.
 * @param name An unlimited length literal string.
 * @returns An un-allocated share-key.
 * @note The returned share-key does not need to be freed.
 */
shkey_t *shctx_key(char *name);

/**
 * @}
 */











/**
 * @}
 */

#endif /* ndef __MEM__SHSYS_H__ */


#ifdef __cplusplus
}
#endif

