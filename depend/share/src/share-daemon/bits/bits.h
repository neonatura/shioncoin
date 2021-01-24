
#ifndef __BITS__BITS_H__
#define __BITS__BITS_H__
/**
 * Network transaction operations
 * @brief shareademon_bits Network transaction operations
 * @addtogroup sharedaemon
 * @{
 */

#include "share.h"
#include "sexe.h"


#define MIN_TX_ONCE 256U

#define MAX_TX_ONCE 2147483647U 

#define MAX_TRANSACTIONS_PER_LEDGER 64

#define MAX_SCHEDULE_TASKS 4096

#define SHARENET_PROTOCOL_VERSION 1

#define MAX_CONTEXT_DATA_SIZE 4096



/** The "USDe" (unitary status dollar elec.) virtual currency. */
#define COIN_USDE "USDE"
/** The "EMC2" (game credits) virtual currency. */
#define COIN_EMC2 "EMC2"
/** The "SHC" (sharecoin) virtual currency. */
#define COIN_SHC "SHC"


/** This transaction is pending until an event takes place. */
#define TXF_EVENT (1 << 0)

/** This transacion is pending until a ward signature is released public. */
#define TXF_WARD (1 << 1) 

/** This transaction permits supplemental user rights. */
#define TXF_TRUST (1 << 2)

/** This transaction permits supplemental user rights. */
#define TXF_CONTEXT (1 << 3)



#if 0
/**
 * A predefined sharenet group restricted from access to this daemon only.
 */
#define TX_GROUP_PRIVATE \
  (shcrc("local", strlen("local")))

/**
 * A predefined sharenet group which only incorporates predisposed trust entities. */
#define TX_GROUP_PEER \
  (shcrc("peer", strlen("peer")))

/**
 * The default public-access sharenet group.
 */
#define TX_GROUP_PUBLIC \
  (shcrc("public", strlen("public")))

/**
 * Generates a sharenet group identifier from a string label. 
 * @returns A 64bit checksum representing a sharenet group.
 */
#define TX_GROUP(_label) \
  (shcrc((_label), strlen(_label)))
#endif




typedef int (*txop_f)(shpeer_t *, void *);
struct txop_t
{
  const char *op_name;
  size_t op_size;
  size_t op_keylen;
  txop_f op_init;
  txop_f op_conf;
  txop_f op_recv;
  txop_f op_send;
  txop_f op_wrap;
  uint64_t tot_send;
  uint64_t tot_recv;
};
typedef struct txop_t txop_t;




/**
 * Network state of transaction.
 */
typedef struct tx_net_t
{

  /** The destination peer or empty on a broadcast. */
  shkey_t tx_sink;

  /** The time-stamp of when transaction was prepared for transmission. */
  shtime_t tx_stamp;

  /** A checksum of the transaction header. */
  uint32_t tx_crc;

  uint32_t tx_magic;

  uint32_t tx_size;

  /** encoded format of transaction data */
  uint32_t tx_proto;

} tx_net_t;

/**
 * The base information for a transaction.
 */
typedef struct tx_t
{

  /** A scrypt-generated hash string validating this transaction. */
  char hash[MAX_SHARE_HASH_LENGTH];

  /** The initiating peer's priveleged key. */
  shkey_t tx_peer;

  /** A key representation of this transaction. */
  shkey_t tx_key;

  /** The time-stamp pertaining to when the transaction was initiated. */
  shtime_t tx_stamp;

  /** The kind of transaction being referenced. */
  uint32_t tx_op;

  /** The transaction flag modifiers. (TXF_XX) */
  uint32_t tx_flag;

  /** The nonce index used to generate or verify the hash. */
  uint32_t nonce;

  /** The method used to compute the transaction hash. */
  uint32_t tx_alg;

} tx_t;

struct tx_subscribe_t
{
  tx_t sub_tx;
  shkey_t sub_key;
  uint32_t sub_op;
  uint32_t sub_flag;
};
typedef struct tx_subscribe_t tx_subscribe_t;

/** require additional trust transaction */
struct tx_trust_t 
{
  /** A persistent transaction referencing the trust. */
  tx_t trust_tx;

  /** The transaction the trust references. */
  shkey_t trust_ref;

  /** The identity being granted trust permissions. */
  shkey_t trust_id;

  shkey_t trust_ctx;

  shkey_t trust_sig;
};
typedef struct tx_trust_t tx_trust_t; 

/**
 * Application-scope unique identity for account operations.
 */
struct tx_id_t 
{

  /** permanent transaction reference to identity */
  tx_t id_tx;

  /** The application the identity is registered for. */
  shpeer_t id_peer;

  /** A key referencing this identity's underlying information. */
  shkey_t id_key;

  /** When the identity was initially generated. */
  shtime_t id_stamp;

  /** The account user id. */
  uint64_t id_uid;

#if 0 
  char id_name[MAX_SHARE_NAME_LENGTH];
  char id_host[MAX_SHARE_NAME_LENGTH];
  char id_email[MAX_SHARE_NAME_LENGTH];
  /** known phone number */
  char id_phone[16]; /* (([2-9][0-8]\d-[2-9]\d{2}-[0-9]{4})|(([0-9]?){6,14}[0-9])) */

  /* known birth-date */
  time_t id_birth;

  /* known location */
  shgeo_t id_geo;
#endif

};
typedef struct tx_id_t tx_id_t; 

/** 
 * An "identity" that holds "identities".
 */ 
struct tx_account_t 
{

	/** a sha256 hash representing this account */
  tx_t acc_tx;

  /** The share account user identification number. */
  uint64_t acc_uid;

  /* an identifier referencing the pshadow file-system */
  shpeer_t acc_peer;

  /** The public information for the REMOTE share account. */
  shauth_t acc_auth;
};
typedef struct tx_account_t tx_account_t;

struct tx_app_t 
{

  /** transaction reference of app instance */
  tx_t app_tx;

  /** application's peer identifier. */
  shpeer_t app_peer;
  /** application birth timestamp (remove me, in tx) */
  shtime_t app_birth;
  /** application 'last successful validation' time-stamp. */
  shtime_t app_stamp;
  /** A compact shnum_t indicating 'successful app validations' minus 'unsuccessful app validations' */
  uint64_t app_trust;
};
typedef struct tx_app_t tx_app_t; 

struct tx_init_t
{

  /** transaction reference of iniorization notification */
  tx_t ini_tx;

  uint64_t __reserved_1__;

  /** Machine byte-order directive. */
  uint32_t ini_endian;

  /** The network protocol version of this transaction. */
  uint32_t ini_ver;

  /* The sequence number of the handshake operation */
  uint32_t ini_seq;

  uint32_t __reserved_2__;

  /** A checksum hash of the initialization info */
  char ini_hash[MAX_SHARE_HASH_LENGTH];

  /** originating peer */
  shpeer_t ini_peer;

  /** time-stamp of when last connection was established. */
  shtime_t ini_stamp;

};
typedef struct tx_init_t tx_init_t;

/**
 * A ledger contains a list of transactions generated for a peer.
 */
struct tx_ledger_t
{
  /* a transaction representing of this ledger entry. */
  tx_t ledger_tx;
  /* the ledger entry with the preceding sequence number. */
  char parent_hash[MAX_SHARE_HASH_LENGTH];
  /** The root tx key of the ledger transactions. */
  shkey_t ledger_txkey;
  /** A signature validating a closed ledger. */
  shkey_t ledger_sig;
  /* the time-stamp of when the ledger was closed. */
  uint64_t ledger_stamp;
  /* the total fees of the combined transactions. */
  uint64_t ledger_fee;
  /* the numbers of ledger entries in this chain. */
  uint32_t ledger_seq;
  /* the number of transactions in this ledger entry. */
  uint32_t ledger_height;
  /* a block of @see tx_ledger_t.ledger_height transactions. */ 
  tx_t ledger[0];
};
typedef struct tx_ledger_t tx_ledger_t;


typedef struct tx_ward_t 
{
  /** unique transaction referencing the ward */
  tx_t ward_tx;

  /** The transaction [header] the ward is being applied to. */
  tx_t ref_tx;

  /** The app peer which the ward originated. */
  shpeer_t ward_peer;
  /** A key reference to the ward context (used to dissolve ward). */
  shsig_t ward_ctx;
  /** The key of the transaction the ward is being applied to. */
  shkey_t ward_ref;
  /** A context validation signature. */
  shkey_t ward_sig;
  /** The timestamp when the ward was assigned. */
  shtime_t ward_stamp;
  /** The timestamp when the ward will expire. */
  shtime_t ward_expire;
  /** The user identity of ward originator. */
  uint64_t ward_id;
} tx_ward_t;

/**
 * A auxillary context containing or referencing information.
 */
typedef struct tx_context_t 
{

  /* a unique context transaction */
  tx_t ctx_tx;

  /** The transaction key that the context is referencing. */
  shkey_t ctx_name;

  /** A reference to an auxillary entity. */
  shkey_t ctx_ref;

  /** A key reference to the context data. */
  shkey_t ctx_key;

  /** A key referencing the server that issued the context. */
  shkey_t ctx_peer;

  /** The geodetic location of the server that issued the context. */
  shgeo_t ctx_geo;

  /** The time-stamp at which the context expires. */
  shtime_t ctx_expire;

  /** A signature validating this transaction. */
  shkey_t ctx_sig;

  uint32_t __reserved_0__;

  uint32_t ctx_data_len;

  /** The data payload. */
  uint8_t ctx_data[MAX_CONTEXT_DATA_SIZE];

} tx_context_t;

typedef struct tx_ref_t
{

  /* a unique reference transaction */
  tx_t ref_tx;

  /** The underlying reference content. */
  shref_t ref;

  /** The time-stamp of when the reference was issued. */
  shtime_t ref_stamp;

  /** A key referencing the server which issued the reference. */
  shkey_t ref_peer;

  /** A signature validating the transaction. */
  shkey_t ref_sig;

} tx_ref_t;

typedef struct tx_event_t
{
  tx_t eve_tx;

  /** A contextual description of the event. */
  shkey_t eve_ctx;

  /** The key referencing the server which issued the event. */
  shkey_t eve_peer;

  /** The time-stamp of the event. */
  shtime_t eve_stamp;

  /** The physical location of the event. */
  shgeo_t eve_geo;

  /** A signature validating the transaction. */
  shkey_t eve_sig;
} tx_event_t;

/** A virtual coin channel. */
#define TXWALLET_CHANNEL 1

#define TXBOND_NONE 0
#define TXBOND_PENDING 10
#define TXBOND_CONFIRM 20
#define TXBOND_FINAL 30
#define TXBOND_SYNC 40
#define TXBOND_COMPLETE 50

#define BOND_CREDIT_VALUE(_value) \
  ( (double)(_value) * 0.00000001 )

/** The maximum character length of a coin identification label. */
#define MAX_COIN_LABEL_SIZE 8

typedef struct tx_bond_t
{
  /** unique transaction referencing the bond */
  tx_t bond_tx;
  
  /** Hash reference to currency destination. */
  char bond_sink[MAX_SHARE_HASH_LENGTH];
  /** supplementary comment */
  char bond_label[MAX_SHARE_NAME_LENGTH];
  /** A signature confirmation of the bond. */
  shkey_t bond_sig;
  /** When the bond was initiated. */
  shtime_t bond_stamp;
  /** When the bond matures. */
  shtime_t bond_expire;
  /** type of currency COIN_USDE, COIN_GMC, COIN_SYS */
  char bond_cur[MAX_COIN_LABEL_SIZE];
  /** currency amount value of bond. */
  uint64_t bond_credit;
  /** The accumulated confirmed credit value of bond. */
  uint64_t bond_value;
  /** The current state of the bond. */
  uint32_t bond_state;
  /** The interest rate described in 100th of a basis point. */
  uint32_t bond_basis;
  
} tx_bond_t;


struct tx_peer_t 
{
  
  /* a persistent transaction representing the peer. */
  tx_t peer_tx;

  /* the peer being referenced. */
  shpeer_t peer;

  /* the system-time of the originating server */
  shtime_t peer_stamp;
};
typedef struct tx_peer_t tx_peer_t;


#define SHMETRIC_NONE 0
#define SHMETRIC_CARD 1
#define SHMETRIC_ZTEX 2

struct tx_metric_t
{
  /** a persistent transaction representing the metric. */
  tx_t met_tx;

  /** The type of metric (SHMETRIC_XX). */
  uint32_t met_type;

  /** Type specific flags for the metric instance. */
  uint32_t met_flags; 

  /** A self-identifying sub-type of the metric. */
  char met_name[8];

  /** The time-stamp of when the metric expires. */
  shtime_t met_expire;

  /** The account being referenced. */
  uint64_t met_acc; 

  /*
   * A signature validating the metric instance.
   */ 
  shkey_t met_sig;
};
typedef struct tx_metric_t tx_metric_t;

struct tx_clock_t
{
  /** a unique transaction representing a clock metric. */
  tx_t clo_tx;
  /** The reciever's peer identifier */
  shkey_t clo_peer;
  /** The transaction initial server's current system time. */
  shtime_t clo_send;
  /** The transaction receiver's current system time. */
  shtime_t clo_recv;
  /** The running average absolute offset (compact shnum_t). */
  uint64_t clo_off;
  /** Time dispersion represents the accuracy or the maximum error (compact shnum_t). */
  uint64_t clo_disp;
  /** Time precision represents the implied discrepency or minimum error (compact shnum_t). */
  uint64_t clo_prec;
};
typedef struct tx_clock_t tx_clock_t;

struct tx_wallet_t
{
  tx_t wal_tx;

  /** The wallet's account name. */
  char wal_name[MAX_SHARE_HASH_LENGTH];

  /** The wallet's access key. */
  char wal_key[MAX_SHARE_HASH_LENGTH];

  /** The currency coin type that is being held in the wallet. */
  char wal_cur[MAX_COIN_LABEL_SIZE];

  /* origin channel key hash */
  shkey_t wal_origin; 

  /* peer channel key hash */
  shkey_t wal_peer;

  /* channel redeem script hash */
  shkey_t wal_redeem;

  /** The wallet's primary name and [recieving] public hash address. */
  shkey_t wal_ref;

  /* The sharenet identity associated with this wallet. */
  shkey_t wal_id;

  uint32_t wal_type;

  uint32_t __reserved_0__;

  /** The time-stamp of when the wallet transaction was initialized. */
  shtime_t wal_birth;

  /** The time-stamp of when the last wallet operation was performed. */
  shtime_t wal_stamp;

  /* A signature referencing the wallet access key. */
  shkey_t wal_sig;
};
typedef struct tx_wallet_t tx_wallet_t;


struct tx_contract_t
{
  tx_t con_tx;

#if 0
  shkey_t con_id;
  /** The ward releasing the ceded asset. */
  shkey_t con_ward;
  /** A currency value being offered. */
  shkey_t con_cede;
  /** The currency value desired in exchange. */
  shkey_t con_gain;
#endif
};
typedef struct tx_contract_t tx_contract_t;


/** A no-op operation. */
#define TXFILE_NONE 0
/** A binary data segment request operation. */
#define TXFILE_READ 1
/** A binary data segment transmission operation. */
#define TXFILE_WRITE 2
/** An inode container list operation. */
#define TXFILE_LIST 3
/** An inode link operaton. */
#define TXFILE_LINK 4
/** An inode unlink operation. */
#define TXFILE_UNLINK 5
/** An inode synchronization request operation. */
#define TXFILE_CHECKSUM 6
/** An inode operation indicating synchronized. */
#define TXFILE_SYNC 7
/** A transmission fee negotiation operation. */
#define TXFILE_FEE 8

#define CALC_TXFILE_FEE(_size, _create) \
  (double)(0.00000001 * (double)_size / shtimef(shtime() - _create))
#define NO_TXFILE_FEE(_value) \
  ((_value) < 0.00000001)

  

typedef struct tx_fileseg_t
{
} tx_fileseg_t;

typedef struct tx_file_t
{

  /** a transaction id for the file entity. */
  tx_t ino_tx;

  /** the absolute path of the file on the partition. */
  char ino_path[SHFS_PATH_MAX];

  /** The sharefs peer identity. */
  shpeer_t ino_peer;

  /** The shfs inode being referenced. */
  shkey_t ino_name;

  /** The shfs inode creation time. */
  shtime_t ino_ctime;

  /** The shfs inode last-modified time. */
  shtime_t ino_mtime;

  /** The shfs inode entire file checksum. */
  uint64_t ino_crc;

  /** The shfs inode entire file size. */
  uint64_t ino_size;

  /** The inode operation being requested. */
  uint32_t ino_op;

  uint32_t __reserved__0;

  /** A file operation data segment. */
  uint64_t seg_crc;
  uint64_t seg_of;
  uint64_t seg_len;
  char seg_data[0];
} tx_file_t;


struct tx_license_t
{
  /** Permanent transaction reference of this license. */
  tx_t lic_tx;
  /** The license being referenced. */
  shlic_t lic;
  /** The identity that the license is applicable for. */
  shkey_t lic_id;
  /** An external (u160 key reference to the certificate. */
  shkey_t lic_certref;
  /** An external (u160) key reference to the license. */
  shkey_t lic_ref;
};
typedef struct tx_license_t tx_license_t;

struct tx_device_t
{
  tx_t dev_tx;

  /* The X.500 distinguished name of the computing device being identified. */
  char dev_name[16];

  char dev_host[16];

  uint16_t dev_vendor;
  uint16_t dev_product;

  uint64_t dev_net[4];

};
typedef struct tx_device_t tx_device_t;

struct tx_host_t
{

  tx_t host_tx;

  char host_name[64];
  uint64_t host_net_of[4];
  uint64_t host_net_max[4];
  uint64_t host_mac[8];

  
};
typedef struct tx_host_t tx_host_t;

struct tx_asset_t
{
  /** Permanent transaction reference to this asset. */
  tx_t ass_tx;

  /** The underlying asset context. */
  shasset_t ass;

  /** Type of asset (TX_BOND, TX_TITLE, TX_LICENSE) */
  uint32_t ass_type;

  /** asset content byte size */
  uint32_t ass_size;

  /* asset content */
  unsigned char ass_data[0];
};
typedef struct tx_asset_t tx_asset_t;

/* The circuit is terminated by the device. */
#define SHLINK_TERMINATION_DEVICE (1 << 0)
/* The circuit is owner/operated by the organization or the service is provided by the software. */
#define SHLINK_SERVICE_PROVIDER (1 << 1) /* circuit/organization service/software */
/* The circuit ends at the network. */
#define SHLINK_NET_TERM_POINT (1 << 2)
/* The database or website is served by the service. */
#define SHLINK_SERVED_BY (1 << 3)
/* The software is installed on the computing device. */
#define SHLINK_ON_DEVICE (1 << 4)
/* The system is connected to the network. */
#define SHLINK_NET_CONNECTION (1 << 5)
/* The person or organization owns the IT asset. */
#define SHLINK_OWNER (1 << 6)
/* The person is the system administrator of the computing device or system. */
#define SHLINK_ADMINISTRATOR (1 << 7)
/* The person is in some way a part of the organization. */
#define SHLINK_INVOLVED (1 << 8)
/* The computing device or system is connected to the system. */
#define SHLINK_CONNECTION (1 << 9)

struct tx_link_t
{
  tx_t tx;
  int link_flag;
  shkey_t link_type; /* TX_XXX */
  shkey_t link_key;
  shkey_t link_ref;
};
typedef struct tx_link_t tx_link_t;


typedef struct tx_session_t
{
  /** Permanent transaction reference for this session. */
  tx_t sess_tx;

  /** The user id number of the identity */
  uint64_t sess_uid;

  /** The identity the session is authorized for. */
  shkey_t sess_id;

  /** Session's certificate token key. */
  shkey_t sess_key;

  /** When the session expires. */
  shtime_t sess_stamp;
} tx_session_t;

/**
 * An evaluation of a thing, place, and time by an identity.
 */
typedef struct tx_eval_t
{
  tx_t eval_tx;
  /** The event being evaluated. */
  shkey_t eval_eve;
  /** The contextual being evaluated. */
  shkey_t eval_ctx;
  /** The [event peer] identity of the evaluator. */
  shkey_t eval_id;
  /** The compact value indicator of the eval. */
  uint64_t eval_val;
  /** A signature validating the context. */
  shkey_t eval_sig;
} tx_eval_t;


/** A virtual 64-bit memory-address operation. */
struct tx_mem_t
{

  /** A transaction referencing with this memory address. */
  tx_t mem_tx;

  /** The destination thread of the memory address operation. */
  shkey_t mem_sink;

  /** The instruction memory operation being performed. (SEMEM_XX) */
  uint32_t mem_op;

  /** A status code for the memory operation. */
  uint32_t mem_status;

  /** The memory address's attributes. */
  sexe_mem_t mem;

  /** The content of the associated data payload. */
  unsigned char mem_data[0];
};
typedef struct tx_mem_t tx_mem_t;


#if 0
/**
 * A thread runs a pre-defined SEXE task as a vm runtime operation. 
 */
struct tx_thread_t
{

  /** The thread's unique transaction identifier. */
  tx_t th_tx;

  /** A unique id representing the thread. */
  shkey_t th_id;

  /** The privileged key of the app which initiated the task. */
  shpeer_t th_app;

  /** The time-stamp of when the thread was last executed. */
  shtime_t th_stamp;

  /** A proof-of-work signature. */
  shsig_t th_sig;

  /** The result code computed by the task. */
  tx_mem_t th_status;

  sexe_thread_t th;
};
typedef struct tx_thread_t tx_thread_t;

/**
 * A declaration of a runtime operation.
 */
struct tx_task_t
{

  /** A transaction representing this thread. */
  tx_t task_tx;

  /* the task operation to perform. */
  uint16_t task_op;

  /** The task's attributes. */
  sexe_task_t task;

};
typedef struct tx_task_t tx_task_t;

/** A network operation on a session's job. */
struct tx_job_t
{

  /** A transaction representing this thread. */
  tx_t job_tx;

  /** A status (error code) in reference to the job. */
  uint32_t job_status;

  /** The job operation being performed. */
  uint16_t job_op;

  /** The priveleged key of the app which initiated the task. */
  shpeer_t job_app;

  /** The job attributes. */
  sexe_job_t job;
};
typedef struct tx_job_t tx_job_t;
#endif

/** An execution runtime (thread) */
struct tx_run_t 
{

  /** The priveleged key of the app which initiated the task. */
  shpeer_t run_app;

  /** A key reference to the memory pool used by the runtime thread. */
  shkey_t run_pool;

  /** A key unique to the runtime execution. */
  shkey_t run_job;

  /** A proof-of-work signature. */
  shkey_t run_sig;

  /** The time-stamp of when execution started. */
  shtime_t run_birth;

  /** The time-stamp of when execution last ran. */
  shtime_t run_stamp;

  /** The expiration date to complete the task. */
  shtime_t run_expire;

  /** Runtime task mode. (SEM_XXX) */
  uint32_t run_mode;

  /* A SHERR_XX error code. */
  uint32_t run_state;

  uint32_t run_arch;
uint32_t __reserved;

};
typedef struct tx_run_t tx_run_t;



struct tx_vm_t
{

  /** A transaction representing this thread. */
  tx_t vm_tx;

  /** A key reference to a particular SEXE bytecode runtime stored as a sharefs device. */
  shkey_t vm_task;

  /** A session token authorizing access to the VM. */
  shkey_t vm_sess;

  /** Runtime execution capability version (compact shnum_t). */
  uint64_t vm_ver;

  /** A VM data operation. (SEOP_XXX) */
  uint32_t vm_op;

  uint32_t vm_arch;

  sexe_mod_t vm_data[0]; 
};
typedef struct tx_vm_t tx_vm_t;

#if 0
/** A vm session network operation. */
typedef struct tx_sess_t
{
  /** The persistent transaction referencing the 'vm session' instance. */
  tx_t sess_tx;
  /** The file containing the 64-bit shared mem address heap/data. */
  tx_file_t sess_heap;
  /** The session's attributes. */
  sexe_sess_t sess;
} tx_sess_t;
#endif

#if 0
/** A 'virtual machine' network operation. */
typedef struct tx_vm_t
{

  /** The persistent transaction referencing the 'virtual machine' instance. */
  tx_t vm_tx;
  /** The 'virtual machine' operation to perform. */
  uint32_t vm_op;
  /** The virtual machine's attributes. */
  sexe_vm_t vm;

} tx_vm_t;
#endif


#include "account.h"
#include "app.h"
#include "file.h"
#include "identity.h"
#include "ledger.h"
#include "schedule.h"
#include "signature.h"
#include "transaction.h"
#include "trust.h"
#include "ward.h"
#include "context.h"
#include "event.h"
#include "session.h"
#include "asset.h"
#include "init.h"
#include "metric.h"
#include "license.h"
#include "subscribe.h"
#include "reference.h"
#include "wallet.h"
#include "eval.h"
#include "vm.h"
#include "run.h"
#include "clock.h"



/** Convert a natural integral variable (short, int, long, etc) to network-byte order. */
#define WRAP_BYTES(_val) \
  (wrap_bytes(&(_val), sizeof(_val)))



int tx_init(shpeer_t *cli_peer, tx_t *tx, int tx_op);

int tx_confirm(shpeer_t *cli_peer, tx_t *tx);

int tx_send(shpeer_t *cli_peer, tx_t *tx);

int tx_recv(shpeer_t *cli_peer, tx_t *tx);



shkey_t *get_tx_key(tx_t *tx);
const char *get_tx_label(int tx_op);
void wrap_bytes(void *data, size_t data_len);
void unwrap_bytes(void *data, size_t data_len);

tx_t *get_tx_parent(tx_t *tx);
shkey_t *get_tx_key_root(tx_t *tx);

size_t get_tx_size(tx_t *tx);

int tx_save(void *raw_tx);

void *tx_load(int tx_op, shkey_t *tx_key);

void tx_wrap(shpeer_t *cli_peer, tx_t *tx);


/**
 * @}
 */

#endif /* ndef __BITS__BITS_H__ */

