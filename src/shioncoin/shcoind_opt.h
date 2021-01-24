
/*
 * @copyright
 *
 *  Copyright 2015 Brian Burrell
 *
 *  This file is part of Shioncoin.
 *  (https://github.com/neonatura/shioncoin)
 *        
 *  ShionCoin is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version. 
 *
 *  ShionCoin is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with ShionCoin.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  @endcopyright
 */  

#ifndef __SHCOIND_OPT_H__
#define __SHCOIND_OPT_H__

#ifdef __cplusplus
extern "C" {
#endif



#define OPT_DEBUG "debug"
#define OPT_NET_DEBUG "net-debug"
#define OPT_MAX_CONN "net-max"
#define OPT_PEER_SEED "seed"
#define OPT_NOTARY "notary"
#define OPT_ADMIN "admin"
#define OPT_FREE_RELAY "free-relay"
#define OPT_BAN_SPAN "ban-span"
#define OPT_BAN_THRESHOLD "ban-threshold"
#define OPT_SHC_PORT "shc-port"
#define OPT_SERV_STRATUM "stratum"
#define OPT_STRATUM_PORT "stratum-port"
#define OPT_STRATUM_WORK_CYCLE "stratum-work-cycle"
#define OPT_SERV_SHAPI "shapi"
#define OPT_SHAPI_PORT "shapi-port"
#define OPT_SHAPI_HOST "shapi-host"
#define OPT_SERV_RPC "rpc"
#define OPT_RPC_PORT "rpc-port"
#define OPT_RPC_HOST "rpc-host"
#define OPT_RPC_KEY "rpc-key"
#define OPT_SERV_TESTNET "testnet"
#define OPT_TESTNET_PORT "testnet-port"
#define OPT_SERV_EMC2 "emc2"
#define OPT_EMC2_PORT "emc2-port"
#define OPT_SHC_BACKUP_RESTORE "shc-backup-restore"
#define OPT_EMC2_BACKUP_RESTORE "emc2-backup-restore"
#define OPT_LTC_BACKUP_RESTORE "ltc-backup-restore"
#define OPT_BLOCK_SIZE "block-size"
#define OPT_MIN_FEE "min-fee"
#define OPT_BECH32 "bech32"

/* Stratum mining interfaces. */
#define OPT_STRATUM_TESTNET "stratum-testnet"
#define OPT_STRATUM_COLOR "stratum-color"

#define OPT_HDKEY "hdkey"
#define OPT_DILITHIUM "dilithium"

#define OPT_PARAM_TX "param-tx"

/* PoW Algorthm. */
#define OPT_STRATUM_SHA256D "stratum-sha256d"
#define OPT_STRATUM_SHA256D_PORT "stratum-sha256d-port"
#define OPT_STRATUM_KECCAK "stratum-keccak"
#define OPT_STRATUM_KECCAK_PORT "stratum-keccak-port"
#define OPT_STRATUM_X11 "stratum-x11"
#define OPT_STRATUM_X11_PORT "stratum-x11-port"
#define OPT_STRATUM_BLAKE2S "stratum-blake2s"
#define OPT_STRATUM_BLAKE2S_PORT "stratum-blake2s-port"
#define OPT_STRATUM_QUBIT "stratum-qubit"
#define OPT_STRATUM_QUBIT_PORT "stratum-qubit-port"
#define OPT_STRATUM_GROESTL "stratum-groestl"
#define OPT_STRATUM_GROESTL_PORT "stratum-groestl-port"
#define OPT_STRATUM_SKEIN "stratum-skein"
#define OPT_STRATUM_SKEIN_PORT "stratum-skein-port"


/* not used */
#define OPT_FMAP_IDLE "fmap-idle"
#define OPT_LOG_PATH "log-path"


void opt_init(void);

void opt_term(void);

int opt_num(const char *tag);

void opt_num_set(const char *tag, int num);

const char *opt_str(const char *tag);

void opt_str_set(const char *tag, char *str);

int opt_bool(const char *tag);

void opt_bool_set(const char *tag, int b);

const char *opt_usage_print(void);

void opt_arg_interp(int argc, char **argv);

const char *opt_config_default_print(void);

const char *get_shioncoin_path(void);


#ifdef __cplusplus
}
#endif


#endif /* ndef __SHCOIND_OPT_H__ */


