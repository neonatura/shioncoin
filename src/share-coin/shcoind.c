
/*
 * @copyright
 *
 *  Copyright 2014 Neo Natura
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

#include "shcoind.h"
#include <signal.h>
#include <stratum/stratum.h>

shpeer_t *server_peer;
int server_msgq;
shbuf_t *server_msg_buff;
shtime_t server_start_t;

static int opt_no_fork;
static int opt_restore;

extern bc_t *GetBlockChain(CIface *iface);
extern void opt_print(void);
extern void server_shutdown(void);
extern void TERM_SECP256K1(void);

void shcoind_term(void)
{
  int idx;

  for (idx = 1; idx < MAX_UNET_MODES; idx++) {
    unet_unbind(idx);
  }

  shpeer_free(&server_peer);
  shbuf_free(&server_msg_buff);

  server_shutdown();

  /* de-allocate libsecp256k1 */
  TERM_SECP256K1();

  /* de-allocation options */
  opt_term();

}

void usage_help(void)
{
  fprintf(stdout,
      "Usage: shcoind [OPTIONS]\n"
      "Virtual currency daemon for the Share Library Suite.\n"
      "\n"
#ifdef WINDOWS
      "Service Options:\n"
      "--install\tInstall the Share Coin service.\n"
      "--remove\tRemove the Share Coin service.\n"
      "\n"
#endif
      "Configuration Options:\n"
			);

	/* configurable runtime options */
  fprintf(stdout, "%s", opt_usage_print());

  fprintf(stdout,
      "\n"
      "Diagnostic Options:\n"
      "\t-nf\n"
			"\t\tRun daemon in foreground (no fork).\n"
      "\n"
      "\t--check-addr\n"
			"\t\tRe-verify this machine's external IP address.\n"
      "\n"
      "\t--shc-rebuild-chain\n"
			"\t\tRestore the backup SHC block-chain.\n"
#ifdef USDE_SERVICE
      "\n"
      "\t--usde-rebuild-chain\n"
			"\t\tRestore the backup USDE block-chain.\n"
#endif
#ifdef EMC2_SERVICE
      "\n"
      "\t--emc2-rebuild-chain\n"
			"\t\tRestore the backup EMC2 block-chain.\n"
#endif
      "\n"
      "Configuration Datafile:\n"
			"\tPersistently set configuration options in \"%s/.shc/shc.conf\":\n"
			"\n"
			"\tFor example:\n"
			"\t\t# shc.conf\n"
			"\t\tdebug=1\n"
			"\t\tmax-conn=300\n"
			"\t\trpc-host=127.0.0.1\n"
      "\n"
      "Persistent Preferences:\n"
      "\tRun \"shpref shcoind.<name> <value>\" to permanently apply configuration options. The \"shpref\" utility program is installed with the share library suite.\n"
			"\n"
			"\tFor example:\n"
			"\t\tshpref shcoind.debug true\n"
			"\t\tshpref shcoind.max-conn 300\n"
			"\t\tshpref shcoind.rpc-host 127.0.0.1\n"
			"\n"
			"Note: Configuration datafile options will over-ride \"shpref\" set options.\n"
			"\n"
      "Visit 'https://shcoins.com/' for additional information.\n"
      "Report bugs to <support@neo-natura.com>.\n",
#ifdef WINDOWS
		getenv("HOMEPATH")
#else
		getenv("HOME")
#endif
      );
//      "\t--rescan\t\tRescan blocks for missing wallet transactions.\n"
}
void usage_version(void)
{
  fprintf(stdout,
      "shcoind version %s\n"
      "\n"
      "Copyright 2013 Neo Natura\n" 
      "Licensed under the GNU GENERAL PUBLIC LICENSE Version 3\n",
      get_libshare_version());
}

extern void RegisterRPCOpDefaults(int ifaceIndex);

static void unlink_chain(void)
{
/* move *.idx, *.tab, and *.# to a "archive/" sub-directory. */
}

int shcoind_main(int argc, char *argv[])
{
  CIface *iface;
  bc_t *bc;
  char buf[1024];
  int idx;
  int fd;
  int err;
  int i;

  if (argc >= 2 &&
      (0 == strcmp(argv[1], "-h") ||
       0 == strcmp(argv[1], "--help"))) {
    usage_help();
    return (0);
  }
  if (argc >= 2 &&
      (0 == strcmp(argv[1], "-v") ||
       0 == strcmp(argv[1], "--version"))) {
    usage_version();
    return (0);
  }

  server_start_t = shtime();

#if WINDOWS 
  /* quash stdin/stdout confusion for windows service. */
  (void)open(".tmp-1", O_RDWR | O_CREAT, 0777);
  (void)open(".tmp-2", O_RDWR | O_CREAT, 0777);
  (void)open(".tmp-3", O_RDWR | O_CREAT, 0777);
#endif

  /* initialize options */
  opt_init();

  /* always perform 'fresh' tx rescan */

	/* process configuration options from command-line arguments. */
	opt_arg_interp(argc, argv);

	/* process special flags */
  for (i = 1; i < argc; i++) {
    if (0 == strcmp(argv[i], "-nf")) {
      opt_no_fork = TRUE;
    } else if (0 == strcmp(argv[i], "--check-addr")) {
      shpref_set("shcoind.net.addr.stamp", "0"); /* clear cached IP addr */
    } else if (0 == strcmp(argv[i], "--shc-rebuild-chain")) {
      opt_bool_set(OPT_SHC_BACKUP_RESTORE, TRUE);
      opt_restore = TRUE;
    } else if (0 == strcmp(argv[i], "--usde-rebuild-chain")) {
      opt_bool_set(OPT_USDE_BACKUP_RESTORE, TRUE);
      opt_restore = TRUE;
    } else if (0 == strcmp(argv[i], "--emc2-rebuild-chain")) {
      opt_bool_set(OPT_EMC2_BACKUP_RESTORE, TRUE);
      opt_restore = TRUE;
    }
  }

#ifndef WINDOWS
  if (!opt_no_fork && !opt_restore)
    daemon(0, 1);
#endif

  /* process signal handling */
  shcoind_signal_init();

  /* initialize libsecp256k1 */
  INIT_SECP256K1();

  /* initialize libshare */
  server_peer = shapp_init("shcoind", "127.0.0.1:9448", 0);
  server_msgq = shmsgget(NULL); /* shared server msg-queue */
  server_msg_buff = shbuf_init();

  if (opt_bool(OPT_DEBUG))
    opt_print();

  shapp_listen(TX_APP, server_peer);
  shapp_listen(TX_IDENT, server_peer);
  shapp_listen(TX_SESSION, server_peer);
  shapp_listen(TX_BOND, server_peer);

  if (opt_restore) {
    unlink_chain();
  }

  /* initialize coin interface's block-chain */
  for (idx = 1; idx < MAX_COIN_IFACE; idx++) {
    CIface *iface = GetCoinByIndex(idx);
    if (!iface || !iface->enabled)
      continue;

    if (idx == USDE_COIN_IFACE) {
#ifndef USDE_SERVICE
      iface->enabled = FALSE;
#endif
      if (!opt_bool(OPT_SERV_USDE))
        iface->enabled = FALSE;
    }
    if (idx == EMC2_COIN_IFACE) {
#ifndef EMC2_SERVICE
      iface->enabled = FALSE;
#endif
      if (!opt_bool(OPT_SERV_EMC2))
        iface->enabled = FALSE;
    }
    if (idx == TESTNET_COIN_IFACE) {
#ifndef TESTNET_SERVICE
      iface->enabled = FALSE;
#endif
			if (!opt_bool(OPT_SERV_TESTNET))
				iface->enabled = FALSE;
		}
    if (!iface->enabled)
      continue;

    if (iface->op_init) {
      err = iface->op_init(iface, NULL);
      if (err) {
        fprintf(stderr, "critical: unable to initialize %s service (%s).", iface->name, sherrstr(err));
        exit(1);
      }
    }

    bc_chain_idle();
  }

  if (opt_restore) {
    printf ("The block-chain has been restored.");
    server_shutdown();
    TERM_SECP256K1();
    opt_term();
    return (0);
  }

  /* initialize coin interface's network service */
  for (idx = 1; idx < MAX_COIN_IFACE; idx++) {
    CIface *iface = GetCoinByIndex(idx);
    if (!iface || !iface->enabled)
      continue;

    if (iface->op_bind) {
      err = iface->op_bind(iface, NULL);
      if (err) {
        fprintf(stderr, "critical: unable to bind %s service (%s).", iface->name, sherrstr(err));
        exit(1);
      }
    }
  }

#ifdef STRATUM_SERVICE
  if (opt_bool(OPT_SERV_STRATUM)) {
    /* initialize stratum server */
    err = stratum_init();
    if (err) {
			unet_log(UNET_STRATUM, "critical: error binding RPC port.");
      raise(SIGTERM);
    }
  }
#endif

#ifdef RPC_SERVICE
  if (opt_bool(OPT_SERV_RPC)) {
    /* initialize rpc server */
    err = rpc_init();
    if (err) {
			char buf[256];
			unet_log(UNET_RPC, "critical: error binding RPC port.");
      raise(SIGTERM);
    }
  }
#endif

  start_node();

  /* unet_cycle() */
  daemon_server();

  return (0);
}

#ifndef WINDOWS
int main(int argc, char *argv[])
{
  return (shcoind_main(argc, argv));
}
#endif

shpeer_t *shcoind_peer(void)
{
  return (server_peer);
}
