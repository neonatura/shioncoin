
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
#include "stratum/stratum.h"
#include <signal.h>
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#include <errno.h>

user_t *client_list;

extern int fShutdown;


void daemon_close_clients(void)
{
  user_t *user;

  for (user = client_list; user; user = user->next) {
    if (user->fd == -1)
      continue;
    shnet_close(user->fd);
    user->fd = -1;
  }

}


void shcoind_poll_msg_queue(void)
{
  tx_app_msg_t *app;
  tx_id_msg_t *dest_id;
  tx_id_msg_t *id;
  tx_session_msg_t *sess;
  tx_bond_msg_t *bond;
  struct in_addr in_addr;
  char host_buf[MAXHOSTNAMELEN+1];
  double amount;
  int tx_op;
  int err;

  shbuf_clear(server_msg_buff);
  err = shmsg_read(server_msgq, NULL, server_msg_buff);
  if (err)
    return;

  if (shbuf_size(server_msg_buff) < sizeof(uint32_t)) return;
  tx_op = *(uint32_t *)shbuf_data(server_msg_buff);

  switch (tx_op) {
    case TX_APP:
      shbuf_trim(server_msg_buff, sizeof(uint32_t));
      if (shbuf_size(server_msg_buff) < sizeof(tx_app_msg_t)) return;
      app = (tx_app_msg_t *)shbuf_data(server_msg_buff);

      /* shared is notifying about a remote application */
      if (0 == strcmp(app->app_peer.label, "shc")) {
        unet_peer_incr(UNET_SHC, &app->app_peer);
      } else if (0 == strcmp(app->app_peer.label, "usde")) {
        unet_peer_incr(UNET_USDE, &app->app_peer);
      } else if (0 == strcmp(app->app_peer.label, "emc2")) {
        unet_peer_incr(UNET_EMC2, &app->app_peer);
      }
      break;


#if 0
    case TX_SESSION:
      shbuf_trim(server_msg_buff, sizeof(uint32_t));
      if (shbuf_size(server_msg_buff) < sizeof(tx_id_msg_t)) return;
      sess = (tx_session_msg_t *)shbuf_data(server_msg_buff);

      id = (tx_ident_msg_t *)pstore_load(TX_IDENT, &sess->sess_id);
      if (!id)
        break;

      /* store session expiration & key for account. */
/* .. */

      if (*id->id_label) {
        /* send server wallet info */
        send_wallet_tx(&sess->sess_id,
            getaddressbyaccount(id->id_label),
            getaccountbalance(id->id_label));
      }
      break;
      
    case TX_BOND:
      shbuf_trim(server_msg_buff, sizeof(uint32_t));
      if (shbuf_size(server_msg_buff) < sizeof(tx_bond_msg_t)) return;
      bond = (tx_bond_msg_t *)shbuf_data(server_msg_buff);

      switch (bond->bond_state) {
        case TX_BOND_TRANSMIT:
//p_bond = ... if (!= PENDING) break
          /* currency xfer request */ 
          sess = (tx_session_msg_t *)pstore_load(TX_SESSION, &bond->bond_sess); 
          if (!sess || sess->sess_expire < shtime64()) {
            send_bond_tx(bond, TX_BONDERR_SESS);
            break;
          }

          id = (tx_ident_msg_t *)pstore_load(TX_IDENT, &sess->sess_id);
          dest_id = (tx_ident_msg_t *)pstore_load(TX_IDENT, &bond->bond_id);
          if (!id || !dest_id)
            break;

          amount = (double)bond->bond_credit / (double)COIN;
          err = wallet_account_transfer(id->id_label, dest_id->id_label, bond->bond_label, amount);
          if (!err) {
            send_bond_tx(bond, TX_BOND_CONFIRM);
            /* send updated server wallet info */
            send_wallet_tx(&sess->sess_id,
                getaddressbyaccount(id->id_label),
                getaccountbalance(id->id_label));
          } else {
            if (err == -5) {
              send_bond_tx(bond, TX_BONDERR_ADDR);
            } else if (err == -3 || err == -6) {
              send_bond_tx(bond, TX_BONDERR_DEBIT);
            } else if (err == -13) {
              send_bond_tx(bond, TX_BOND_CONFIRM); /* retry */
            } else {
              send_bond_tx(bond, TX_BONDERR_NET);
            }
          }
          break;
      }
      break;
#endif

    default:
      break;
  }

}



#define RUN_NONE 0
#define RUN_CYCLE 1
#define RUN_SHUTDOWN 2
#define RUN_RESTART 3 /* not used */

extern void bc_chain_idle(void);


void daemon_server(void)
{
  int run_mode;

  run_mode = RUN_CYCLE;
  while (run_mode != RUN_SHUTDOWN) {
    if (_shutdown_timer == 1) {
      printf("info: shcoind daemon shutting down.\n");
      run_mode = RUN_SHUTDOWN;
    } else if (_shutdown_timer > 1) {
      _shutdown_timer--;
    }

    /* handle network communication. */
    unet_cycle(0.2); /* max idle 200ms */

    bc_chain_idle();

    /* handle libshare message queue */
    shcoind_poll_msg_queue();

#if 0
#ifdef RPC_SERVICE
    /* handle RPC communication */
    RPC_CycleConnections();
#endif
#endif

    if (fShutdown && !_shutdown_timer) {
      set_shutdown_timer();
    }
  }

  shcoind_term(); 
}


