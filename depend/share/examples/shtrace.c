
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

#include <stdio.h>
#include <string.h>

#include "config.h"
#include "share.h"
#include "bits.h"

#define SHARE_DAEMON_PORT 32080

char prog_name[PATH_MAX+1];

/**
 * Displays the program's version information to the command console.
 */
void program_version(void)
{
  printf ("%s version %s (%s)\n"
      "\n"
      "Copyright 2014 Neo Natura\n"
      "Licensed under the GNU GENERAL PUBLIC LICENSE Version 3\n"
      "Visit 'https://github.com/neonatura/share' for more information.\n",
      prog_name, PACKAGE_VERSION, PACKAGE_NAME);
}

/**
 * Displays the program's usage information to the command console.
 */
void program_usage(void)
{
  printf (
    "%s version %s (%s)\n"
    "usage: shtrace host[:port]\n"
    "\n"
    "Example of the share daemon messaging protocol.\n"
    "\n"
    "Visit 'https://github.com/neonatura/share' for more information.\n",
    prog_name, PACKAGE_VERSION, PACKAGE_NAME, prog_name);
}

int print_serv_tx(tx_t *tx, char *name)
{
  printf(
    "TX [%s] %s"
    "\thash: %s\n"
    "\tpeer key: %s\n"
    "\tnonce:%d\n",
    name, shctime(tx->tx_stamp), 
    tx->hash, shkey_print(&tx->tx_peer),
    tx->nonce); 
}

int print_serv_trust(tx_trust_t *trust)
{
  char id_key[256];
  char peer_key[256];
  char key[256];

  strcpy(id_key, shkey_print(&trust->trust_context));
  strcpy(peer_key, shkey_print(&trust->trust_peer));

  printf(
    "TRUST %s"
    "\tcontext key: %s\n"
    "\tpeer key: %s\n",
    shctime(trust->trust_tx.tx_stamp),
    id_key, peer_key);

  print_serv_tx(&trust->trust_tx, "TRUST");

  return (0);
}

void print_serv_id(tx_id_t *id, char *name)
{
  char pub_key[256];
  char priv_key[256];

  strcpy(pub_key, shkey_print(&id->id_key));
  //strcpy(priv_key, shkey_print(&id->id_sig.sig_key));

  print_serv_tx(&id->id_tx, "IDENT");
  printf(
    "ID [%s]"
    "\tpub key: %s\n"
    "\tpriv key: %s\n",
    name, 
    pub_key, priv_key);

}

void print_serv_ward(tx_ward_t *ward)
{
  printf("WARD %s",
    shctime(ward->ward_stamp));
  print_serv_tx(&ward->ward_tx, "WARD");
  print_serv_id(&ward->ward_id, "WARD");
}

void print_serv_file(tx_file_t *file)
{

  printf(
    "FILE %s\n"
    "\tfs peer: %s\n"
    "\tfile op: %d\n",
    "\tdata size: %u\n",
    "\tdata offset: %u\n"
    "\tdata crc: %llu\n",
    shstrtime(file->ino_stamp, NULL),
    shpeer_print(&file->ino_peer),
    file->ino_op, file->ino_size, file->ino_of,
    shcrc((char *)file->ino_data, file->ino_size));
  printf(
      "\tfile info: size(%llu) crc(%llu) mtime(%s)",
      file->ino.pos.jno, file->ino.pos.ino,
      file->ino.size, file->ino.crc,
      shstrtime(file->ino.mtime, NULL));
  print_serv_tx(&file->ino_tx, "FILE");

}

void print_serv_app(tx_app_t *app)
{
  char app_name[256];
  char app_sig[256];

  strcpy(app_name, shkey_hex(shpeer_kpub(&app->app_peer)));
  strcpy(app_sig, shkey_hex(&app->app_sig));

  printf(
    "APP %s"
    "\tarch %d\n"
    "\tpub key %s\n"
    "\tsig key %s\n",
    shctime(app->app_stamp),
    app->app_arch,
    app_name, app_sig);

  print_serv_tx(&app->app_tx, "APP");
}
int recv_serv_msg(shbuf_t *buff)
{
  tx_ledger_t *ledger;
  tx_peer_t *peer;
  tx_file_t *file;
  tx_ward_t *ward;
  tx_t *tx;
  tx_t *tx_list;
  tx_id_t *id;
  int i;

  if (shbuf_size(buff) < sizeof(tx_t))
    return (0);

  tx = (tx_t *)shbuf_data(buff);

  switch (tx->tx_op) {
    case TX_APP:
      if (shbuf_size(buff) < sizeof(tx_app_t))
        break;

      shbuf_trim(buff, sizeof(tx_app_t));
      print_serv_tx(tx, "APP");
      print_serv_app((tx_app_t *)shbuf_data(buff));
      break;

    case TX_IDENT:
      if (shbuf_size(buff) < sizeof(tx_id_t))
        break;

      id = (tx_id_t *)shbuf_data(buff);
      shbuf_trim(buff, sizeof(tx_id_t));

      print_serv_tx(tx, "IDENT");
      print_serv_id(id, "IDENT");
      break;

    case TX_SESSION:
      if (shbuf_size(buff) < sizeof(tx_session_t))
        break;

      print_serv_tx(tx, "SESSION");
      break;

#if 0
    case TX_PEER:
      if (shbuf_size(buff) < sizeof(tx_peer_t))
        break;

      peer = (tx_peer_t *)shbuf_data(buff);
      shbuf_trim(buff, sizeof(tx_peer_t));

      print_serv_tx(tx, "PEER");
      printf("PEER %s\n", shpeer_print(&peer->peer));
      break;
#endif

    case TX_FILE:
      if (shbuf_size(buff) < sizeof(tx_file_t))
        break;

      file = (tx_file_t *)shbuf_data(buff);
      shbuf_trim(buff, sizeof(tx_file_t));

      print_serv_tx(tx, "FILE");
      print_serv_file((tx_file_t *)shbuf_data(buff));
      break;

    case TX_ACCOUNT:
      if (shbuf_size(buff) < sizeof(tx_account_t))
        break;

      print_serv_tx(tx, "ACCOUNT");
      shbuf_trim(buff, sizeof(tx_account_t));
      break;

    case TX_WARD:
      if (shbuf_size(buff) < sizeof(tx_ward_t))
        break;

      ward = (tx_ward_t *)shbuf_data(buff);
      shbuf_trim(buff, sizeof(tx_ward_t));

      print_serv_tx(tx, "TX");
      print_serv_ward((tx_ward_t *)shbuf_data(buff));
      break;

    case TX_LEDGER:
      if (shbuf_size(buff) < sizeof(tx_ledger_t))
        break;

      ledger = (tx_ledger_t *)shbuf_data(buff);
      shbuf_trim(buff, sizeof(tx_ledger_t) + 
          sizeof(tx_t) * ledger->ledger_height);

      print_serv_tx(tx, "LEDGER");
      tx_list = (tx_t *)ledger->ledger;
      for (i = 0; i < ledger->ledger_height; i++)
        print_serv_tx(&tx_list[i], "LEDGER-TX");
      break;

    case TX_TRUST:
      if (shbuf_size(buff) < sizeof(tx_trust_t))
        break;

      shbuf_trim(buff, sizeof(tx_trust_t));
      print_serv_tx(tx, "TRUST");
      print_serv_trust((tx_trust_t *)shbuf_data(buff));
      break;

    default:
      printf("SHTRACE: unknown tx operation '%d'.\n", tx->tx_op);
      shbuf_clear(buff);
      return (0);
  }

  printf ("\n");
  return (1);
}

int main(int argc, char **argv)
{
  char hostname[MAXHOSTNAMELEN+1];
  shbuf_t *buff;
  int port;
  int err;
  int sk;
  int i;

  strcpy(prog_name, argv[0]);

  port = SHARE_DAEMON_PORT;
  strcpy(hostname, "127.0.0.1");

  sk = shconnect_host(hostname, port, FALSE);
  if (sk < 0) {
    perror("shnet_conn");
    exit(1);
  }

  while ((buff = shnet_read_buf(sk))) {
    while (1 == recv_serv_msg(buff));
  }

  shnet_close(sk);
}


