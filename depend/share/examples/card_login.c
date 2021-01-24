
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

#include <stdio.h>
#include <string.h>

#include "config.h"
#include "share.h"
#include "bits.h"

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
    "usage: card_login\n"
    "\n"
    "Example of utilizing the TX_METRIC transaction.\n"
    "\n"
    "Visit 'http://www.sharelib.net/' for more information.\n",
    prog_name, PACKAGE_VERSION, PACKAGE_NAME, prog_name);
}

int validate_metric(char *acc_name, tx_metric_msg_t *met)
{
  char rname[MAX_SHARE_NAME_LENGTH];
  char *ptr;

  ptr = strchr(acc_name, ' ');
  if (!ptr) 
    ptr = acc_name;
  else
    ptr++;
  memset(rname, 0, sizeof(rname));
  strncpy(rname, ptr, strlen(ptr));

  printf ("METRIC[%s] "
      "FLAGS:%d "
      "TYPE:\"%-8.8s\" "
      "EXPIRE:%s "
      "ACC:%llu\n",
      met->met_type == SHMETRIC_CARD ? "CARD" : "<n/a>",
      met->met_flags, met->met_name, 
      shctime(met->met_expire), met->met_acc);

  if (met->met_acc == shpam_uid(rname)) {
    /* real name UID matches card's listed name. */
    return (0);
  }

  return (SHERR_ACCESS);
}

/**
 * Poll the server message queue for a TX_METRIC notification.
 */
int metric_poll(void)
{
  static int _auth_msgqid;
  shbuf_t *buff;
  tx_metric_msg_t *met;
  char acc_name[MAX_SHARE_NAME_LENGTH];
  int cnt;
  int err;

  if (!_auth_msgqid)
    _auth_msgqid = shmsgget(NULL);

  memset(acc_name, 0, sizeof(acc_name));
  strncpy(acc_name, get_libshare_account_name(), sizeof(acc_name)-1);
  printf ("Account: \"%s\"\n", acc_name);
  printf ("Swipe an identification or credit card.");

  cnt = 0;
  buff = shbuf_init();
retry:
  while ((err = shmsg_read(_auth_msgqid, NULL, buff))) {
    cnt++;
    if (cnt > 60)
      break;
    sleep(1);

    printf(".");
    fflush(stdout);
  }
  if (!err) {
    unsigned char *data = shbuf_data(buff);
    uint32_t mode = *((uint32_t *)data);

    switch (mode) {
      case TX_METRIC:
        met = (tx_metric_msg_t *)(data + sizeof(uint32_t));
        err = validate_metric(acc_name, met);
        break;
      default:
        shbuf_clear(buff);
        goto retry;
    }
  }
  shbuf_free(&buff);

  return (err);
}

int main(int argc, char *argv[])
{
  char *app_name;
  shpeer_t *app_peer;
  shpeer_t *serv_peer;
  int err;
  int i;

  app_name = shfs_app_name(argv[0]);
  strncpy(prog_name, app_name, sizeof(prog_name));
  for (i = 0; i < argc; i++) {
    if (0 == strcmp(argv[i], "-v") ||
        0 == strcmp(argv[i], "--version")) {
      program_version();
      return (0);
    }
    if (0 == strcmp(argv[i], "-h") ||
        0 == strcmp(argv[i], "--help")) {
      program_usage();
      return (0);
    }
  }

  app_peer = shapp_init(app_name, NULL, 0);

  /* request notification of TX_LEDGER from server */
  shapp_listen(TX_METRIC, app_peer);

  err = metric_poll();
  if (!err) {
    fprintf(stderr, "card read success -- login user authenticated.\n");
  } else {
    fprintf(stderr, "card read failure: %s\n", sherrstr(err));
  }

  shpeer_free(&app_peer);
  return (0);
}


