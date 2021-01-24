
/*
 *  Copyright 2013 Neo Natura
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
 */  

#include "sharetool.h"



info_table_t *info_table_init(void)
{
  info_table_t *table;

  table = (info_table_t *)calloc(1, sizeof(info_table_t));
  return (table);
}

int info_table_column(info_table_t *table, char *col_name)
{
  char label[8];
  int i;

  memset(label, 0, sizeof(label));
  strncpy(label, col_name, sizeof(label) - 1);
  for (i = 0; i < strlen(label); i++)
    label[i] = toupper(label[i]);

  for (i = 0; i < MAX_TABLE_COLUMNS; i++) {
    if (!table->label[i] || 0 == strcmp(table->label[i], label))
      break;
  }
  if (i == MAX_TABLE_COLUMNS)
    return (-1);

  if (!table->label[i])
    table->label[i] = strdup(label);

  return (i);
}

void info_table_add_row(info_table_t *table, char *row_name, shtime_t stamp)
{
  info_table_row_t *row;
  int idx;
  
  /* allocate a new row */
  row = (info_table_row_t *)calloc(1, sizeof(info_table_row_t));
  if (table->row)
    table->row->next = row;
  table->row = row;
  if (!table->row_head)
    table->row_head = row;

  idx = info_table_column(table, "TYPE");
  if (idx != -1)
    table->row->col[idx] = strdup(row_name);

  if (stamp) {
    idx = info_table_column(table, "TIME");
    if (idx != -1)
      table->row->col[idx] = strdup(shstrtime(stamp, NULL));
  }

}

void info_table_add_str(info_table_t *table, char *col_name, char *str)
{
  int idx;
  
  if (!str || !*str)
    return;

  idx = info_table_column(table, col_name);
  if (idx != -1)
    table->row->col[idx] = strdup(str);
}

void info_table_add_int(info_table_t *table, char *col_name, int val)
{
  char buf[256];
  int idx;
  
  if (!val)
    return;

  if (!(run_flags & PFLAG_VERBOSE))
    return;

  sprintf(buf, "%u", (unsigned)val);
  idx = info_table_column(table, col_name);
  if (idx != -1)
    table->row->col[idx] = strdup(buf);
}

void info_table_add_key(info_table_t *table, char *col_name, shkey_t *key)
{
  int idx;

  if (!key || shkey_cmp(ashkey_blank(), key))
    return;

  if (!(run_flags & PFLAG_VERBOSE))
    return;

  idx = info_table_column(table, col_name);
  if (idx != -1)
    table->row->col[idx] = strdup(shkey_print(key));
}

void info_table_add_peer(info_table_t *table, char *col_name, shpeer_t *peer)
{
  struct in_addr in_addr;
  int pid;

  if (!peer)
    return;

  info_table_add_str(table, "APP", peer->label);
  info_table_add_str(table, "GROUP", peer->group);
  info_table_add_key(table, "TOKEN", shpeer_kpub(peer));
  info_table_add_key(table, "PRIV", shpeer_kpriv(peer));

  if (peer->type == SHNET_PEER_IPV4 &&
      peer->addr.sin_port) {
    info_table_add_int(table, "PORT", ntohs(peer->addr.sin_port));
  }

#if 0
  if (run_flags & PFLAG_VERBOSE) {
    if (peer->arch & SHARCH_LINUX && peer->arch & SHARCH_32BIT)
      info_table_add_str(table, "ARCH", "LIN32");
    else if (peer->arch & SHARCH_WIN && peer->arch & SHARCH_32BIT)
      info_table_add_str(table, "ARCH", "WIN32");
    else if (peer->arch & SHARCH_LINUX)
      info_table_add_str(table, "ARCH", "LIN");
    else if (peer->arch & SHARCH_WIN)
      info_table_add_str(table, "ARCH", "WIN");
  }
#endif

  pid = share_appinfo_pid(peer->label);
  info_table_add_int(table, "PID", pid);
}

void info_table_print(info_table_t *table, FILE *fout)
{
  info_table_row_t *row;
  int dim;
  int cols;
  int col;
  int len;

  for (cols = 0; table->label[cols] && cols < MAX_TABLE_COLUMNS; cols++);
  if (cols == 0)
    return;

  dim = MAX(9, (79 / cols));
  dim--; /* seperator */

  /* print header */
  for (col = 0; col < cols; col++) {
    fprintf(fout, "%-*.*s ", dim, dim, table->label[col]);
  }
  fprintf(fout, "\n");

  for (row = table->row_head; row; row = row->next) {
    for (col = 0; col < cols; col++) {
      if (!row->col[col]) {
        fprintf(fout, "%-*.*s ", dim, dim, ""); 
        continue;
      }

      len = strlen(row->col[col]);
      if (len > (dim*3)) {
        char prefix[256];
        char suffix[256];
        int of;

        of = dim/2-1;
        memset(prefix, 0, sizeof(prefix));
        memset(suffix, 0, sizeof(suffix));
        strncpy(prefix, row->col[col], of);
        strncpy(suffix, row->col[col] + len - of, of);
        fprintf(fout, "%s..%s ", prefix, suffix);
        continue;
      }
      if (len > dim) {
        fprintf(fout, "%-*.*s ", dim, dim,
            row->col[col] + len - dim);
        continue;
      }
      fprintf(fout, "%-*.*s ", dim, dim, row->col[col]);
    }
    fprintf(fout, "\n");
  }

  fprintf(fout, "\n");

}

