
/*
 *  Copyright 2017 Neo Natura
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

#include "share.h"

extern shkey_t _shmem_key;



static void shctx_table_init(shdb_t *db, char *table)
{

  if (0 != shdb_table_new(db, table))
    return;

  shdb_col_new(db, table, "name");
  shdb_col_new(db, table, "value");
  shdb_col_new(db, table, "stamp");
  shdb_col_new(db, table, "expire");
  shdb_col_new(db, table, "issuer");

}

shdb_t *shctx_open(void)
{
  shdb_t *db;
  shpeer_t *peer;

  peer = shpeer_init(NULL, NULL); /* "libshare" partition */
  db = shdb_open_peer(SHCTX_DATABASE_NAME, peer);
  shpeer_free(&peer);
  if (!db)
    return (NULL);

  shctx_table_init(db, SHCTX_TABLE_COMMON);

  return (db);
}

static int shctx_ctx_sql_cb(void *p, int arg_nr, char **args, char **cols)
{
  shctx_t *value_p = (shctx_t *)p;
  char q_name[MAX_SHARE_HASH_LENGTH];
  shkey_t *key;
  int err;

  if (arg_nr != 5)
    return (0);

  memset(value_p, 0, sizeof(shctx_t));

  memset(q_name, 0, sizeof(q_name));
  if (args[0]) { 
    strncpy(q_name, args[0], sizeof(q_name)-1);
  }
  key = shkey_shr160_gen(args[0]);
  if (!key)
    return (0); /* silent error */
  memcpy(&value_p->ctx_key, key, sizeof(shkey_t)); 
  shkey_free(&key);

  if (args[1]) {
    err = shdecode_b64(args[1], 
        &value_p->ctx_data, &value_p->ctx_data_len, &value_p->ctx_key);
  }

  if (args[2])
    value_p->ctx_stamp = shtime_adj(0, atof(args[2]));

  if (args[3])
    value_p->ctx_expire = shtime_adj(0, atof(args[3]));

  if (args[4])
    strncpy(value_p->ctx_iss, args[4], sizeof(value_p->ctx_iss)-1);


  return (0);
}

static inline void _lowercase_string(char *text)
{
  int len = strlen(text);
  int i;

  for (i = 0; i < len; i++) {
    if (isalpha(text[i]))
      text[i] = tolower(text[i]);
  }
}



shkey_t *shctx_key(char *name)
{
  char *key_name;
  size_t key_len;
  
  key_name = (char *)calloc(strlen(name) + 32, sizeof(char));
  if (!key_name)
    return (NULL);

  memset(&_shmem_key, 0, sizeof(_shmem_key));
  key_len = MAX(16, strlen(name));

  if (name)
    strcpy(key_name, name);
  _lowercase_string(key_name);

  memset(&_shmem_key, 0, sizeof(_shmem_key));
  shkey_shr160_hash(&_shmem_key, key_name, key_len);
  free(key_name);

  return (&_shmem_key);
}

char *shctx_key_print(char *name)
{
  return (shkey_shr160_print(shctx_key(name)));
}

int shctx_rowid(shdb_t *db, const char *table, char *name_key, shdb_idx_t *rowid_p)
{
  char sql_str[1024];
  shnum_t lat, lon;
  char *ret_str;
  int err;

  lat = lon = 0;
  ret_str = NULL;
  sprintf(sql_str, "select _rowid from %s where name = '%s' limit 1", table, name_key);
  err = shdb_exec_cb(db, sql_str, shdb_col_value_cb, &ret_str);
  if (err)
    return (err);

  if (ret_str == NULL)
    return (SHERR_NOENT);

  *rowid_p = atoll(ret_str);
  free(ret_str);

  return (0);
}

void shctx_free(shctx_t *ctx)
{
  if (ctx->ctx_data) {
    free(ctx->ctx_data);
    ctx->ctx_data = NULL;
    ctx->ctx_data_len = 0;
  }
}

int shctx_db_get_key(shdb_t *db, shkey_t *name_key, shctx_t *ctx)
{
  char sql_str[1024];
  char q_name[MAX_SHARE_HASH_LENGTH];
  shkey_t key;
  int err;

  if (!name_key)
    return (SHERR_INVAL);

  memset(ctx, 0, sizeof(shctx_t));
  ctx->ctx_stamp = SHTIME_UNDEFINED;

  memset(q_name, 0, sizeof(q_name));
  if (name_key)
    strncpy(q_name, shkey_shr160_print(name_key), sizeof(q_name)-1);

  memset(sql_str, 0, sizeof(sql_str));
  snprintf(sql_str, sizeof(sql_str)-1,
      "select name,value,stamp,expire,issuer "
      "from %s where name = '%s' limit 1", 
      SHCTX_TABLE_COMMON, q_name);
  err = shdb_exec_cb(db, sql_str, shctx_ctx_sql_cb, ctx);
  if (err)
    return (err);

  if (ctx->ctx_stamp == SHTIME_UNDEFINED)
    return (SHERR_NOENT);

  if (ctx->ctx_expire != SHTIME_UNDEFINED &&
      shtime_after(shtime(), ctx->ctx_expire))
    return (SHERR_KEYEXPIRED);

  return (0);
}

int shctx_get_key(shkey_t *name_key, shctx_t *ctx)
{
  shdb_t *db;
  int ret_err;

  db = shctx_open();
  if (!db)
    return (SHERR_INVAL);

  ret_err = shctx_db_get_key(db, name_key, ctx);

  shdb_close(db);
  return (ret_err);
}

int shctx_get(char *name, shctx_t *ctx)
{
  return (shctx_get_key(shctx_key(name), ctx));
}

int shctx_db_set_key(shdb_t *db, shkey_t *name_key, unsigned char *data, size_t data_len)
{
  shdb_idx_t rowid;
  shkey_t key;
  shkey_t *enc_key;
  shtime_t stamp;
  shtime_t expire;
  char q_name[MAX_SHARE_HASH_LENGTH];
  char iss[MAX_SHARE_HASH_LENGTH];
  char stamp_buf[256];
  char expire_buf[256];
  char *value;
  int err;

  memset(q_name, 0, sizeof(q_name));
  if (name_key)
    strncpy(q_name, shkey_shr160_print(name_key), sizeof(q_name)-1);

  err = shctx_rowid(db, SHCTX_TABLE_COMMON, q_name, &rowid); 
  if (err) {
    /* no matching entry */
    err = shdb_row_new(db, SHCTX_TABLE_COMMON, &rowid);
    if (err)
      return (err);
  }

  data_len = MAX(0, MIN(SHCTX_MAX_VALUE_SIZE, data_len));

  enc_key = shkey_shr160_gen(q_name);
  err = shencode_b64(data, data_len, &value, enc_key);
  shkey_free(&enc_key);
  if (err)
    return (err);

  stamp = shtime();
  sprintf(stamp_buf, "%f", shtimef(stamp));

  expire = shtime_adj(shtime(), SHCTX_DEFAULT_EXPIRE_TIME);
  sprintf(expire_buf, "%f", shtimef(expire));

  memset(iss, 0, sizeof(iss));
  { /* issuer */
    const char *username = shpam_username_sys();
    uint64_t uid = shpam_uid((char *)username);
    shkey_t *ident;

    err = shapp_ident(uid, &ident);
    if (!err) {
      /* record current user's peer identification. */
      strncpy(iss, shkey_print(ident), sizeof(iss)-1);
      shkey_free(&ident);
    }
  }

  shdb_row_set(db, SHCTX_TABLE_COMMON, rowid, "name", q_name);
  shdb_row_set(db, SHCTX_TABLE_COMMON, rowid, "value", value);
  shdb_row_set(db, SHCTX_TABLE_COMMON, rowid, "stamp", stamp_buf);
  shdb_row_set(db, SHCTX_TABLE_COMMON, rowid, "expire", expire_buf);
  shdb_row_set(db, SHCTX_TABLE_COMMON, rowid, "issuer", iss);

  free(value);

  return (0);
}

int shctx_notify(shkey_t *name_key)
{
  unsigned char *data = (unsigned char *)name_key;
  size_t data_len = sizeof(shkey_t);
  shbuf_t *buff;
  uint32_t mode;
  int qid;
  int err;

  mode = (uint32_t)TX_CONTEXT;
  buff = shbuf_init();
  shbuf_cat(buff, &mode, sizeof(uint32_t));
  shbuf_cat(buff, data, data_len);
  qid = shmsgget(NULL);
  err = shmsg_write(qid, buff, NULL);
  shbuf_free(&buff);
  if (err)
    return (err);

  return (0);
}

int shctx_set_key(shkey_t *name_key, unsigned char *data, size_t data_len)
{
  shdb_t *db;
  int ret_err;

  db = shctx_open();
  if (!db) {
    return (SHERR_INVAL);
  }

  ret_err = shctx_db_set_key(db, name_key, data, data_len);
  shdb_close(db);
  if (ret_err)
    return (ret_err);

  /* notify shared of context update */
  (void)shctx_notify(name_key);

  return (0);
}

int shctx_set(char *name, unsigned char *data, size_t data_len)
{
  return (shctx_set_key(shctx_key(name), data, data_len));
}

int shctx_setstr(char *name, char *data)
{
  return (shctx_set(name, (unsigned char *)data, (size_t)strlen(data)));
}



_TEST(shctx_set)
{
  shctx_t ctx;
  const char *test_name = "test";
  const char *test_value = "value";
  int err;

  err = shctx_setstr(test_name, test_value);
  _TRUE(err == 0);

  err = shctx_get(test_name, &ctx);
  _TRUE(err == 0);

  _TRUE(0 == shkey_shr160_ver(&ctx.ctx_key));

  _TRUEPTR(ctx.ctx_data);
  _TRUE(ctx.ctx_data_len == strlen(test_value));
  _TRUE(0 == strcmp(ctx.ctx_data, test_value));
  free(ctx.ctx_data);

}


