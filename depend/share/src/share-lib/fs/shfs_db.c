


#include "share.h"
#include "shfs_db_sqlite.h"






int shdb_col_num_cb(void *p, int arg_nr, char **args, char **cols)
{
  uint64_t *val = (uint64_t *)p;

  *val = 0;
  if (arg_nr > 0 && *args) {
    *val = atoll(*args);
  }

  return (0);
}

int shdb_col_value_cb(void *p, int arg_nr, char **args, char **cols)
{
  char **value_p = (char **)p;

  *value_p = NULL;
  if (arg_nr > 0 && *args)
    *value_p = strdup(*args);

  return (0);
}

static _shdb_open_index;

int shdb_init(char *path, shdb_t **db_p)
{
  int err;

  *db_p = NULL;
  err = sqlite3_open_v2(path, db_p, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI, 0);
  if (err)
    return (err);

  _shdb_open_index++;
  shdb_exec(*db_p, "PRAGMA journal_mode=OFF");

  return (0);
}

shdb_t *shdb_open_file(SHFL *file)
{
  shdb_t *db;
  char path[SHFS_PATH_MAX];
  int err;

  memset(path, 0, sizeof(path));
  strncpy(path, shpeer_print(shfs_inode_peer(file)), sizeof(path)-2);
  strcat(path, ":");
  strncat(path, shfs_inode_path(file), sizeof(path)-strlen(path)-1);
  err = shdb_init(path, &db);
  if (err)
    return (NULL);

  return (db);
}

shdb_t *shdb_open_peer(char *db_name, shpeer_t *peer)
{
  shdb_t *db;
  char path[SHFS_PATH_MAX];
  char sys_path[SHFS_PATH_MAX];
  char app_name[256];
  int err;

  memset(app_name, 0, sizeof(app_name));
  strncpy(app_name, shpeer_get_app(peer ? peer : ashpeer()), sizeof(app_name)-1);

  memset(path, 0, sizeof(path));
  sprintf(path, "%s/%s", app_name, db_name);

  memset(sys_path, 0, sizeof(sys_path));
  if (peer) {
    sprintf(sys_path, "%s:", app_name);
  }
  strcat(sys_path, shfs_sys_dir(SHFS_DIR_DATABASE, path));

  err = shdb_init(sys_path, &db);
  if (err)
    return (NULL);

  return (db);
}
shdb_t *shdb_open(char *db_name)
{
  return (shdb_open_peer(db_name, NULL));
}
#if 0
shdb_t *shdb_open(char *db_name)
{
  shpeer_t *peer;
  shdb_t *db;
  char path[SHFS_PATH_MAX];
  int err;

  memset(path, 0, sizeof(path));
  sprintf(path, "%s/%s", shpeer_get_app(ashpeer()), db_name);
  err = shdb_init(path, &db);
  if (err)
    return (NULL);

  return (db);
}
#endif

void shdb_close(shdb_t *db)
{
  int err;

  err = sqlite3_close(db);
  if (err) {
    sherr(SHERR_IO, "shdb_close");
    return;
  }

  if (_shdb_open_index > 0) {
    _shdb_open_index--;
    if (_shdb_open_index == 0)
      sqlite3_shutdown();
  }
}

int shdb_exec(shdb_t *db, char *sql)
{
  char *errmsg;
  int err;

  errmsg = NULL;
  err = sqlite3_exec(db, sql, NULL, NULL, &errmsg);
  if (err) {
    err = SHERR_INVAL;
    if (errmsg) {
      if (!strstr(errmsg, "already exists")) {
        sherr(SHERR_INVAL, errmsg);
      } else {
        err = SHERR_EXIST;
      }
      sqlite3_free(errmsg); 
    }
    return (err);
  }

  return (0);
}

int shdb_exec_cb(shdb_t *db, char *sql, shdb_cb_t func, void *arg)
{
  char *errmsg;
  int err;

  errmsg = NULL;
  err = sqlite3_exec(db, sql, func, arg, &errmsg);
  if (err) {
    if (errmsg) {
      if (!strstr(errmsg, "already exists"))
        sherr(SHERR_INVAL, errmsg);
      sqlite3_free(errmsg);
    }
    return (SHERR_INVAL);
  }

  return (0);
}

int shdb_table_new(shdb_t *db, char *table)
{
  char sql[1024];
  int err;

  if (!table || strlen(table) > 256)
    return (SHERR_INVAL);

  sprintf(sql, "create table %s ( _rowid INTEGER PRIMARY KEY ASC )", table);
  //sprintf(sql, "create table IF NOT EXISTS %s ( _rowid INTEGER PRIMARY KEY ASC )", table);
  err = shdb_exec(db, sql); 
  if (err)
    return (err);

  return (0);
}

int shdb_table_like(shdb_t *db, char *table, char *tmpl_table)
{
  char sql[1024];
  int err;

  if (!table || strlen(table) > 256)
    return (SHERR_INVAL);

  if (!tmpl_table || strlen(tmpl_table) > 256)
    return (SHERR_INVAL);

  sprintf(sql, "create table %s like %s", table, tmpl_table);
  err = shdb_exec(db, sql); 
  if (err)
    return (err);

  return (0);
}

int shdb_table_delete(shdb_t *db, char *table)
{
  char sql[512];

  if (!table || strlen(table) > 256)
    return (SHERR_INVAL);

  sprintf(sql, "drop table %s", table);
  return (shdb_exec(db, sql));
}

int shdb_table_copy(shdb_t *db, char *orig_table, char *new_table)
{
  char sql[1024];
  int err;

  err = shdb_table_like(db, new_table, orig_table);
  if (err)
    return (err);

  sprintf(sql, "insert into %s select * from %s", orig_table, new_table);
  err = shdb_exec(db, sql); 
  if (err) {
    shdb_table_delete(db, new_table);
    return (err);
  }

  return (0);
}

int shdb_col_new(shdb_t *db, char *table, char *col)
{
  char sql[1024];
  int err;

  if (!table || strlen(table) > 256)
    return (SHERR_INVAL);
  if (!col || strlen(col) > 256)
    return (SHERR_INVAL);

  sprintf(sql, "alter table %s add column %s text", table, col);
  err = shdb_exec(db, sql); 
  if (err) {
    return (err);
  }

  return (0);
}


int shdb_row_new(shdb_t *db, char *table, shdb_idx_t *rowid_p)
{
  char sql[1024];
  int err;

  if (!table || strlen(table) > 256)
    return (SHERR_INVAL);

  sprintf(sql, "insert into %s (_rowid) values (null)", table);
  err = shdb_exec(db, sql);
  if (err)
    return (err);

  *rowid_p = (uint64_t)sqlite3_last_insert_rowid(db);

  return (0);
}

int shdb_row_set(shdb_t *db, char *table, shdb_idx_t rowid, char *col, char *text)
{
  char *sql;
  int err;

  sql = sqlite3_mprintf(
      "update %s set %s = %Q where _rowid = %llu",
      table, col, text, rowid);
  err = shdb_exec(db, sql);
  sqlite3_free(sql);
  if (err)
    return (err);

  return (0);
}

int shdb_row_set_time(shdb_t *db, char *table, shdb_idx_t rowid, char *col)
{
  char sql[1024];
  int err;

  if (!table || strlen(table) > 256)
    return (SHERR_INVAL);

  sprintf(sql, 
      "update %s set %s = CURRENT_TIMESTAMP where _rowid = %llu",
      table, col, rowid);
  err = shdb_exec(db, sql);
  if (err)
    return (err);

  return (0);
}
int shdb_row_set_time_adj(shdb_t *db, char *table, shdb_idx_t rowid, char *col, unsigned int dur)
{
  char sql[1024];
  int err;

  if (!table || strlen(table) > 256)
    return (SHERR_INVAL);

  sprintf(sql, 
      "update %s set %s = datetime('now', '+%u seconds') where _rowid = %llu",
      table, col, dur, rowid);
  err = shdb_exec(db, sql);
  if (err)
    return (err);

  return (0);
}

time_t shdb_row_time(shdb_t *db, char *table, shdb_idx_t rowid, char *col)
{
  char sql[1024];
  uint64_t val;
  int err;

  if (!table || strlen(table) > 256)
    return (SHERR_INVAL);

  val = 0;
  sprintf(sql, 
      "select strftime('%%s', %s) from %s where _rowid = %llu",
      col, table, rowid);
  err = shdb_exec_cb(db, sql, shdb_col_num_cb, &val);
  if (err)
    return (0);

  return ((time_t)val);
}

char *shdb_row_value(shdb_t *db, char *table, shdb_idx_t rowid, char *col)
{
  char sql[1024];
  char *value;
  int err;

  if (!table || strlen(table) > 256)
    return (NULL);
  if (!col || strlen(col) > 256)
    return (NULL);

  value = NULL;
  sprintf(sql, "select %s from %s where _rowid = %llu", col, table, rowid);
  err = shdb_exec_cb(db, sql, shdb_col_value_cb, &value);
  if (err)
    return (NULL);

  return (value);
}

char *shdb_sql_value(char *field_value)
{
  return (field_value);
}

#define SHSQL_LIKE (1 << 0)

int shdb_row_find(shdb_t *db, char *table, shdb_idx_t *rowid_p, char *col, char *val, int flags)
{
  char *sql_str;
  char *ret_val;
  int err;

  if (!db || !table || !col)
    return (SHERR_INVAL);

  sql_str = (char *)calloc(
      strlen(val) + strlen(col) + strlen(table) + 512, sizeof(char));
  if (!sql_str)
    return (SHERR_NOMEM);

  if (!val) {
    sprintf(sql_str, "select _rowid from %s where %s is null", table, col);
  } else if (flags & SHSQL_LIKE) {
    sprintf(sql_str, "select _rowid from %s where %s like '%%%s%%'", 
        table, col, shdb_sql_value(val));
  } else {
    sprintf(sql_str, "select _rowid from %s where %s = '%s'", 
        table, col, shdb_sql_value(val));
  }

  ret_val = NULL;
  err = shdb_exec_cb(db, sql_str, shdb_col_value_cb, &ret_val);
  free(sql_str);
  if (err)
    return (err);

  if (ret_val == NULL)
    return (SHERR_NOENT);

  /* success */
  if (rowid_p) {
    *rowid_p = (uint64_t)atoll(ret_val);
  }
  free(ret_val);
    
  return (0);
} 

int shdb_row_delete(shdb_t *db, char *table, shdb_idx_t rowid)
{
  char sql[512];

  if (!table || strlen(table) > 256)
    return (SHERR_INVAL);

  sprintf(sql, "delete from %s where _rowid = %u", table, (unsigned int)rowid);
  return (shdb_exec(db, sql));
}



_TEST(shfs_db)
{
  shdb_t *db;
  char *errmsg;
  char *str;
  char sql[256];
  shdb_idx_t rowid;
  time_t t;
  time_t now;
  int err;

  db = shdb_open("test");
  _TRUEPTR(db);

  err = shdb_table_new(db, "test");
  if (err) {
    /* last run failed */
    err = shdb_table_delete(db, "test");
    _TRUE(0 == err);
    err = shdb_table_new(db, "test");
  }
  _TRUE(0 == err);

  _TRUE(0 == shdb_col_new(db, "test", "fld1"));
  _TRUE(0 == shdb_col_new(db, "test", "fld2"));
  _TRUE(0 == shdb_col_new(db, "test", "fld3"));

  rowid = 0;
  err = shdb_row_new(db, "test", &rowid);
  _TRUE(0 == err);

  err = shdb_row_set(db, "test", rowid, "fld1", "text1");
  _TRUE(0 == err);
  err = shdb_row_set(db, "test", rowid, "fld2", "text2");
  _TRUE(0 == err);
  now = time(NULL);
  err = shdb_row_set_time(db, "test", rowid, "fld3");
  _TRUE(0 == err);

  str = shdb_row_value(db, "test", rowid, "fld1");
  _TRUEPTR(str);
  free(str);
  str = shdb_row_value(db, "test", rowid, "fld2");
  _TRUEPTR(str);
  free(str);
  t = shdb_row_time(db, "test", rowid, "fld3");
  _TRUE(t >= now);

  err = shdb_table_delete(db, "test");
  _TRUE(err == 0);


  shdb_close(db);

}



int shfs_db_read_of(shfs_ino_t *file, shbuf_t *buff, off_t of, size_t size)
{
  shfs_ino_t *aux;
  shfs_ino_t *db;
  int err;

  if (file == NULL)
    return (SHERR_INVAL);

  if (shfs_format(file) != SHINODE_DATABASE)
    return (SHERR_INVAL);

  db = shfs_inode(file, NULL, SHINODE_DATABASE);

  if (shfs_format(db) != SHINODE_BINARY)
    return (SHERR_NOENT);

  err = shfs_bin_read_of(db, buff, of, size);
  if (err) {
    return (err);
  }


  return (0);
}

/** Read raw database content from a file. */
int shfs_db_read(shfs_ino_t *file, shbuf_t *buff)
{
  return (shfs_db_read_of(file, buff, 0, 0));
}

int shfs_db_write(shfs_ino_t *file, shbuf_t *buff)
{
  shfs_ino_t *db;
  shfs_ino_t *aux;
  int err;

  if (file == NULL)
    return (SHERR_INVAL);

  db = shfs_inode(file, NULL, SHINODE_DATABASE);
  err = shfs_bin_write(db, buff);
  if (err)
    return (err);

  err = shfs_inode_write_entity(db);
  if (err) {
    sherr(err, "shfs_db_write [shfs_inode_write_entity]");
    return (err);
  }

  /* copy aux stats to file inode. */
  file->blk.hdr.mtime = db->blk.hdr.mtime;
  file->blk.hdr.size = db->blk.hdr.size;
  file->blk.hdr.crc = db->blk.hdr.crc;
  file->blk.hdr.format = SHINODE_DATABASE;

  return (0);
}

int shdb_json_value_cb(void *p, int arg_nr, char **args, char **cols)
{
  shjson_t *json = (shjson_t *)p;
  shjson_t *row;
  char id_str[256];
  int idx;

  memset(id_str, 0, sizeof(id_str));
  for (idx = 0; idx < arg_nr; idx++) {
    char *col_name = cols[idx];
    char *col_val = args[idx];
    if (0 == strcmp(col_name, "_rowid"))
      strncpy(id_str, col_val, sizeof(id_str)-1);
  }

  row = shjson_obj_add(json, id_str);
  for (idx = 0; idx < arg_nr; idx++) {
    char *col_name = cols[idx];
    char *col_val = args[idx];
    if (0 == strcmp(col_name, "_rowid"))
      continue;
    shjson_str_add(row, col_name, col_val);
  }

  return (0);
}

shjson_t *shdb_json_write(shdb_t *db, char *table, shdb_idx_t rowid_of, shdb_idx_t rowid_len)
{
  shjson_t *json;
  shjson_t *node;
  char sql_str[1024];
  int err;

  json = shjson_init(NULL);
  if (!json)
    return (NULL);

  node = shjson_obj_add(json, table);

  sprintf(sql_str, "select * from %s where _rowid >= %d order by _rowid", table, rowid_of);
  if (rowid_len > 0)
    sprintf(sql_str+strlen(sql_str), " limit %d", rowid_len);

  err = shdb_exec_cb(db, sql_str, shdb_json_value_cb, node);
  if (err)
    return (NULL);

  return (json);
}

int shdb_json_read(shdb_t *db, shjson_t *json)
{
  shjson_t *table;
  shjson_t *node;
  shjson_t *rec;
  shdb_idx_t rowid;
  char buf[256];
  int err;

  /* parse through tables */
  for (table = json->child; table; table = table->next) {
    char *table_name = table->string; 

    if (!table_name || !*table_name)
      continue; /* wrong format? */
    
    err = shdb_table_new(db, table_name);
    if (err == 0) {
      /* initial column creation */
      rec = table->child;
      if (!rec)
        continue;
      for (node = rec->child; node; node = node->next) {
        const char *field_name = (const char *)node->string;
        shdb_col_new(db, table_name, field_name);
      }
    } else if (err != SHERR_EXIST) {
      continue;
    }

    /* parse through records */
    for (rec = table->child; rec; rec = rec->next) {
      err = shdb_row_new(db, table_name, &rowid);
      if (err) {
        PRINT_ERROR(err, "shdb_row_new");
        continue;
      }

      /* parse through fields */
      for (node = rec->child; node; node = node->next) {
        const char *field_name = (const char *)node->string;

        err = 0;
        switch (node->type) {
          case shjson_True:
            err = shdb_row_set(db, table_name, rowid, field_name, "1");
            break;
          case shjson_False:
            err = shdb_row_set(db, table_name, rowid, field_name, "0");
            break;
          case shjson_Number:
            if (node->valueint == (int)node->valuedouble)
              sprintf(buf, "%d", node->valueint);
            else
              sprintf(buf, "%f", node->valuedouble);
            err = shdb_row_set(db, table_name, rowid, field_name, buf);
            break;
          case shjson_String:
            if (node->valuestring)
              err = shdb_row_set(db, table_name, rowid, field_name, node->valuestring);
            break;
        } 
        if (err) {
          PRINT_ERROR(err, "shdb_row_new");
          continue;
        }

      }
    }

  }

  return (0);
}


