
/*
 *  Copyright 2016 Neo Natura
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
#include <math.h>

/**
 * Upper limit of roughly 300k miles for allowed altitude. 
 */
#define SHGEO_MAX_ALTITUDE 1584000000

#define MAX_SHGEO_SCAN_RECORDS 72

void shgeo_set(shgeo_t *geo, shnum_t lat, shnum_t lon, int alt)
{

  alt = MIN(alt, 1584000000);

  geo->geo_stamp = shtime();
  shnum_set((shnum_t)lat, &geo->geo_lat);
  shnum_set((shnum_t)lon, &geo->geo_lon);
  geo->geo_alt = (uint32_t)alt;

}

void shgeo_loc(shgeo_t *geo, shnum_t *lat_p, shnum_t *lon_p, int *alt_p)
{

  if (lat_p)
    *lat_p = shnum_get(geo->geo_lat);

  if (lon_p)
    *lon_p = shnum_get(geo->geo_lon);

  if (alt_p)
    *alt_p = (int)geo->geo_alt;

}

time_t shgeo_timestamp(shgeo_t *geo)
{
  return (shutime(geo->geo_stamp));
}

time_t shgeo_lifespan(shgeo_t *geo)
{
  return ((time_t)shtime_diff(shtime(), geo->geo_stamp));
}

shkey_t *shgeo_tag(shgeo_t *geo, int prec)
{
  shnum_t nlat;
  shnum_t nlon;
  double lat;
  double lon;
  char buf[32];

  shgeo_loc(geo, &nlat, &nlon, NULL);

  lat = (double)shnum_prec_dim(nlat, prec);
  lon = (double)shnum_prec_dim(nlon, prec);

  memset(buf, 0, sizeof(buf));
  memcpy(buf, &lat, sizeof(double));
  memcpy(buf + sizeof(double), &lon, sizeof(double));

  return (shkey_bin(buf, sizeof(double) * 2));
}

int shgeo_cmp(shgeo_t *geo, shgeo_t *cmp_geo, int prec)
{
  shnum_t lat;
  shnum_t lon;
  shnum_t c_lat;
  shnum_t c_lon;

  shgeo_loc(geo, &lat, &lon, NULL);
  lat = shnum_prec_dim(lat, prec);
  lon = shnum_prec_dim(lon, prec);

  shgeo_loc(geo, &c_lat, &c_lon, NULL);
  c_lat = shnum_prec_dim(c_lat, prec);
  c_lon = shnum_prec_dim(c_lon, prec);

  return (lat == c_lat && lon == c_lon);
}

int shgeo_cmpf(shgeo_t *geo, double lat, double lon)
{
  shgeo_t t_geo;
  shgeo_set(&t_geo, (shnum_t)lat, (shnum_t)lon, 0);
  return (shgeo_cmp(geo, &t_geo, SHGEO_PREC_POINT)); 
}

static shnum_t _deg2rad(shnum_t deg) 
{
  return (deg * M_PI / 180.0);
}

static shnum_t _rad2deg(shnum_t rad) 
{
  static const shnum_t half_deg = 180.0;
  return (rad * half_deg / (shnum_t)M_PI);
}

/**
 * Calculate the distance between two geodetic location in miles.
 */
double shgeo_dist(shgeo_t *f_geo, shgeo_t *t_geo)
{
  static const shnum_t mile_mod = 90.9;
  shnum_t theta, dist;
  shnum_t lat1, lat2;
  shnum_t lon1, lon2;

  shgeo_loc(f_geo, &lat1, &lon1, NULL);
  shgeo_loc(t_geo, &lat2, &lon2, NULL);

  theta = lon1 - lon2;
  dist = (sinl(_deg2rad(lat1)) * sinl(_deg2rad(lat2))) + 
    (cosl(_deg2rad(lat1)) * cosl(_deg2rad(lat2)) * cosl(_deg2rad(theta)));
  dist = acosl(dist);
  dist = _rad2deg(dist);
  dist = dist * mile_mod;

  return ((double)dist);
}

double shgeo_radius(shgeo_t *f_geo, shgeo_t *t_geo)
{
  return (shgeo_dist(f_geo, t_geo) / 2);
}


_TEST(shgeo_dist)
{
  shgeo_t fl_geo;
  shgeo_t ms_geo;
  shnum_t in_lat, in_lon;
  shnum_t lat, lon;
  double d;
  int ok;

  in_lat = 44.66;
  in_lon = -114.0;
  shgeo_set(&fl_geo, in_lat, in_lon, 1); 
  shgeo_loc(&fl_geo, &lat, &lon, NULL);
  _TRUE((float)lat == (float)in_lat);
  _TRUE((float)lon == (float)(in_lon * -1));

  in_lat = 46.87;
  in_lon = -113.99;
  shgeo_set(&ms_geo, in_lat, in_lon, 0); 
  shgeo_loc(&ms_geo, &lat, &lon, NULL);
  _TRUE((float)lat == (float)in_lat);
  _TRUE((float)lon == (float)(in_lon * -1));

  d = ceil(shgeo_dist(&fl_geo, &ms_geo));
  _TRUE(d == 201);
}

void shgeo_dim(shgeo_t *geo, int prec)
{
  shnum_t lat;
  shnum_t lon;

  if (!geo) return;

  if (prec < SHGEO_MAX_PRECISION) {
    lat = shnum_get(geo->geo_lat);
    lon = shnum_get(geo->geo_lon);
    lat = shnum_prec_dim(lat, prec);
    lon = shnum_prec_dim(lon, prec);
    shnum_set((shnum_t)lat, &geo->geo_lat);
    shnum_set((shnum_t)lon, &geo->geo_lon);
  }
}

static shgeo_t _local_geo_index;

/**
 * Obtain the device's current location.
 */
void shgeo_local(shgeo_t *geo, int prec)
{
  shnum_t lat, lon;

  if (!geo)
    return;

  if (_local_geo_index.geo_stamp == SHTIME_UNDEFINED) {
    char *pref = (char *)shpref_get(SHPREF_ACC_GEO, "");
    if (pref && *pref) {
      sscanf(pref, "%Lf,%Lf", &lat, &lon);
      if (lat != 0.0000 && lon != 0.0000)
        shgeo_set(&_local_geo_index, lat, lon, 0); /* previous setting */
    }
  }

  memcpy(geo, &_local_geo_index, sizeof(_local_geo_index));
  shgeo_dim(geo, prec);
  
}

/**
 * Manually set the device's current location.
 */
void shgeo_local_set(shgeo_t *geo)
{
  shnum_t lat, lon;
  char buf[256];

  if (!geo)
    return;

  /* set in-memory */
  memcpy(&_local_geo_index, geo, sizeof(_local_geo_index));
  _local_geo_index.geo_stamp = shtime();

  /* set persistent */
  shgeo_loc(geo, &lat, &lon, NULL);
  sprintf(buf, "%Lf,%Lf", lat, lon);
  shpref_set(SHPREF_ACC_GEO, buf);
}


/* ** shgeodb ** */

static void shgeodb_table_init(shdb_t *db, char *table)
{

  if (0 != shdb_table_new(db, table))
    return;

  shdb_col_new(db, table, "name");
  shdb_col_new(db, table, "summary");
  shdb_col_new(db, table, "latitude");
  shdb_col_new(db, table, "longitude");
  shdb_col_new(db, table, "locale"); /* en_US */
  shdb_col_new(db, table, "zone"); /* America/Indiana/Indianapolis */
  shdb_col_new(db, table, "type"); /* RDG, TMPL, etc */
#if 0
  shdb_col_new(db, table, "accuracy"); /* SHGEO_PREC precision */
  shdb_col_new(db, table, "stamp");
  shdb_col_new(db, table, "altitude");
#endif

}

shdb_t *shgeodb_open(char *db_name)
{
  shdb_t *db;
  shpeer_t *peer;

  peer = shpeer_init(NULL, NULL); /* "libshare" partition */
  db = shdb_open_peer(db_name, peer);
  shpeer_free(&peer);
  if (!db)
    return (NULL);

  shgeodb_table_init(db, SHGEO_ZIPCODE);
  shgeodb_table_init(db, SHGEO_CITY);
  shgeodb_table_init(db, SHGEO_COMMON);
  shgeodb_table_init(db, SHGEO_NETWORK);
#if 0
  shgeodb_table_init(db, SHGEO_USER);
#endif

  return (db);
}

shdb_t *shgeodb_open_sys(void)
{
  return (shgeodb_open(SHGEO_SYSTEM_DATABASE_NAME));
}

shdb_t *shgeodb_open_user(void)
{
  return (shgeodb_open(SHGEO_USER_DATABASE_NAME));
}

static int shgeodb_geo_sql_cb(void *p, int arg_nr, char **args, char **cols)
{
  shgeo_t *value_p = (shgeo_t *)p;
  shtime_t stamp = SHTIME_UNDEFINED;
  shnum_t lat = 0;
  shnum_t lon = 0;
  int alt = 0;

  if (arg_nr == 2) {
    if (args[0])
      lat = (shnum_t)atof(args[0]);
    if (args[1])
      lon = (shnum_t)atof(args[1]);
#if 0
    if (args[2])
      alt = atoi(args[2]);
#endif
    shgeo_set(value_p, lat, lon, alt);

#if 0
    if (args[3])
      value_p->geo_stamp = (shtime_t)atoll(args[3]);
#endif
    if (value_p->geo_stamp == SHTIME_UNDEFINED)
      value_p->geo_stamp = shtime();
  }

  return (0);
}

static int shgeodb_loc_sql_cb(void *p, int arg_nr, char **args, char **cols)
{
  shloc_t *loc = (shloc_t *)p;

  if (arg_nr != 5)
    return (-1);

  if (args[0])
    strncpy(loc->loc_name, args[0], sizeof(loc->loc_name)-1);
  if (args[1])
    strncpy(loc->loc_summary, args[1], sizeof(loc->loc_summary)-1);
  if (args[2])
    strncpy(loc->loc_locale, args[2], sizeof(loc->loc_locale)-1);
  if (args[3])
    strncpy(loc->loc_zone, args[3], sizeof(loc->loc_zone)-1);
  if (args[4])
    strncpy(loc->loc_type, args[4], sizeof(loc->loc_type)-1);

  return (0);
}

static inline int is_shgeo_zipcode(const char *name)
{
  return (atoi(name) >= 10000);
}


static int shgeodb_scan_sql_cb(void *p, int arg_nr, char **args, char **cols)
{
  shgeo_t *value_p = (shgeo_t *)p;
  shnum_t lat = 0;
  shnum_t lon = 0;
  int idx;

  for (idx = 0; idx < MAX_SHGEO_SCAN_RECORDS; idx++) {
    if (value_p[idx].geo_stamp == SHTIME_UNDEFINED)
      break;
  }
  if (idx == MAX_SHGEO_SCAN_RECORDS)
    return (0); /* full list */

  if (arg_nr == 2) {
    if (args[0] == NULL || args[1] == NULL)
      return (0);

    lat = (shnum_t)atof(args[0]);
    lon = (shnum_t)atof(args[1]);
    shgeo_set(value_p + idx, lat, lon, 0);
    if (value_p[idx].geo_stamp == SHTIME_UNDEFINED)
      value_p[idx].geo_stamp = shtime();
  }

  return (0);
}


int shgeodb_name(shdb_t *db, char *table, const char *name, shgeo_t *geo)
{
  char sql_str[1024];
  int err;

  if (!name || !*name)
    return (SHERR_INVAL);

  memset(geo, 0, sizeof(shgeo_t));
  geo->geo_stamp = SHTIME_UNDEFINED;

  memset(sql_str, 0, sizeof(sql_str));
  snprintf(sql_str, sizeof(sql_str)-1,
      "select latitude,longitude "
      "from %s where name = '%s' limit 1", 
      table, name);
  err = shdb_exec_cb(db, sql_str, shgeodb_geo_sql_cb, geo);
  if (err)
    return (err);

  if (geo->geo_stamp == SHTIME_UNDEFINED)
    return (SHERR_NOENT);

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

static int _shgeodb_place(shdb_t *db, const char *place_str, shgeo_t *geo)
{
  int err;

  if (is_shgeo_zipcode(place_str)) {
    err = shgeodb_name(db, SHGEO_ZIPCODE, place_str, geo);
    if (!err)
      return (0);
  }

  if (strchr(place_str, ',')) {
    err = shgeodb_name(db, SHGEO_CITY, place_str, geo);
    if (!err)
      return (0);
  }

  err = shgeodb_name(db, SHGEO_COMMON, place_str, geo);
  if (!err)
    return (0);

#if 0
  err = shgeodb_name(db, SHGEO_USER, place_str, geo);
  if (!err)
    return (0);
#endif

  return (SHERR_NOENT);
}

int shgeodb_place(const char *name, shgeo_t *geo)
{
  shdb_t *db;
  char place_str[1024];;
  int ret_err;
  int err;

  ret_err = SHERR_NOENT;

  memset(place_str, 0, sizeof(place_str));
  strncpy(place_str, name, sizeof(place_str)-1);
  _lowercase_string(place_str);

  db = shgeodb_open_sys();
  if (db) {
    err = _shgeodb_place(db, place_str, geo);
    shdb_close(db);
    if (err == 0)
      return (0);
    ret_err = err;
  }

  db = shgeodb_open_user();
  if (db) {
    err = _shgeodb_place(db, place_str, geo);
    shdb_close(db);
    if (err == 0)
      return (0);
    ret_err = err;
  }

  return (ret_err);
}

int _shgeodb_host(shdb_t *db, int a, int b, int c, shgeo_t *geo)
{
  char ipaddr[MAXHOSTNAMELEN+1];
  int err;

  memset(ipaddr, 0, sizeof(ipaddr));
  sprintf(ipaddr, "%u.%u.%u", a, b, c);
  err = shgeodb_name(db, SHGEO_NETWORK, ipaddr, geo);
  if (err)
    return (err);

  return (0);
}

int shgeodb_host(const char *name, shgeo_t *geo)
{
  struct hostent *host;
  shdb_t *db;
  unsigned int a, b, c, d;
  char *str;
  int ret_err;
  int err;
  int n;
  int i;

  n = sscanf(name, "%u.%u.%u.%u", &a, &b, &c, &d);
  if (n != 4) {
    struct in_addr *in;
    char ipaddr[MAXHOSTNAMELEN+1];

    host = shresolve((char *)name);  
    if (!host)
      return (SHERR_NOENT);

    in = (struct in_addr *)host->h_addr;
    if (!in)
      return (SHERR_OPNOTSUPP);

    memset(ipaddr, 0, sizeof(ipaddr));
    strncpy(ipaddr, inet_ntoa(*in), sizeof(ipaddr)-1);
    n = sscanf(ipaddr, "%u.%u.%u.%u", &a, &b, &c, &d);
    if (n != 4)
      return (SHERR_OPNOTSUPP);
  }

  ret_err = 0;

  db = shgeodb_open_sys();
  if (db) {
    err = _shgeodb_host(db, a, b, c, geo);
    shdb_close(db);
    if (err == 0)
      return (0);

    ret_err = err;
  }

  db = shgeodb_open_user();
  if (db) {
    err = _shgeodb_host(db, a, b, c, geo);
    shdb_close(db);
    if (err == 0)
      return (0);

    ret_err = err;
  }

  return (ret_err);
}

int shgeodb_rowid(shdb_t *db, const char *table, shgeo_t *geo, shdb_idx_t *rowid_p)
{
  char sql_str[1024];
  shnum_t lat, lon;
  char *ret_str;
  int err;

  lat = lon = 0;
  ret_str = NULL;
  shgeo_loc(geo, &lat, &lon, NULL);
  sprintf(sql_str, "select _rowid from %s where latitude = '%-5.5Lf' and longitude = '%-5.5Lf' limit 1", table, lat, lon);
  err = shdb_exec_cb(db, sql_str, shdb_col_value_cb, &ret_str);
  if (err)
    return (err);

  if (ret_str == NULL)
    return (SHERR_NOENT);

  *rowid_p = atoll(ret_str);
  free(ret_str);

  return (0);
}


int _shgeodb_scan(shdb_t *db, shnum_t lat, shnum_t lon, shnum_t radius, shgeo_t *geo)
{
  shgeo_t geo_list[MAX_SHGEO_SCAN_RECORDS];
  shnum_t ret_lat, ret_lon;
  shgeo_t rad_geo;
  double ret_dist;
  double dist;
  char sql_str[1024];
  int idx;

  memset((shgeo_t *)geo_list, '\000', sizeof(shgeo_t) * MAX_SHGEO_SCAN_RECORDS);
#if 0
  sprintf(sql_str, "select latitude,longitude from %s where cast(latitude as decimal) >= %-5.5Lf and cast(latitude as decimal) <= %-5.5Lf and cast(longitude as decimal) >= %-5.5Lf and cast(longitude as decimal) <= %-5.5Lf limit 32", SHGEO_ZIPCODE, (lat - radius), (lat + radius), (lon - radius), (lon + radius));
  shdb_exec_cb(db, sql_str, shgeodb_scan_sql_cb, (shgeo_t *)geo_list);
#endif

  sprintf(sql_str, "select latitude,longitude from %s where cast(latitude as decimal) >= %-5.5Lf and cast(latitude as decimal) <= %-5.5Lf and cast(longitude as decimal) >= %-5.5Lf and cast(longitude as decimal) <= %-5.5Lf limit 24", SHGEO_CITY, (lat - radius), (lat + radius), (lon - radius), (lon + radius));
  shdb_exec_cb(db, sql_str, shgeodb_scan_sql_cb, (shgeo_t *)geo_list);

  sprintf(sql_str, "select latitude,longitude from %s where cast(latitude as decimal) >= %-5.5Lf and cast(latitude as decimal) <= %-5.5Lf and cast(longitude as decimal) >= %-5.5Lf and cast(longitude as decimal) <= %-5.5Lf limit 24", SHGEO_COMMON, (lat - radius), (lat + radius), (lon - radius), (lon + radius));
  shdb_exec_cb(db, sql_str, shgeodb_scan_sql_cb, (shgeo_t *)geo_list);

#if 0
  sprintf(sql_str, "select latitude,longitude from %s where cast(latitude as decimal) >= %-5.5Lf and cast(latitude as decimal) <= %-5.5Lf and cast(longitude as decimal) >= %-5.5Lf and cast(longitude as decimal) <= %-5.5Lf limit 24", SHGEO_USER, (lat - radius), (lat + radius), (lon - radius), (lon + radius));
  shdb_exec_cb(db, sql_str, shgeodb_scan_sql_cb, (shgeo_t *)geo_list);
#endif

  shgeo_set(&rad_geo, lat, lon, 0);

  ret_lat = lat;
  ret_lon = lon;
  ret_dist = 100;
  for (idx = 0; idx < MAX_SHGEO_SCAN_RECORDS; idx++) {
    if (geo_list[idx].geo_stamp == SHTIME_UNDEFINED)
      break;

    dist = shgeo_dist(&rad_geo, geo_list + idx);
    if (dist < ret_dist) {
      ret_dist = dist;
      memcpy(geo, geo_list + idx, sizeof(shgeo_t));
    }
  }

  if (idx == 0)
    return (SHERR_NOENT);

  return (0);
}

int shgeodb_scan(shnum_t lat, shnum_t lon, shnum_t radius, shgeo_t *geo)
{
  shdb_t *db;
  int ret_err;
  int err;
 
  radius = MIN(1.0, radius);
  radius = MAX(0.00001, radius);

  ret_err = 0;

  db = shgeodb_open_sys();
  if (db) {
    err = _shgeodb_scan(db, lat, lon, radius, geo);
    shdb_close(db);
    if (err == 0)
      return (0);

    ret_err = err;
  }

  db = shgeodb_open_user();
  if (db) {
    err = _shgeodb_scan(db, lat, lon, radius, geo);
    shdb_close(db);
    if (err == 0)
      return (0);

    ret_err = err;
  }

  return (ret_err);
}

/**
 * Obtain known information about a location.
 */
int _shgeodb_loc(shdb_t *db, shgeo_t *geo, shloc_t *loc)
{
  shnum_t lat, lon;
  char sql_str[256];
  char *ret_val;
  int err;

  shgeo_loc(geo, &lat, &lon, NULL);

  memset(loc, 0, sizeof(shloc_t));
  memcpy(&loc->loc_geo, geo, sizeof(shgeo_t));

#if 0
  sprintf(sql_str, "select name,summary,locale,zone,type from %s where latitude = '%-5.5Lf' and longitude = '%-5.5Lf' limit 1", SHGEO_ZIPCODE, lat, lon);
  err = shdb_exec_cb(db, sql_str, shgeodb_loc_sql_cb, loc);
  if (!err && *loc->loc_name) {
    shdb_close(db);
    return (0);
  }
#endif

  sprintf(sql_str, "select name,summary,locale,zone,type from %s where latitude = '%-5.5Lf' and longitude = '%-5.5Lf' limit 1", SHGEO_CITY, lat, lon);
  err = shdb_exec_cb(db, sql_str, shgeodb_loc_sql_cb, loc);
  if (!err && *loc->loc_name) {
    return (0);
  }

  sprintf(sql_str, "select name,summary,locale,zone,type from %s where latitude = '%-5.5Lf' and longitude = '%-5.5Lf' limit 1", SHGEO_COMMON, lat, lon);
  err = shdb_exec_cb(db, sql_str, shgeodb_loc_sql_cb, loc);
  if (!err && *loc->loc_name) {
    return (0);
  }

#if 0
  sprintf(sql_str, "select name,summary,locale,zone,type from %s where latitude = '%-5.5Lf' and longitude = '%-5.5Lf' limit 1", SHGEO_USER, lat, lon);
  err = shdb_exec_cb(db, sql_str, shgeodb_loc_sql_cb, loc);
  if (!err && *loc->loc_name) {
    return (0);
  }
#endif

  return (SHERR_NOENT);
}

int shgeodb_loc(shgeo_t *geo, shloc_t *loc)
{
  shdb_t *db;
  int ret_err;
  int err;

  ret_err = 0;

  db = shgeodb_open_sys();
  if (db) {
    err = _shgeodb_loc(db, geo, loc);
    shdb_close(db);
    if (err == 0)
      return (0);

    ret_err = err;
  }

  db = shgeodb_open_user();
  if (db) {
    err = _shgeodb_loc(db, geo, loc);
    shdb_close(db);
    if (err == 0)
      return (0);

    ret_err = err;
  }

  return (ret_err);
}

/**
 * Set custom contextual information for a particular location.
 */
int _shgeodb_loc_set(shdb_t *db, shgeo_t *geo, shloc_t *loc)
{
  shnum_t lat, lon;
  shdb_idx_t rowid;
  shgeo_t db_geo;
  char lat_str[256];
  char lon_str[256];
  char alt_str[256];
  char stamp_str[256];
  char prec_str[256];
  char name_str[256];
  uint32_t prec;
  shtime_t stamp;
  int alt;
  int err;

  if (!*loc->loc_name)
    return (SHERR_INVAL);

  err = shgeodb_rowid(db, SHGEO_COMMON, geo, &rowid);
  if (err) {
    /* no matching entry */
    err = shdb_row_new(db, SHGEO_COMMON, &rowid);
    if (err)
      return (err);
  }

  /* lower resolution to match type specified. */
  prec = SHGEO_PREC_SPOT; /* 5 */
  memcpy(&db_geo, geo, sizeof(shgeo_t));
  if (*loc->loc_type) {
    prec = shgeo_place_prec(loc->loc_type);
    shgeo_dim(&db_geo, prec);
  }

  alt = 0;
  lat = lon = 0;
  shgeo_loc(&db_geo, &lat, &lon, &alt);
  sprintf(lat_str, "%-5.5Lf", lat);
  sprintf(lon_str, "%-5.5Lf", lon);

  memset(name_str, 0, sizeof(name_str));
  strncpy(name_str, loc->loc_name, sizeof(name_str)-1);
  _lowercase_string(name_str);

  shdb_row_set(db, SHGEO_COMMON, rowid, "latitude", lat_str);
  shdb_row_set(db, SHGEO_COMMON, rowid, "longitude", lon_str);
  shdb_row_set(db, SHGEO_COMMON, rowid, "name", name_str);
  shdb_row_set(db, SHGEO_COMMON, rowid, "summary", loc->loc_summary);
  shdb_row_set(db, SHGEO_COMMON, rowid, "locale", loc->loc_locale);
  shdb_row_set(db, SHGEO_COMMON, rowid, "zone", loc->loc_zone);
  shdb_row_set(db, SHGEO_COMMON, rowid, "type", loc->loc_type);

  return (0);
}

int shgeodb_loc_set(shgeo_t *geo, shloc_t *loc)
{
  shdb_t *db;
  int err;

  db = shgeodb_open_user();
  if (!db)
    return (SHERR_IO);

  err = _shgeodb_loc_set(db, geo, loc);
  shdb_close(db);
  if (err)
    return (0);

  return (err);
}

int _shgeodb_loc_unset(shdb_t *db, shgeo_t *geo)
{
  shdb_idx_t rowid;
  int err;

  if (!db || !geo)
    return (SHERR_INVAL);

  err = shgeodb_rowid(db, SHGEO_COMMON, geo, &rowid);
  if (err)
    return (err);

  err = shdb_row_delete(db, SHGEO_COMMON, rowid);
  if (err)
    return (err);

  return (0);
}

int shgeodb_loc_unset(shgeo_t *geo)
{
  shdb_t *db;
  int err;

  db = shgeodb_open_user();
  if (!db)
    return (SHERR_IO);

  err = _shgeodb_loc_unset(db, geo);
  shdb_close(db);
  if (err)
    return (0);

  return (err);
}

_TEST(shgeo_db)
{
  shloc_t cmp_loc;
  shgeo_t cmp_geo;
  shgeo_t geo;
  shloc_t loc;
  shnum_t lat = 46.8;
  shnum_t lon = 113.9;
  int err;


  memset(&geo, 0, sizeof(geo));
  memset(&loc, 0, sizeof(loc));

  shgeo_set(&geo, lat, lon, 0);

  strcpy(loc.loc_name, "Missoula, MT");
  strcpy(loc.loc_locale, "US");
  strcpy(loc.loc_zone, "America/Montana/Missoula");
  strcpy(loc.loc_type, "AREA");

  err =  shgeodb_loc_set(&geo, &loc);
  _TRUE(0 == err);

  err = shgeodb_loc(&geo, &cmp_loc);
  _TRUE(err == 0);
  _TRUE(0 == strcasecmp(loc.loc_name, cmp_loc.loc_name));

  err = shgeodb_scan(lat, lon, 0.001, &cmp_geo);
  _TRUE(0 == err);
  _TRUE(shgeo_cmp(&geo, &cmp_geo, SHGEO_PREC_SPOT));

  memset(&cmp_geo, 0, sizeof(cmp_geo));
  err = shgeodb_place("Missoula, MT", &cmp_geo);
  _TRUE(err == 0);
  _TRUE(shgeo_cmp(&geo, &cmp_geo, SHGEO_PREC_SPOT));
 
  err = shgeodb_place("Nowhere, USA", &cmp_geo);
  _TRUE(err == SHERR_NOENT);

}


/* ** shgeo_place ** */

#define MAX_PLACE_TABLE_SIZE 84
typedef struct place_table_t
{
  const char *name; /* code */
  const char *label; /* description */
  int prec; /* precision */
} place_table_t;
static struct place_table_t _place_table[MAX_PLACE_TABLE_SIZE] = {
  /* region */
  { "AREA", "General Area", 1 },
  { "MT", "Mountain", 1 },
  { "STM", "River Stream", 1 },
  { "SPNG", "Natural Spring", 1 },
  { "RSV", "Reservoir", 1 },
  { "INLT", "Water Inlet", 1 },
  { "LK", "Lake", 1 },
  { "RDG", "Mountain Ridge", 1 },
  { "CLF", "Mountain Cliff", 1 },
  { "SWMP", "Swamp", 1 },
  { "ISL", "Island", 1 },
  { "CRTR", "Crater", 1 },
  { "LAVA", "Lava", 1 },
  { "SEA", "Sea", 1 },
  { "GLCR", "Glacier", 1 },
  { "CNYN", "Canyon", 1 },
  { "DSRT", "Desert", 1 },

  /* regional area */
  { "MUNI", "Municipal Zone", 2 },
  { "MALL", "Mall", 2 },
  { "SCH", "School", 2 },
  { "PRK", "Recreation Area", 2 },
  { "AIR", "Airplace/Jet Landing", 2 },
  { "DAM", "Water Dam", 2 },
  { "CMTY", "Cemetery", 2 },
  { "MAR", "Marina", 2 },
  { "TOWR", "Radio Tower", 2 },
  { "VAL", "Mountain Valley", 2 },
  { "PT", "Mountain Point", 2 },
  { "LNDF", "Landfill", 2 },
  { "TRL", "Hiking Trail", 2 },
  { "BDG", "Bridge", 2 },
  { "INDS", "Industrial Park", 2 },
  { "CTR", "Medical Facility", 2 },
  { "FLD", "Stadium/Athletic Field", 2 },
  { "UNIV", "University", 2 },
  { "CHN", "Water Channel", 2 },
  { "CNL", "Canal", 2 },
  { "LEV", "Dike", 2 },
  { "LIBR", "Library", 2 },
  { "MUS", "Museum", 2 },
  { "ZOO", "Zoo", 2 },
  { "CAVE", "Cave", 2 },
  { "FLL", "Waterfall/Overflow", 2 },
  { "ARCH", "Natural Bridge", 2 },
  { "RES", "Wilderness", 2 },
  { "GDN", "Arbor/Garden", 2 },
  { "SQR", "Squaer/Plaza", 2 },
  { "FRM", "Farm", 2 },
  { "BNCH", "River Bench", 2 },
  { "ISTH", "Isthmus", 2 },
  { "RECR", "Racetrack", 2 },
  { "PND", "Pond", 2 },
  { "VIN", "Vineyard", 2 },
  { "RUIN", "Ruins", 2 },
  { "BSNU", "Basin", 2 },
  { "FLTU", "Flats", 2 },
  { "HLL", "Hill", 2 },
  { "PASS", "Mountain Pass", 2 },

  /* point of interest */
  { "SLP", "Mountain Slide", 3 },
  { "RK", "Boulder", 3 },
  { "PLAT", "Plateu", 3 },
  { "PO", "Post Office", 3 },
  { "TMPL", "Religious Temple", 3 },
  { "FISH", "Fishing Hole", 3 },
  { "WHRF", "Wharf", 3 },
  { "THTR", "Theater", 3 },
  { "WLL", "Well", 3 },
  { "BCH", "Beach", 3 },
  { "RPDS", "Ripple/Shoal", 3 },
  { "MNMT", "Monument", 3 },
  { "HUT", "Hut", 3 },
  { "DCK", "Dock", 3 },
  { "SPNT", "Natural Spa", 3 },
  { "OBS", "Observatory", 3 },
  { "PIER", "Pier", 3 },
  { "MISC", "Miscellaneous", 3 },
  { "OBPT", "Observation Point", 3 },

  /* section */
  { "FRST", "Forest", 4 },
  { "PLN", "Prairie", 4 },
  { "STN", "Ranger Station", 4 },
  { "MDW", "Meadow", 4 },
  { "GRV", "Grove", 4 },
  { "PK", "Peak", 4 },

  /* spot */
  { "SPOT", "Specific Spot", 5 }

};

const char *shgeo_place_desc(char *code)
{
  int idx;

  for (idx = 0; idx < MAX_PLACE_TABLE_SIZE; idx++) {
    if (0 == strcasecmp(_place_table[idx].name, code))
      return (_place_table[idx].label); 
  }

  return (code);
}

int shgeo_place_prec(char *code)
{
  int idx;

  for (idx = 0; idx < MAX_PLACE_TABLE_SIZE; idx++) {
    if (0 == strcasecmp(_place_table[idx].name, code))
      return (_place_table[idx].prec); 
  }

  return (SHGEO_PREC_SECTION); /* default */
}

const char **shgeo_place_codes(void)
{
  static char **str_l;

  if (!str_l) {
    int idx;

    str_l = (char **)calloc(MAX_PLACE_TABLE_SIZE + 1, sizeof(char *));
    if (!str_l)
      return (NULL);

    for (idx = 0; idx < MAX_PLACE_TABLE_SIZE; idx++) {
      str_l[idx] = strdup(_place_table[idx].name); 
    }
  }
 
  return ((const char **)str_l);
}



