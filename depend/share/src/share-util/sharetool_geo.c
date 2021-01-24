
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
#include "sharetool.h"


int sharetool_geo_query(char *arg_str)
{
  shgeo_t geo;
  shloc_t loc;
  shnum_t lat, lon;
  char *place_str;
  unsigned int a, b, c, d;
  int err;
  int n;

  memset(&geo, 0, sizeof(geo));
  n = sscanf(arg_str, "geo:%Lf,%Lf", &lat, &lon);
  if (n == 2) {
    memset(&loc, 0, sizeof(loc));

    /* search exact match */
    shgeo_set(&geo, lat, lon, 0);
    err = shgeodb_loc(&geo, &loc);
    if (err) {
      /* perform regional scan */
      err = shgeodb_scan(lat, lon, 0.2, &geo); 
      if (err) {
        fprintf(sharetool_fout, "ERROR: lat/lon (%Lf,%Lf): %s.\n", lat, lon, sherrstr(err));
        return (SHERR_NOENT);
      }

      /* reference found location */
      shgeo_loc(&geo, &lat, &lon, NULL);

      /* obtain location info */
      err = shgeodb_loc(&geo, &loc);
      if (err) {
        fprintf(sharetool_fout, "ERROR: lat/lon (%Lf,%Lf): %s.\n", lat, lon, sherrstr(err));
        return (SHERR_NOENT);
      }
    }

    fprintf(sharetool_fout, "INFO: lat/lon (%Lf,%Lf) near '%s' (%s)\n", lat, lon, loc.loc_name, shgeo_place_desc(loc.loc_type));
    if (*loc.loc_summary) {
      fprintf(sharetool_fout, "INFO: Desc: %s (Zone: %s)\n", loc.loc_summary, *loc.loc_zone ? loc.loc_zone : "n/a");
    }
    return (0);
  }

  n = sscanf(arg_str, "%u.%u.%u.%u", &a, &b, &c, &d);
  if (n == 4) {
    char *addr_str = arg_str;

    memset(&geo, 0, sizeof(geo));
    err = shgeodb_host(addr_str, &geo);
    if (err) {
      fprintf(sharetool_fout, "ERROR: host '%s' not found: %s\n", addr_str, sherrstr(err));
      return (1);
    }

    shgeo_loc(&geo, &lat, &lon, NULL);
    fprintf(sharetool_fout, "INFO: host '%s': %Lf,%Lf\n", addr_str, lat, lon);

#if 0
memset(&geo, 0, sizeof(geo));
    err = shgeodb_scan(lat, lon, 0.5, &geo); 
    if (!err) {
      err = shgeodb_loc(&geo, &loc);
      if (!err) {
        printf("INFO: host '%s' near '%s' (%s)\n", addr_str, loc.loc_name, shgeo_place_desc(loc.loc_type));
      }
    }
#endif

    return (0);
  } 


  place_str = arg_str;
  memset(&geo, 0, sizeof(geo));
  err = shgeodb_place(place_str, &geo);
  if (err) {
    fprintf(sharetool_fout, "ERROR: place '%s' not found: %s\n", place_str, sherrstr(err));
  } else {
    shgeo_loc(&geo, &lat, &lon, NULL);
    fprintf(sharetool_fout, "INFO: place '%s': %Lf,%Lf\n", place_str, lat, lon);
  }
 
  return (0);
}

void sharetool_geo_input(char *label, char *ret_str, size_t ret_str_max)
{
  char ret_buf[1024];

  if (label)
    fprintf(stdout, "%s: ", label);
  fflush(stdout);

  memset(ret_buf, 0, sizeof(ret_buf));
  (void)fgets(ret_buf, sizeof(ret_buf)-1, stdin);
  if (*ret_buf && ret_buf[strlen(ret_buf)-1] == '\r')
    ret_buf[strlen(ret_buf)-1] = '\000';
  if (*ret_buf && ret_buf[strlen(ret_buf)-1] == '\n')
    ret_buf[strlen(ret_buf)-1] = '\000';

  strncpy(ret_str, ret_buf, ret_str_max);

}

#if 0
static void _strtolower(char *text)
{
  int len;
  int i;

  len = strlen(text);
  for (i = 0; i < len; i++)
    text[i] = tolower(text[i]);
}
#endif
static void _strtoupper(char *text)
{
  int len;
  int i;

  len = strlen(text);
  for (i = 0; i < len; i++)
    text[i] = toupper(text[i]);
}

int sharetool_geo_create(char *place_str)
{
  static const char **places;
  shnum_t lat, lon;
  shgeo_t geo;
  shloc_t loc;
  int err;
  int n;
  int i;

  memset(&geo, 0, sizeof(geo));
  n = sscanf(place_str, "geo:%Lf,%Lf", &lat, &lon);
  if (n != 2)
    return (SHERR_INVAL);

  memset(&loc, 0, sizeof(loc));
  shgeo_set(&geo, lat, lon, 0);
  if (0 == shgeodb_loc(&geo, &loc)) {
    fprintf(sharetool_fout, "Error: Location already exists at latitude %Lf and longitude %Lf.\n", lat, lon);
    return (SHERR_EXIST);
  }

  memset(&loc, 0, sizeof(loc));

  sharetool_geo_input("Location Name",
      loc.loc_name, sizeof(loc.loc_name)-1);

  sharetool_geo_input("Country Abreviation [US]",
      loc.loc_locale, sizeof(loc.loc_locale)-1);
  if (strlen(loc.loc_locale) != 2) {
    if (loc.loc_locale[0]) {
      printf("Warning: Unknown country abeviation \"%s\" -- defaulting to \"US\".\n", loc.loc_locale);
    }
    strcpy(loc.loc_locale, "US");
  }

  sharetool_geo_input("State/Provice []", 
      loc.loc_zone, sizeof(loc.loc_zone)-1);

  /* list codes */
  printf("\n");
  if (!places)
    places = shgeo_place_codes();
  if (places) {
    for (i = 0; places[i]; i++) {
      printf("%-12.12s ", places[i]);
      if (5 == (i % 6))
        printf("\n");
    }
    printf("\n");
  }
  sharetool_geo_input("Enter location type [AREA]",
      loc.loc_type, sizeof(loc.loc_type));
  _strtoupper(loc.loc_type);
  if (!*loc.loc_type)
    strcpy(loc.loc_type, "AREA");

  sharetool_geo_input("Enter an optional description []",
      loc.loc_summary, sizeof(loc.loc_summary));

  err = shgeodb_loc_set(&geo, &loc);
  if (err) {
    fprintf(sharetool_fout, 
        "Error: Unable to set location \"geo:%Lf,%Lf\": %s [sherr %d].",
        lat, lon, sherrstr(err), err);
    return (err);
  }

  fprintf(sharetool_fout,
      "Created new location \"geo:%Lf,%Lf\".\n", lat, lon);

  return (0);
}

int sharetool_geo(char **args, int arg_cnt)
{
  char place_str[1024];
  int is_set;
  int err;
  int i;

  if (arg_cnt < 1) {
    fprintf(sharetool_fout, "error: no archive specified.\n");
    return (SHERR_INVAL);
  }

  is_set = FALSE;
  memset(place_str, 0, sizeof(place_str)-1);
  for (i = 1; i < arg_cnt; i++) {
    if (0 == strcasecmp(args[i], "-s") ||
        0 == strcasecmp(args[i], "--set")) {
      is_set = TRUE;
      continue;
    }

    if (place_str[0])
      strncat(place_str, " ", sizeof(place_str) - strlen(place_str) - 1);
    strncat(place_str, args[i], sizeof(place_str) - strlen(place_str) - 1);
  }

  if (!is_set) {
    err = sharetool_geo_query(place_str);
    if (err)
      return (err);
  } else {
    err = sharetool_geo_create(place_str);
    if (err)
      return (err);
  }

  return (0);
}


