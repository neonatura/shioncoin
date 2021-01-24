/*
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
 */  

#include "share.h"
#include "sharetool.h"


int sharetool_pref(char *subcmd)
{
  char tok[4096];
  char val[SHPREF_VALUE_MAX+1];

  memset(tok, 0, sizeof(tok));
  strncpy(tok, subcmd, sizeof(tok) - 2);
  strtok(tok, " ");
  if (!*tok) {
    return (SHERR_INVAL);
  }

  if (0 == strncmp(tok, "sys.", 4)) {
    return (SHERR_OPNOTSUPP);
  }

  memset(val, 0, sizeof(val));
  strncpy(val, subcmd + strlen(tok) + 1, sizeof(val) - 1);

  if (*val) {
    shpref_set(tok, val);
    printf ("Preference '%s' set: %s\n", tok, val);
  } else {
    const char *cur_val = shpref_get(tok, "");
    if (!*cur_val) {
      return (SHERR_NOENT);
    }
    printf ("Preference '%s': %s\n", tok, cur_val);
  }
  
  return (0);
}

