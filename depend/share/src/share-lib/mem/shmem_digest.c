

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

#include "share.h"


char *shdigest(void *data, int32_t len)
{
  static char ret_buf[256];
  char buf[64];
  int32_t *int_ar;
  int i;

  memset(buf, 0, sizeof(buf));
  sh_sha256((unsigned char *)data, len, buf);
  int_ar = (uint32_t *)buf;

  memset(ret_buf, 0, sizeof(ret_buf));
  for (i = 0; i < 8; i++) {
    sprintf(ret_buf + strlen(ret_buf), "%-8.8x", int_ar[i]);
  }

  return (ret_buf);
}



_TEST(shdigest)
{
  char *data;
  char *ptr;

  data = (char *)calloc(10240, sizeof(char));
  memset(data, 'a', 10240);
  ptr = shdigest(data, 10240);
  free(data);

  _TRUE(strlen(ptr) == 64);
}






