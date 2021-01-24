
/*
 * @copyright
 *
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
 *
 *  @endcopyright
 */

#include "share.h"

/* directly include diff library */
#include "shmem_diff_pool.c"
#include "shmem_diff_int.c"





static void buffcat_bytes(shbuf_t *buff, const char *bytes, uint32_t len)
{
	uint32_t i;
  char ch_str[64];

  memset(ch_str, 0, sizeof(ch_str));
	for (i = 0; i < len; ++i) {
		char ch = bytes[i];
		if (isprint(ch)) {
      ch_str[0] = ch;
      shbuf_cat(buff, ch_str, 1);
		} else {
			sprintf(ch_str, "\\x%02x", ((unsigned int)ch) & 0x00ffu);
      shbuf_catstr(buff, ch_str);
    }
	}

}

int shdiff(shbuf_t *buff, char *str_1, char *str_2)
{
	shdiff_diff *diff;
	shdiff_options opts;
	int pos, ct = 0, ct0 = 0;
	const shdiff_node *node;
  char ch_str[256];

  if (!buff)
    return (SHERR_INVAL);

  memset(&opts, 0, sizeof(opts));
  shdiff_options_init(&opts);

  opts.check_lines = 3; /* -C 3 style */

  diff = NULL;
	shdiff_diff_from_strs(&diff, &opts, str_1, str_2);
  if (!diff)
    return (SHERR_INVAL);

  shbuf_catstr(buff, "\n> \"");
	buffcat_bytes(buff, diff->t1, diff->l1);
  shbuf_catstr(buff, "\"\n");

	for (pos = diff->list.start; pos >= 0; pos = node->next) {
		node = shdiff_node_at(&diff->pool,pos);
		ct0++;
		if (node->len > 0)
			ct++;
		sprintf(ch_str, "%c\"", (node->op < 0) ? '-' : (node->op > 0) ? '+' : '=');
    shbuf_catstr(buff, ch_str);
		buffcat_bytes(buff, node->text, node->len);
    if (node->next >= 0) 
      strcpy(ch_str,"\", ");
    else
		  strcpy(ch_str, "\"\n");
    shbuf_catstr(buff, ch_str);
	}

	shbuf_catstr(buff, "< \"");
	buffcat_bytes(buff, diff->t2, diff->l2);
  shbuf_catstr(buff, "\"\n");

  return (0);
}


