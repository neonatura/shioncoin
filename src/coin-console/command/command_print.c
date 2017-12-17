

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

#include "shcon.h"

extern char *shjson_Print(shjson_t *item);

void command_print_r(FILE *out, shjson_t *j)
{
  char *text;

  text = shjson_Print(j);
  if (!text) {
    shcon_log(SHERR_PROTO, "error decoding JSON");
    return;
  }

  if (0 != strcmp(text, "null"))
    fprintf(out, "%s\n", text);

  free(text);
}

void command_print_result(FILE *out, shjson_t *j)
{
  command_print_r(out, j);
}

void command_print_error(FILE *out, int err_code, char *tag)
{

  if (!err_code)
    return;

  fprintf(out, "Error Code: %d\n", err_code);
  fprintf(out, "Error: %s\n", sherrstr(err_code));
  if (tag && *tag)
    fprintf(out, "Message: %s\n", tag);

}

void command_print(FILE *out, shjson_t *j)
{
  shjson_t *node;

  node = shjson_obj_get(j, "result");
  if (node) {
    char *text = shjson_astr(j, "result", "");
    if (!text || !*text) {
      command_print_result(out, node);
    } else if (0 != strcmp(text, "null")) {
      fprintf(out, "%s\n", text); 
    }
  }

  node = shjson_obj_get(j, "error");
  if (node) {
    char *text = shjson_astr(j, "error", "");
    if (!text || !*text) {
      command_print_error(out,
          shjson_array_num(j, "error", 0),
          shjson_array_str(j, "error", 1));
    }
  }

} 
