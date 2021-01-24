
/*
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
 */  

#include <stdio.h>
#include "share.h"
#include "sharetool.h"

char *shjson_Print(shjson_t *item);
 

int share_info_get(shkey_t *name_key)
{
  shctx_t ctx;
  shjson_t *j;
  int err;

  err = shctx_get_key(name_key, &ctx);
  if (err)
    return (err);

  if (!(run_flags & PFLAG_VERBOSE)) {
    if (ctx.ctx_data) {
      fwrite(ctx.ctx_data, ctx.ctx_data_len, 1, sharetool_fout);
      if (strlen(ctx.ctx_data) == ctx.ctx_data_len)
        fprintf(sharetool_fout, "\n");
    }
  } else {
    fprintf(sharetool_fout,
        "Key: %s\n",
        shkey_shr160_print(&ctx.ctx_key));

    fprintf(sharetool_fout,
        "Expires: %s\n",
        shstrtime(ctx.ctx_expire, "%T %D"));

    j = shjson_init(ctx.ctx_data);
    if (j) {
      char *text = shjson_Print(j);
      fprintf(sharetool_fout, "%s\n", text);
      free(text);
    } else {
      fwrite(ctx.ctx_data, ctx.ctx_data_len, 1, sharetool_fout);
      fprintf(sharetool_fout, "\n");
    }
  }

  return (0);
}

int share_info_set(shkey_t *name_key, char *name, shbuf_t *buff)
{
  shjson_t *j;
  char *text;
  char *val;
  int err;
  int i;

  if (shbuf_size(buff) > 4096) {
    return (SHERR_2BIG);
  }

  err = shctx_set_key(name_key, shbuf_data(buff), shbuf_size(buff));
  if (err)
    return (err);
  
  return (0);
}

int share_info_set_json(shkey_t *name_key, char *name, shjson_t *j)
{
  char *text;
  int err;
  int i;

  text = shjson_print(j);
  if (!text)
    return (SHERR_NOMEM);

  if (strlen(text) > 4095) {
    return (SHERR_2BIG);
  }

  err = shctx_set_key(name_key, text, strlen(text));
  free(text);
  if (err)
    return (err);
  
  return (0);
}

int share_info(char **args, int arg_cnt, int pflags)
{
  shkey_t *ctx_key;
  shbuf_t *buff;
  shjson_t *ctx_json;
  char **data;
  char *ctx_name;
  char *tok;
  char *val;
  char name[MAX_SHARE_NAME_LENGTH];
  int data_max;
  int data_nr;
  int err;
  int idx;
  int i;

  data_max = arg_cnt + 1;
  data = (char **)calloc(data_max, sizeof(char *));
  if (!data)
    return (SHERR_NOMEM);

  ctx_key = NULL;
  ctx_name = NULL;
  ctx_json = NULL;

  for (i = 1; i < arg_cnt; i++) {
    if (0 == strcmp(args[i], "-k") ||
        0 == strcmp(args[i], "--key")) {
      if ((i+1) >= arg_cnt) {
        fprintf(sharetool_fout, "error: no key identifier specified.\n");
        return (1);
      }

      ctx_key = shkey_shr160_gen(args[i+1]);
      if (!ctx_key) {
        fprintf(sharetool_fout, "error: invalid key identifier specified.\n");
        return (1);
      }

      args[i++] = NULL;
      args[i] = NULL;
    }
  }

  for (i = 1; i < arg_cnt; i++) {
    if (!ctx_key) {
      ctx_key = shkey_dup(shctx_key(args[i]));
      ctx_name = strdup(args[i]); 
      args[i] = NULL;
      break;
    }
  }

  buff = shbuf_init();
  for (i = 1; i < arg_cnt; i++) {
    if (args[i] == NULL)
      continue;

    if (args[i][0] == '@') {
      if (run_flags & PFLAG_JSON) {
        if (shbuf_size(buff) != 0)
          shbuf_catstr(buff, "\n");
      }

      /* read from file */
      err = shfs_mem_read(args[i] + 1, buff);
      if (err) {
        fprintf(sharetool_fout, "error: file \"%s\": %s.\n", args[i] + 1, sherrstr(err));
        shbuf_free(&buff);
        return (1);
      }
      if (shbuf_size(buff) > 4096) {
        fprintf(sharetool_fout, "error: file \"%s\": %s.\n", args[i] + 1, sherrstr(SHERR_2BIG));
        shbuf_free(&buff);
        return (1);
      }

      continue;
    }

    if (run_flags & PFLAG_JSON) {
      if (shbuf_size(buff) != 0)
        shbuf_catstr(buff, "\n");
    } else {
      if (shbuf_size(buff) != 0)
        shbuf_catstr(buff, " ");
    }
    shbuf_catstr(buff, args[i]);
  }

  if (run_flags & PFLAG_JSON) {
    ctx_json = shjson_init(NULL);

    tok = strtok(shbuf_data(buff), "\r\n");
    while (tok) {
      idx = stridx(tok, '=');

      memset(name, 0, sizeof(name));
      if (idx != -1) {
        strncpy(name, tok, idx);
        val = tok + (idx + 1);
      } else {
        strncpy(name, tok, sizeof(name)-1);
        val = "";
      }

      if (*tok)
        shjson_str_add(ctx_json, name, val);

      tok = strtok(NULL, "\r\n");
    }
  }

  if (!ctx_key) {
    fprintf(sharetool_fout, "error: no identifier specified.\n");
    return (1);
  }

  if (run_flags & PFLAG_UPDATE) {
    if (!ctx_name) {
      fprintf(sharetool_fout, "error: identifier must be literal.\n");
      return (1);
    }

    if (ctx_json) {
      err = share_info_set_json(ctx_key, ctx_name, ctx_json);
    } else {
      err = share_info_set(ctx_key, ctx_name, buff);
    }
    if (err) {
      fprintf(sharetool_fout, "error: unable to set context \"%s\": %s.", ctx_name, sherrstr(err));
      goto done;
    }
  }

  if (ctx_name) {
    if (run_flags & PFLAG_VERBOSE) {
      fprintf(sharetool_fout, "Name: \"%s\"\n", ctx_name);
    }
  }

  err = share_info_get(ctx_key);
  if (err) {
    if (ctx_name)
      fprintf(sharetool_fout, "error: context \"%s\": %s.\n", ctx_name, sherrstr(err));
    else
      fprintf(sharetool_fout, "error: context \"%s\": %s.\n", shkey_shr160_print(ctx_key), sherrstr(err));
    goto done;
  }
  
  /* success */
  err = 0;

done:

  if (ctx_key)
    shkey_free(&ctx_key);
  if (ctx_name)
    free(ctx_name);

  shbuf_free(&buff);
  shjson_free(&ctx_json);

  return (err);
}



