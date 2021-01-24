
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

#include <stdio.h>
#include "share.h"
#include "sharetool.h"

static int _alg_format;
static int _alg_mode;

static void share_alg_arg(char *arg, unsigned char **data_p, size_t *data_len_p)
{
  int is_lit;
  int err;

  if (!data_p || !data_len_p)
    return;

  *data_p = arg;
  *data_len_p = 0;
  
  is_lit = TRUE;
  if (arg[0] == '@') {
    err = shfs_read_mem(arg + 1, data_p, data_len_p); 
    if (err)
      is_lit = FALSE;
  }

  if (is_lit) {
    *data_p = arg;
    *data_len_p = strlen(arg);
  }
 
}

static share_alg_priv(unsigned char *data, size_t data_len)
{
  unsigned char raw[32];
  shalg_t priv_key;
  char *text;
  int err;

  if (!data) {
    /* random */
    memcpy(raw, ashkey_uniq(), sizeof(raw)); 
    data = raw + sizeof(uint32_t);
    data_len = sizeof(shkey_t) - sizeof(uint32_t);

    if (run_flags & PFLAG_VERBOSE) {
      fprintf(sharetool_fout, "info: generated random secret (%d bytes).\n", data_len);
    }
  }

  if (run_flags & PFLAG_VERBOSE) {
    fprintf(sharetool_fout, "Secret: %s\n", shalg_encode(_alg_format, data, data_len));
  }
  err = shalg_priv(_alg_mode, priv_key, data, data_len);
  if (err)
    return (err);

  text = shalg_encode(_alg_format, (unsigned char *)priv_key, shalg_size(priv_key));
  if (!text)
    return (SHERR_INVAL);

  if (!(run_flags & PFLAG_QUIET)) {
    if (run_flags & PFLAG_VERBOSE) {
      fprintf(sharetool_fout, "Private Key: ");
    }
    fprintf(sharetool_fout, "%s\n", text);
  }

  return (0);
}

static share_alg_pub(shalg_t priv_key)
{
  shalg_t pub_key;
  char *text;
  int err;

  err = shalg_pub(_alg_mode, priv_key, pub_key);
  if (err)
    return (err);

  if (run_flags & PFLAG_VERBOSE) {
    fprintf(sharetool_fout, "Private Key: %s\n", shalg_print(_alg_format, priv_key));
  }

  text = shalg_encode(_alg_format,
      (unsigned char *)pub_key, shalg_size(pub_key));
  if (!text)
    return (SHERR_INVAL);

  if (!(run_flags & PFLAG_QUIET)) {
    if (run_flags & PFLAG_VERBOSE) {
      fprintf(sharetool_fout, "Public Key: ");
    }
    fprintf(sharetool_fout, "%s\n", text);
  }

  return (0);
}

static share_alg_sign(shalg_t priv_key, unsigned char *data, size_t data_len)
{
  shalg_t sig_key;
  char *text;
  int err;

  err = shalg_sign(_alg_mode, priv_key, sig_key, data, data_len);
  if (err)
    return (err);

  if (run_flags & PFLAG_VERBOSE) {
    fprintf(sharetool_fout, "Private Key: %s\n", shalg_print(_alg_format, priv_key));
  }

  text = shalg_encode(_alg_format,
      (unsigned char *)sig_key, shalg_size(sig_key));
  if (!text)
    return (SHERR_INVAL);

  if (!(run_flags & PFLAG_QUIET)) {
    if (run_flags & PFLAG_VERBOSE) {
      fprintf(sharetool_fout, "Signature-Size: %d bytes\n", shalg_size(sig_key));
      fprintf(sharetool_fout, "Signature: ");
    }
    fprintf(sharetool_fout, "%s\n", text);
  }

  return (0);
}

static share_alg_ver(shalg_t pub_key, shalg_t sig_key, unsigned char *data, size_t data_len)
{
  char *text;
  int err;

  err = shalg_ver(_alg_mode, pub_key, sig_key, data, data_len);
  if (err)
    return (err);

  if (run_flags & PFLAG_VERBOSE) {
    fprintf(sharetool_fout, "Public Key: %s\n", shalg_print(_alg_format, pub_key));
    fprintf(sharetool_fout, "Signature: %s\n", shalg_print(_alg_format, sig_key));
  }

  text = shalg_encode(_alg_format,
      (unsigned char *)sig_key, shalg_size(sig_key));
  if (!text)
    return (SHERR_INVAL);

  if (!(run_flags & PFLAG_QUIET)) {
    if (run_flags & PFLAG_VERBOSE) {
      fprintf(sharetool_fout, "Verfied: ");
    }
    fprintf(sharetool_fout, "%s\n", text);
  }


  return (0);
}



int sharetool_alg(char **args, int arg_cnt, int pflags)
{
  shalg_t pub_key;
  shalg_t priv_key;
  shalg_t sig_key;
  unsigned char *data;
  char opt_fmt[256];
  char opt_alg[256];
  char opt_mode[256];
  char *opt_arg1;
  char *opt_arg2;
  char *opt_arg3;
  size_t data_len;
  int err;
  int i;

  memset(opt_fmt, 0, sizeof(opt_fmt));
  memset(opt_alg, 0, sizeof(opt_alg));
  memset(opt_mode, 0, sizeof(opt_mode));

  opt_arg1 = NULL;
  opt_arg2 = NULL;
  opt_arg3 = NULL;

  for (i = 1; i < arg_cnt; i++) {
    if (0 == strcmp(args[i], "-b") ||
        0 == strcmp(args[i], "--bin")) {
      if (++i < arg_cnt) {
        strncpy(opt_fmt, args[i], sizeof(opt_fmt)-1);
      }
    } else if (0 == strcmp(args[i], "-a") ||
        0 == strcmp(args[i], "--alg")) {
      if (++i < arg_cnt) {
        strncpy(opt_alg, args[i], sizeof(opt_alg)-1);
      }
    } else if (!*opt_mode) {
      strncpy(opt_mode, args[i], sizeof(opt_mode));
    } else if (!opt_arg1) {
      opt_arg1 = args[i];
    } else if (!opt_arg2) {
      opt_arg2 = args[i];
    } else if (!opt_arg3) {
      opt_arg3 = args[i];
    }
  }

  _alg_format = shalg_fmt(opt_fmt);
  if (_alg_format < 0)
    _alg_format = SHFMT_HEX; /* default */
  if (run_flags & PFLAG_VERBOSE) {
    fprintf(sharetool_fout, 
        "Binary Format: %s\n", shalg_fmt_str(_alg_format));
  }


  _alg_mode = shalg_mode_str(opt_alg);
  if (_alg_mode < 0)
    _alg_mode = SHALG_SHA256;
  if (run_flags & PFLAG_VERBOSE) {
    fprintf(sharetool_fout, 
        "Hash Algorythm: %s\n", shalg_str(_alg_mode));
  }

  err = 0;
  data = NULL;
  data_len = 0;

  if (0 == strncmp(opt_mode, "ver", 3)) {
    /* verify signature */
    if (!opt_arg1) {
      fprintf(stderr, "error: no public key specified.\n");
      err = SHERR_INVAL;
      goto done;
    }
    if (!opt_arg2) {
      fprintf(stderr, "error: no message signature specified.\n");
      err = SHERR_INVAL;
      goto done;
    }
    if (opt_arg3) {
      share_alg_arg(opt_arg3, &data, &data_len); 
    }
    shalg_gen(_alg_format, opt_arg1, pub_key);
    shalg_gen(_alg_format, opt_arg2, sig_key);
    err = share_alg_ver(pub_key, sig_key, data, data_len);
  } else if (0 == strncmp(opt_mode, "sign", 4)) {
    /* sign message */
    if (!opt_arg1) {
      fprintf(stderr, "error: no private key specified.\n");
      err = SHERR_INVAL;
      goto done;
    }
    if (opt_arg2) {
      share_alg_arg(opt_arg2, &data, &data_len); 
    }
    shalg_gen(_alg_format, opt_arg1, priv_key);
    err = share_alg_sign(priv_key, data, data_len);
  } else if (0 == strncmp(opt_mode, "pub", 3)) {
    /* derive a public key */
    if (!opt_arg1) {
      fprintf(stderr, "error: no private key specified.\n");
      err = SHERR_INVAL;
      goto done;
    }
    shalg_gen(_alg_format, opt_arg1, priv_key);
    err = share_alg_pub(priv_key);
  } else {
    /* generate a private key */
    if (opt_arg1) {
      share_alg_arg(opt_arg1, &data, &data_len); 
    }
    err = share_alg_priv(data, data_len);
  }



done:

  return (err);
}



