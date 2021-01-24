
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

#include "share.h"

int shpkg_cert_clear(shpkg_t *pkg)
{
  return (shesig_remove_alias(shpkg_name(pkg)));
#if 0
  SHFL *file;
  shfs_t *fs;
  char path[SHFS_PATH_MAX];
  int err;

  if (pkg->pkg.pkg_cert.ver == 0)
    return;

  /* remove previous refs */
  sprintf(path, "pkg/%s", shpkg_name(pkg));
  fs = shfs_sys_init(SHFS_DIR_CERTIFICATE, path, &file);
  err = shfs_file_remove(file);
  shfs_free(&fs);
  if (err)
    return (err);

  return (0);
#endif
}

#if 0
int shpkg_cert_sign(shpkg_t *pkg, shesig_t *cert)
{
  char path[SHFS_PATH_MAX];
  int err;

 if (!pkg || !cert)
   return (SHERR_INVAL);

  /* apply certificate specified to package */
  memcpy(&pkg->pkg.pkg_cert, cert, sizeof(pkg->pkg.pkg_cert));
  err = shpkg_info_write(pkg);
  if (err) {
    shesig_free(&cert);
    return (err);
  }

  /* generate package reference for certificate */
  sprintf(path, "pkg/%s", shpkg_name(pkg));
  err = shfs_cert_save(cert, path);
  if (err)
    return (err);

  return (0);
}
#endif
 
int shpkg_cert_file(shpkg_t *pkg, SHFL *file)
{
  shkey_t *key;
  shbuf_t *buff;
  shbuf_t *enc_buff;
  unsigned char *enc_data;
  size_t enc_len;
  int err;

  buff = shbuf_init();
  err = shfs_read(file, buff);
  if (err)
    return (err);

  key = (shkey_t *)shesig_sub_sig(&pkg->pkg.pkg_cert);
  err = shencode(shbuf_data(buff), shbuf_size(buff),
    &enc_data, &enc_len, key);
  shbuf_free(&buff);
  if (err)
    return (err);

  enc_buff = shbuf_map(enc_data, enc_len);
  err = shfs_write(file, enc_buff);
  free(enc_data);
  free(enc_buff);
  if (err)
    return (err);

  return (0);
}

