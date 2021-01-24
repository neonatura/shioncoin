
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
#include <sys/stat.h>
#include <libgen.h>

#ifndef P_tmpdir
#define P_tmpdir "/tmp"
#endif

static int _pref_expire_time = -1;

char *shcache_path(const char *tag)
{
  static char ret_path[PATH_MAX+1];
  uint32_t crc = shcrc(tag, strlen(tag));
  shkey_t *key = ashkey_str(tag);

#ifndef WINDOWS
	mkdir (P_tmpdir, 0777);
  sprintf(ret_path, "%s/.shcache_%-4.4x/", P_tmpdir, (crc % 65536));
#else
  sprintf(ret_path, "%s\\shcache_%-4.4x\\", getenv("TEMP"), (crc % 65536));
#endif

  mkdir(ret_path, 0777);
  strcat(ret_path, shkey_hex(key));

  return (ret_path);
}

int shcache_write(const char *tag, shbuf_t *buff)
{
  char pbuf[PATH_MAX+1];
  char *dir_path;
  char *path;
  time_t ttl;

  ttl = shcache_ttl();
  if (ttl == 0)
    return (0); /* all done */

  path = shcache_path(tag);

  memset(pbuf, 0, sizeof(pbuf));
  strncpy(pbuf, path, sizeof(pbuf)-1);
  dir_path = dirname(pbuf);
  utime(dir_path, NULL);

  return (shfs_mem_write(path, buff));
}

/**
 * The expiration time (in seconds) for when a cache entry is considered stale. 
 * @note Settable by the "cache.expire" share preference.
 */
time_t shcache_ttl(void)
{
  if (_pref_expire_time == -1)
    _pref_expire_time = (time_t)atol(shpref_get("cache.expire", "3600"));
  return (_pref_expire_time);
}

int shcache_read(const char *tag, shbuf_t *buff)
{
  struct stat st;
  char *path = shcache_path(tag);
  char pbuf[PATH_MAX+1];
  char *dir_path;
  time_t expire_t;
  time_t ttl;
  int err;

  ttl = shcache_ttl();
  if (ttl == 0) {
    return (SHERR_NOENT);
}

  expire_t = MAX(0, time(NULL) - ttl);

  memset(pbuf, 0, sizeof(pbuf));
  strncpy(pbuf, path, sizeof(pbuf)-1);
  dir_path = dirname(pbuf);
  err = stat(dir_path, &st);
  if (err) {
    return (errno2sherr());
	}

  if (st.st_atime < expire_t) {
    /* entire directory is expired */
    shcache_purge(dir_path);
    return (SHERR_NOENT);
  }

  err = stat(path, &st);
  if (err)
    return (errno2sherr());

  if (st.st_mtime < expire_t) {
    /* cache entry is expired */
    unlink(path);
    return (SHERR_NOENT);
  }

  if (!buff)
    return (0);

  return (shfs_mem_read(path, buff));
}

int shcache_fresh(const char *tag)
{
  return (0 == shcache_read(tag, NULL));
}


void shcache_purge(char *path)
{
  DIR *dir;
  struct stat stFileInfo;
  struct dirent *ent;
  char abs_filename[PATH_MAX+1];

  dir = opendir(path);
  if (!dir)
    return;

  memset(abs_filename, 0, sizeof(abs_filename));
  while (ent = readdir(dir)) {
    if (0 == strcmp(ent->d_name, ".") ||
        0 == strcmp(ent->d_name, ".."))
      continue;

    snprintf(abs_filename, PATH_MAX, "%s/%s", path, ent->d_name);
    if (lstat(abs_filename, &stFileInfo) < 0)
      continue;

    if(!S_ISDIR(stFileInfo.st_mode)) {
      unlink(abs_filename);
    }
  }
  (void) closedir (dir);

  (void) rmdir(path);
}


