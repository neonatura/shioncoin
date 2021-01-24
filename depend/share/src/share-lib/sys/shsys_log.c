
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

#if defined(HAVE_SYS_RESOURCE_H)
#include <sys/resource.h>
#endif


#define SHLOG_INFO 1
#define SHLOG_WARNING 2
#define SHLOG_ERROR 3
#define SHLOG_RUSAGE 4

#define MAX_FLUSH_SPAN 5


static int _log_queue_id;

static FILE *_shlog_file;

static char _log_path[PATH_MAX+1];

static int _log_level;


int shlog_path_set(const char *path)
{
	struct stat st;

	if (0 != stat(path, &st) && /* does not exist */ 
			0 != mkdir(path, 0777)) /* cannot be made */
		return (errno2sherr());

	memset(_log_path, 0, sizeof(_log_path));
	strncpy(_log_path, path, sizeof(_log_path)-1);
	return (0);
}

const char *shlog_path(char *tag)
{

	if (!*_log_path) {
		if (!tag)
			tag = "share";

		/* default log directory */
#ifdef WINDOWS
		sprintf(_log_path, "%s\\%s\\", getenv("ProgramData"), tag);
#else
		sprintf(_log_path, "/var/log/%s/", tag);
#endif
		(void)mkdir(_log_path, 0777);
	}

	return ((const char *)_log_path);
}

static size_t shlog_mem_size(void)
{
  size_t mem_size;

  mem_size = 0;

#ifdef linux
  {
    FILE *fl = fopen("/proc/self/status", "r");
    if (fl) {
      char buf[256];

      while (fgets(buf, sizeof(buf) - 1, fl) != NULL) {
        if (0 == strncmp(buf, "VmSize:", strlen("VmSize:"))) {
          mem_size = (size_t)atol(buf + strlen("VmSize:"));
          break;
        }
      }
      fclose(fl);
    }
  }
#endif

  return (mem_size);
}

void shlog_write(shbuf_t *buff, int level, int err_code, char *log_str)
{
  static char log_path[PATH_MAX+1];
  char line[640];
  char *beg_line;
  size_t mem_size;

  if (!buff)
    return;

  if (!*log_path) {
		char *label;
    shpeer_t peer;

    memcpy(&peer, ashpeer(), sizeof(peer));
		label = (!*peer.label ? PACKAGE_NAME : peer.label);
		sprintf(log_path, "%s%s.log", shlog_path(label), label); 
  }
  if (*log_path && !_shlog_file) {
    _shlog_file = fopen(log_path, "ab");
  }

  beg_line = shbuf_data(buff) + shbuf_size(buff);

  sprintf(line, "%s", shstrtime(shtime(), "[%x %T] "));
  shbuf_catstr(buff, line);

  if (level == SHLOG_ERROR) {
    shbuf_catstr(buff, "error");
  } else if (level == SHLOG_WARNING) {
    shbuf_catstr(buff, "warning");
  } else {
    shbuf_catstr(buff, "info");
  }

  if (err_code) {
    memset(line, 0, sizeof(line));
    snprintf(line, sizeof(line) - 1,
        ": %s [code %d]", strerror(-(err_code)), (err_code));
    shbuf_catstr(buff, line);
  }

  if (log_str) {
    shbuf_catstr(buff, ": ");
    shbuf_catstr(buff, log_str);
  }

  mem_size = shlog_mem_size();
  if (mem_size > 100000) {
    sprintf(line, " (mem:%dm)", (mem_size / 1000)); 
    shbuf_catstr(buff, line);
  }

  shbuf_catstr(buff, "\n");

}

void shlog_free(void)
{

  if (_shlog_file) {
    fclose(_shlog_file);
    _shlog_file = NULL;
  }

}

int shlog(int level, int err_code, char *log_str)
{
  static time_t last_day;
  static time_t last_flush;
  static shbuf_t *buff;
  time_t day;
  time_t now;
  int err;

	if (level < _log_level)
		return (0);

  if (!buff)
    buff = shbuf_init();
	if (!buff)
		return (ERR_NOMEM);

  now = time(NULL);
  day = now / 86400; 
  if (day != last_day) {
    // shlog_zcompr();  /* compress .YY.WW bin log file, removing prev zip */
		shbuf_lock(buff);
    shlog_free();
		shbuf_unlock(buff);
  }
  last_day = day;

	{
		shbuf_lock(buff);

		shbuf_clear(buff);
		shlog_write(buff, level, err_code, log_str);
		if (shbuf_data(buff) && _shlog_file) {
			fprintf(_shlog_file, "%s", shbuf_data(buff));
			if (last_flush < (now - MAX_FLUSH_SPAN)) {
				fflush(_shlog_file);
				last_flush = now;
			}
		}

		shbuf_unlock(buff);
	}

  return (0);
}

void sherr(int err_code, char *log_str)
{
  shlog(SHLOG_ERROR, err_code, log_str);
}

void shwarn(char *log_str)
{
  shlog(SHLOG_WARNING, 0, log_str);
}

void shinfo(char *log_str)
{
  shlog(SHLOG_INFO, 0, log_str);
}

void shlog_rinfo(void)
{
#if defined(HAVE_SYS_RESOURCE_H) && defined(HAVE_GETRUSAGE)
  struct rusage rusage;
  char rinfo_buf[256];

  memset(&rusage, 0, sizeof(rusage));
  getrusage(RUSAGE_SELF, &rusage);

  sprintf(rinfo_buf,
      "PROCESS [cpu(user:%d.%-6.6ds sys:%d.%-6.6ds) maxrss(%uk) flt(%uk) swaps(%uk) in-ops(%uk) out-ops(%uk)]",
      rusage.ru_utime.tv_sec, rusage.ru_utime.tv_usec,
      rusage.ru_stime.tv_sec, rusage.ru_stime.tv_usec,
      rusage.ru_maxrss, rusage.ru_majflt, rusage.ru_nswap,
      rusage.ru_inblock, rusage.ru_oublock);

  shinfo(rinfo_buf);
#endif
}

void shlog_level_set(int level /* SHLOG_XXX */)
{
	_log_level = MAX(0, MIN(MAX_SHLOG_LEVEL - 1, level));
}

int shlog_level(void)
{
	return (_log_level);
}

