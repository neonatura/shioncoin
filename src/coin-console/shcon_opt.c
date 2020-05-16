
/*
 * @copyright
 *
 *  Copyright 2014 Brian Burrell
 *
 *  This file is part of ShionCoin.
 *  (https://github.com/neonatura/shioncoin)
 *        
 *  ShionCoin is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version. 
 *
 *  ShionCoin is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with ShionCoin.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  @endcopyright
 */  

#include "shcon.h"

static shmap_t *_shcon_option_table;
#define OPT_LIST _shcon_option_table

int shcon_opt_init(void)
{
	char path[PATH_MAX+1];

  OPT_LIST = shmap_init();
  if (!OPT_LIST)
    return (SHERR_NOMEM);

	sprintf(path, "%sshc.conf", get_shioncoin_path());
	shcon_opt_load(path);

#ifdef WINDOWS
	sprintf(path, "%s\\.shc\\shc.conf", getenv("HOMEPATH"));
#else
	sprintf(path, "%s/.shc/shc.conf", getenv("HOME"));
#endif
	shcon_opt_load(path);

  return (0);
}

void shcon_opt_term(void)
{

  if (!OPT_LIST)
    return;

  shmap_free(&OPT_LIST);
  OPT_LIST = NULL;
}

const char *opt_str(char *opt_name)
{
  static char blank_str[16];
  const char *ret_str;

  ret_str = (const char *)shmap_get_str(OPT_LIST, ashkey_str(opt_name)); 
  if (!ret_str)
    return (blank_str);

  return (ret_str);
}

int opt_num(char *opt_name)
{
  return (atoi(opt_str(opt_name)));
}


double opt_fnum(char *opt_name)
{
  return (atof(opt_str(opt_name)));
}

int opt_bool(char *opt_name)
{
  return (opt_num(opt_name) ? TRUE : FALSE);
}

void opt_str_set(char *opt_name, char *opt_value)
{
  shmap_set_astr(OPT_LIST, ashkey_str(opt_name), opt_value);
}

void opt_num_set(char *opt_name, int num)
{
  char buf[64];

  memset(buf, 0, sizeof(buf));
  sprintf(buf, "%d", num);
  opt_str_set(opt_name, buf);
}

void opt_fnum_set(char *opt_name, double num)
{
  char buf[64];

  memset(buf, 0, sizeof(buf));
  sprintf(buf, "%f", num);
  opt_str_set(opt_name, buf);
}

void opt_bool_set(char *opt_name, int b)
{
  opt_num_set(opt_name, b ? TRUE : FALSE);
}

const char *opt_iface(void)
{
  return (opt_str(OPT_IFACE));
}

void shcon_opt_load(char *path)
{
	char name[256];
	char *tok, *val;
  char *data;
  char *line;
  size_t data_len;
  int err;

	err = shfs_read_mem(path, &data, &data_len);
	if (err)
		return (err);

	line = strtok(data, "\r\n");
	while (line) {
		if (!*line) goto next;
		if (*line == '#') goto next;

		tok = line;
		val = strchr(line, '=');
		if (!val) goto next;
		*val++ = '\000';

		memset(name, 0, sizeof(name));
		snprintf(name, sizeof(name)-1, "shcoind.%s", tok);
		opt_str_set(name, val);

next:
		line = strtok(NULL, "\r\n");
	}

}

const char *get_shioncoin_path(void)
{
	static char ret_path[PATH_MAX+1];

	if (!*ret_path) {
#ifdef WINDOWS
		char *str;

		str = getenv("ProgramData");
		if (!str)
			str = "C:\\ProgramData";

		sprintf(ret_path, "%s\\shioncoin\\", str);
		mkdir(ret_path, 0777);
#else
		strcpy(ret_path, "/var/lib/shioncoin/");
		mkdir(ret_path, 0777);
#endif
	}

	return (ret_path);
}

