
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

#include "shcoind.h"
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>

#define OPT_TYPE_NULL 0
#define OPT_TYPE_BOOL 1
#define OPT_TYPE_NUM 2
#define OPT_TYPE_STR 3

typedef struct opt_t {
	const char *opt_name;
	int opt_type;
	int64_t opt_def;
	const char *opt_strdef;
	const char *opt_desc;
} opt_t;

static shmap_t *_proc_option_table;
#define OPT_LIST _proc_option_table

static opt_t _option_table[] = {
	{ OPT_DEBUG, OPT_TYPE_BOOL, 0, NULL,
		"Verbose logging information." },
	{ OPT_MAX_CONN, OPT_TYPE_NUM, 300, NULL,
		"The maximum number of socket connections." }, 
	{ OPT_PEER_SEED, OPT_TYPE_NUM, 1, NULL, 
		"Whether to auto-seed the core node peers." }, 
	{ OPT_NOTARY, OPT_TYPE_BOOL, 1, NULL,
		"Whether to participate in notary transactions." },
	{ OPT_ADMIN, OPT_TYPE_BOOL, 0, NULL,
		"Administrative RPC commands." },
	{ OPT_FREE_RELAY, OPT_TYPE_BOOL, 0, NULL,
		"Allow no-fee transactions (<= 512b)." },
	{ OPT_BAN_SPAN, OPT_TYPE_NUM, 21600, NULL,
		"The number of seconds to ban a node for suspicious activity." }, 
	{ OPT_BAN_THRESHOLD, OPT_TYPE_NUM, 1000, NULL,
		"The amount of suspicious behaviour before banning a node." },

	/* user concensus parameters */
	{ OPT_BLOCK_SIZE, OPT_TYPE_NUM, 4096000, NULL,
		"The preferred maximum block size." },
	{ OPT_MIN_FEE, OPT_TYPE_NUM, 1000, NULL,
		"The preferred minimum relay tx fee in sharetoshis." },

	/* network options */
	{ OPT_SHC_PORT, OPT_TYPE_NUM, 24104, NULL,
		"The port to accept incoming SHC service connections." },


	/* the stratum service provides a service for mining hardware to connect to in order to generate new blocks. */
#ifdef STRATUM_SERVICE
	{ OPT_SERV_STRATUM, OPT_TYPE_BOOL, 1, NULL,
		"The built-in stratum miner service." },
	{ OPT_STRATUM_PORT, OPT_TYPE_NUM, 9448, NULL, 
		"The socket port to listen for stratum connections." },
	{ OPT_STRATUM_WORK_CYCLE, OPT_TYPE_NUM, 15, NULL,
		"The maximum number of seconds between \"getwork\" notifications." },
#endif

	/* unless compiled with "--disable-rpc"; the RPC service provides a method to perform RPC commands against a virtual coin service. each virtual service is provided with it's own executable for communication. */
#ifdef RPC_SERVICE
	{ OPT_SERV_RPC, OPT_TYPE_BOOL, 1, NULL,
		"The RPC command service." },
	{ OPT_RPC_PORT, OPT_TYPE_NUM, 9447, NULL, 
		"The socket port to listen for RPC commands." }, 
	{ OPT_RPC_HOST, OPT_TYPE_STR, 0, "127.0.0.1",
		"The IP Address of the ethernet device to bind the RPC service to or a literal star \"*\" to allow any incoming network connection." },
#endif

#ifdef TESTNET_SERVICE
	{ OPT_SERV_TESTNET, OPT_TYPE_BOOL, 0, NULL,
		"The ShareCoin Testnet service." },
	{ OPT_TESTNET_PORT, OPT_TYPE_NUM, 26104, NULL,
		"The socket port to listen for testnet connections." },
#endif

	/* The EMC2 service is available when compiled with "--enable-emc2". */
#ifdef EMC2_SERVICE
	{ OPT_SERV_EMC2, OPT_TYPE_BOOL, 1, NULL,
		"The EMC2 currency service." },
	{ OPT_EMC2_PORT, OPT_TYPE_NUM, 41878, NULL, 
		"The socket port to listen for EMC2 connections." },
#endif

	/* The USDE service is available when compiled with "--enable-usde". */
#ifdef USDE_SERVICE
	{ OPT_SERV_USDE, OPT_TYPE_BOOL, 1, NULL,
		"The USDE currency service." },
	{ OPT_USDE_PORT, OPT_TYPE_NUM, 54449, NULL, 
		"The socket port to listen for USDE connections." },
#endif

	/* end of the line */
	{ "", OPT_TYPE_NULL, 0, "" },

};


static const char *opt_home_dir(void)
{
	static char ret_buf[PATH_MAX+1];

	if (!*ret_buf) {
		char* homedir = NULL;
		struct passwd *pw = NULL;

#ifdef HAVE_GETPWUID
		pw = getpwuid(getuid());
		if (pw)
			homedir = pw->pw_dir;
#endif

		if (!homedir) {
#ifdef WINDOWS
			homedir = getenv("HOMEDIR");
#else
			homedir = getenv("HOME");
#endif
		}
		if (homedir) {
			strncpy(ret_buf, homedir, sizeof(ret_buf)-1);
#ifdef WINDOWS
			if (*ret_buf && ret_buf[strlen(ret_buf)-1] == '\\')
				ret_buf[strlen(ret_buf)-1] = '\000';
#else
			if (*ret_buf && ret_buf[strlen(ret_buf)-1] == '/')
				ret_buf[strlen(ret_buf)-1] = '\000';
#endif
		}
	}

	return ((const char *)ret_buf);
}
void opt_print(void)
{
  char buf[512];
	int idx;

	for (idx = 0; _option_table[idx].opt_type != OPT_TYPE_NULL; idx++) {
		switch (_option_table[idx].opt_type) {
			case OPT_TYPE_BOOL:
				sprintf(buf, "%s set to \"%s\".", 
						_option_table[idx].opt_name,
						opt_bool(_option_table[idx].opt_name) ? "true" : "false");
				shcoind_info("option", buf); 
				break;
			case OPT_TYPE_NUM:
				sprintf(buf, "%s set to \"%d\".", 
						_option_table[idx].opt_name,
						opt_num(_option_table[idx].opt_name));
				shcoind_info("option", buf); 
				break;
			case OPT_TYPE_STR:
				sprintf(buf, "%s set to \"%s\".", 
						_option_table[idx].opt_name,
						opt_str(_option_table[idx].opt_name));
				shcoind_info("option", buf); 
				break;
		}
	}

}

/** Write out the defaults to "shc.conf". */ 
static void write_default_shc_conf_file(void)
{
	char path[PATH_MAX+1];
	const char *data;
	size_t data_len;
	int err;

	data = opt_config_default_print();
	if (!data)
		return;

#ifdef WINDOWS
	sprintf(path, "%s\\.shc\\shc.conf", opt_home_dir());
#else
	sprintf(path, "%s/.shc/shc.conf", opt_home_dir());
#endif
	data_len = strlen(data);
	(void)shfs_write_mem(path, data, data_len);

}

static void opt_set_defaults_datfile(void)
{
	char path[PATH_MAX+1];
	char *tok, *val;
	char *data;
	char *line;
	size_t data_len;
	int idx;
	int err;

#ifdef WINDOWS
	sprintf(path, "%s\\.shc\\shc.conf", opt_home_dir());
#else
	sprintf(path, "%s/.shc/shc.conf", opt_home_dir());
#endif
	err = shfs_read_mem(path, &data, &data_len);
	if (err) {
		/* try to write a default config file. */
		write_default_shc_conf_file();
		return;
	}

	line = strtok(data, "\r\n");
	while (line) {
		if (!*line) goto next;
		if (*line == '#') goto next;

		tok = line;
		val = strchr(line, '=');
		if (!val) goto next;
		*val++ = '\000';

		for (idx = 0; _option_table[idx].opt_type != OPT_TYPE_NULL; idx++) {
			if (0 == strcasecmp(tok, _option_table[idx].opt_name)) {
				switch (_option_table[idx].opt_type) {
					case OPT_TYPE_BOOL:
						opt_bool_set(_option_table[idx].opt_name, atoi(val));
						break;
					case OPT_TYPE_NUM:
						opt_num_set(_option_table[idx].opt_name, atoi(val));
						break;
					case OPT_TYPE_STR:
						opt_str_set(_option_table[idx].opt_name, val);
						break;
				}
				break;
			}
		}

next:
		line = strtok(NULL, "\r\n");
	}

}

static void opt_set_defaults_system(void)
{
	char opt_name[256];
  char buf[256];
	int idx;

  memset(buf, 0, sizeof(buf));

	for (idx = 0; _option_table[idx].opt_type != OPT_TYPE_NULL; idx++) {
		sprintf(opt_name, "shcoind.%s", _option_table[idx].opt_name);
		strncpy(buf, shpref_get(opt_name, ""), sizeof(buf)-1);
		if (!*buf) continue;

		switch (_option_table[idx].opt_type) {
			case OPT_TYPE_BOOL:
				strncpy(buf, shpref_get(opt_name, ""), sizeof(buf)-1);
				if (tolower(*buf) == 't')
					opt_bool_set(_option_table[idx].opt_name, TRUE);
				break;
			case OPT_TYPE_NUM:
				opt_num_set(_option_table[idx].opt_name, atoi(buf));
				break;
			case OPT_TYPE_STR:
				opt_str_set(_option_table[idx].opt_name, buf);
				break;
		}
	}

}

static void opt_set_defaults(void)
{
	int idx;

	/* hard-coded configurable defaults */
	for (idx = 0; _option_table[idx].opt_type != OPT_TYPE_NULL; idx++) {
		switch (_option_table[idx].opt_type) {
			case OPT_TYPE_BOOL:
				opt_bool_set(_option_table[idx].opt_name, _option_table[idx].opt_def);
				break;
			case OPT_TYPE_NUM:
				opt_num_set(_option_table[idx].opt_name, _option_table[idx].opt_def);
				break;
			case OPT_TYPE_STR:
				opt_str_set(_option_table[idx].opt_name, _option_table[idx].opt_strdef);
				break;
		}
	}

	/* libshare configuration settings */
	opt_set_defaults_system();

	/* "~/.shc/shc.conf" datafile */
	opt_set_defaults_datfile();

}

void opt_init(void)
{
  OPT_LIST = shmap_init();

  opt_set_defaults();
}

void opt_term(void)
{

  if (!OPT_LIST)
    return;

  shmap_free(&OPT_LIST);
  OPT_LIST = NULL;
}

int opt_num(const char *tag)
{
  void *v = shmap_get(OPT_LIST, ashkey_str(tag));
  return ((int)(uint64_t)v);
}

void opt_num_set(const char *tag, int num)
{
  void *v = (void *)(uint64_t)num;
  shmap_set(OPT_LIST, ashkey_str(tag), v);
}

const char *opt_str(const char *tag)
{
  char *str = shmap_get_str(OPT_LIST, ashkey_str(tag));
  return ((const char *)str);
}

void opt_str_set(const char *tag, char *str)
{
  shmap_set_astr(OPT_LIST, ashkey_str(tag), str);
}

int opt_bool(const char *tag)
{
  int b = opt_num(tag) ? TRUE : FALSE;
  return (b);
}

void opt_bool_set(const char *tag, int b)
{
  opt_num_set(tag, b ? TRUE : FALSE);
}

const char *opt_usage_print(void)
{
	static shbuf_t *ret_buff;
  char buf[512];
	int idx;

	if (!ret_buff)
		ret_buff = shbuf_init();
	else
		shbuf_clear(ret_buff);

	for (idx = 0; _option_table[idx].opt_type != OPT_TYPE_NULL; idx++) {
		memset(buf, 0, sizeof(buf));
		switch (_option_table[idx].opt_type) {
			case OPT_TYPE_BOOL:
				if (_option_table[idx].opt_def) {
					sprintf(buf, "\t--no-%s\n\t\t%s\n\n",
							_option_table[idx].opt_name, _option_table[idx].opt_desc);
				} else {
					sprintf(buf, "\t--%s\n\t\t%s\n\n", 
							_option_table[idx].opt_name, _option_table[idx].opt_desc);
				}
				break;
			case OPT_TYPE_NUM:
				sprintf(buf, "\t--%s=%d\n\t\t%s\n\n", 
						_option_table[idx].opt_name, 
						_option_table[idx].opt_def,
						_option_table[idx].opt_desc);
				break;
			case OPT_TYPE_STR:
				sprintf(buf, "\t--%s=%s\n\t\t%s\n\n", 
						_option_table[idx].opt_name, 
						_option_table[idx].opt_strdef,
						_option_table[idx].opt_desc);
				break;
		}
		shbuf_catstr(ret_buff, buf); 
	}

	return ((const char *)shbuf_data(ret_buff));
}

void opt_arg_interp(int argc, char **argv)
{
	char buf[256];
	char *opt_name;
	char *tok, *val;
	char *ptr;
	int num_val;
	int bool_val;
	int idx;
	int i;

	for (i = 1; i < argc; i++) {
		if (0 != strncmp(argv[i], "--", 2))
			continue;

		memset(buf, 0, sizeof(buf));
		strncpy(buf, argv[i] + 2, sizeof(buf)-1);

		tok = buf;
		val = strchr(buf, '=');
		if (val)
			*val++ = '\000';

		num_val = 0;
		bool_val = 1;
		if (0 == strncmp(tok, "no-", 3)) {
			bool_val = 0;
			tok += 3;
		}
		if (val)
			num_val = atoi(val);

		for (idx = 0; _option_table[idx].opt_type != OPT_TYPE_NULL; idx++) {
			if (0 == strcasecmp(_option_table[idx].opt_name, tok)) {
				switch (_option_table[idx].opt_type) {
					case OPT_TYPE_BOOL:
						opt_bool_set(_option_table[idx].opt_name, bool_val);
						break;
					case OPT_TYPE_NUM:
						opt_num_set(_option_table[idx].opt_name, num_val);
						break;
					case OPT_TYPE_STR:
						opt_str_set(_option_table[idx].opt_name, val?val:"");
						break;
				}
				break;
			}
		}
	}

}

const char *opt_config_default_print(void)
{
	static shbuf_t *ret_buff;
  char buf[1024];
	int idx;

	if (!ret_buff)
		ret_buff = shbuf_init();
	else
		shbuf_clear(ret_buff);

	for (idx = 0; _option_table[idx].opt_type != OPT_TYPE_NULL; idx++) {
		memset(buf, 0, sizeof(buf));
		switch (_option_table[idx].opt_type) {
			case OPT_TYPE_BOOL:
				sprintf(buf, 
						"\n"
						"#\n"
						"# %s\n",
						_option_table[idx].opt_desc);
				if (_option_table[idx].opt_def) {
					sprintf(buf+strlen(buf), "# Default: 1 (true)\n#%s=1\n",
							_option_table[idx].opt_name);
				} else {
					sprintf(buf+strlen(buf), "# Default: 0 (false)\n#%s=0\n",
							_option_table[idx].opt_name);
				}
				break;
			case OPT_TYPE_NUM:
				sprintf(buf,
						"\n"
						"#\n"
						"# %s\n"
						"# Default: %d\n"
						"#%s=%d\n",
						_option_table[idx].opt_desc,
						_option_table[idx].opt_def,
						_option_table[idx].opt_name, 
						_option_table[idx].opt_def);
				break;
			case OPT_TYPE_STR:
				sprintf(buf, 
						"\n"
						"#\n"
						"# %s\n"
						"# Default: %s\n"
						"#%s=%s\n", 
						_option_table[idx].opt_desc,
						_option_table[idx].opt_strdef,
						_option_table[idx].opt_name, 
						_option_table[idx].opt_strdef);
				break;
		}
		shbuf_catstr(ret_buff, buf); 
	}

	return ((const char *)shbuf_data(ret_buff));
}

