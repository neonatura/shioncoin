
/*
 * @copyright
 *
 *  Copyright 2014 Neo Natura
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
		"The maximum number of socket connections allowed for all services." }, 
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
		"The preferred minimum relay tx fee in shionoshis." },

	/* network options */
	{ OPT_SHC_PORT, OPT_TYPE_NUM, 24104, NULL,
		"The port to accept incoming SHC service connections." },

	{ OPT_BECH32, OPT_TYPE_BOOL, 0, NULL,
		"Generate bech32 style coin addresses when supported." },

	/* the stratum service provides a service for mining hardware to connect to in order to generate new blocks. */
#ifdef STRATUM_SERVICE
	{ OPT_SERV_STRATUM, OPT_TYPE_BOOL, 1, NULL,
		"The built-in stratum miner service." },
	{ OPT_STRATUM_PORT, OPT_TYPE_NUM, 9448, NULL, 
		"The socket port to listen for stratum connections." },
	{ OPT_STRATUM_WORK_CYCLE, OPT_TYPE_NUM, 16, NULL,
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

	/* The shioncoin testnet service. */
#ifdef TESTNET_SERVICE
	{ OPT_SERV_TESTNET, OPT_TYPE_BOOL, 0, NULL,
		"The ShionCoin Testnet service." },
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

#ifdef STRATUM_SERVICE
#ifdef USE_ALGO_SHA256D
	{ OPT_STRATUM_SHA256D, OPT_TYPE_BOOL, 0, NULL,
		"Provide a stratum mining service for the SHA256D PoW algorthm." },
	{ OPT_STRATUM_SHA256D_PORT, OPT_TYPE_NUM, 9450, NULL, 
		"The socket port to listen for stratum SHA256D connections." },
#endif
#ifdef USE_ALGO_KECCAK
	{ OPT_STRATUM_KECCAK, OPT_TYPE_BOOL, 0, NULL,
		"Provide a stratum mining service for the KECCAK PoW algorthm." },
	{ OPT_STRATUM_KECCAK_PORT, OPT_TYPE_NUM, 9452, NULL, 
		"The socket port to listen for stratum KECCAK connections." },
#endif
#ifdef USE_ALGO_X11
	{ OPT_STRATUM_X11, OPT_TYPE_BOOL, 0, NULL,
		"Provide a stratum mining service for the X11 PoW algorthm." },
	{ OPT_STRATUM_X11_PORT, OPT_TYPE_NUM, 9454, NULL, 
		"The socket port to listen for stratum X11 connections." },
#endif
#ifdef USE_ALGO_BLAKE2S
	{ OPT_STRATUM_BLAKE2S, OPT_TYPE_BOOL, 0, NULL,
		"Provide a stratum mining service for the BLAKE2S PoW algorthm." },
	{ OPT_STRATUM_BLAKE2S_PORT, OPT_TYPE_NUM, 9456, NULL, 
		"The socket port to listen for stratum BLAKE2S connections." },
#endif
#ifdef USE_ALGO_QUBIT
	{ OPT_STRATUM_QUBIT, OPT_TYPE_BOOL, 0, NULL,
		"Provide a stratum mining service for the QUBIT PoW algorthm." },
	{ OPT_STRATUM_QUBIT_PORT, OPT_TYPE_NUM, 9458, NULL, 
		"The socket port to listen for stratum QUBIT connections." },
#endif
#ifdef USE_ALGO_GROESTL
	{ OPT_STRATUM_GROESTL, OPT_TYPE_BOOL, 0, NULL,
		"Provide a stratum mining service for the GROESTL PoW algorthm." },
	{ OPT_STRATUM_GROESTL_PORT, OPT_TYPE_NUM, 9460, NULL, 
		"The socket port to listen for stratum GROESTL connections." },
#endif
#ifdef USE_ALGO_SKEIN
	{ OPT_STRATUM_SKEIN, OPT_TYPE_BOOL, 0, NULL,
		"Provide a stratum mining service for the SKEIN PoW algorthm." },
	{ OPT_STRATUM_SKEIN_PORT, OPT_TYPE_NUM, 9462, NULL, 
		"The socket port to listen for stratum SKEIN connections." },
#endif
#ifdef TESTNET_SERVICE
	{ OPT_STRATUM_TESTNET, OPT_TYPE_BOOL, 0, NULL,
		"Provide a stratum mining service for the TESTNET coin interface." },
#endif
#endif /* STRATUM_SERVICE */

#if 0 /* TODO: */
	{ OPT_STRATUM_COLOR, OPT_TYPE_STR, 0, "",
		"A hexadecimal color code to enable stratum mining for the COLOR coin interface." },
#endif

	/** 
	 * HD Keys are derived individually per account. Retaining the "default"
	 * or "master" (the master is derived from the default) key for an account
	 * can regenerate all underlying HD addresses.
	 * Note: Disable this option for added security.
	 */
	{ OPT_HDKEY, OPT_TYPE_BOOL, 1, NULL,
		"Derive new wallet keys using a hierarhchically deterministic algorythm." },

	{ OPT_DILITHIUM, OPT_TYPE_BOOL, 0, NULL,
		"Use the Dilithium signing algorythm for new coin addresses." },

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
			/* a env. var that the shioncoin MSI installer creates based on the user who installs it. */
			homedir = getenv("SHCOIND_HOME");
			if (!homedir)
#ifdef WINDOWS
			/* kick back to windows set env. var. note that this is probably not defined for a 'system account'. */
				homedir = getenv("HOMEPATH");
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
	sprintf(path, "%s\\.shc\\", opt_home_dir());
#else
	sprintf(path, "%s/.shc/", opt_home_dir());
#endif
	mkdir(path, 0777);
	strcat(path, "shc.conf");
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


static const char *opt_set_environment_name(opt_t *opt)
{
	static char env_buf[1024];
	int len;
	int i;

	sprintf(env_buf, "SHCOIND_%s", opt->opt_name);

	len = strlen(env_buf);
	for (i = 0; i < len; i++) {
		if (ispunct(env_buf[i]))
			env_buf[i] = '_';
		else 
			env_buf[i] = toupper(env_buf[i]);
	}

	return (env_buf);
}

static void opt_set_environment_settings(void)
{
	char *env;
	int idx;

	for (idx = 0; _option_table[idx].opt_type != OPT_TYPE_NULL; idx++) {
		env = getenv(opt_set_environment_name(&_option_table[idx]));
		if (!env) continue;
		switch (_option_table[idx].opt_type) {
			case OPT_TYPE_BOOL:
				opt_bool_set(_option_table[idx].opt_name, !!atoi(env));
				break;
			case OPT_TYPE_NUM:
				opt_num_set(_option_table[idx].opt_name, atoi(env));
				break;
			case OPT_TYPE_STR:
				opt_str_set(_option_table[idx].opt_name, env);
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

	/* environment settings */
	opt_set_environment_settings();

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
