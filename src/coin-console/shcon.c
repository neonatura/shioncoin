
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

#define SHCON_MAX_ARGS 64

void shcon_tool_version(char *prog_name)
{
  fprintf(stdout,
      "%s version %s\n"
      "\n"
      "Copyright 2013 Neo Natura\n"
      "Licensed under the GNU GENERAL PUBLIC LICENSE Version 3\n",
      prog_name,
      get_libshare_version());
}

void shcon_tool_usage(char *prog_name)
{
  fprintf(stdout,
      "Usage: %s [COMMAND] [PARAMS]\n"
      "Perform RPC operations on the share-coin daemon.\n"
      "\n"
      "Commands:\n"
      "\tUse the \"help\" command in order to list all available RPC operations.\n"
      "\n"
      "Visit 'http://docs.sharelib.net/' for libshare API documentation."
      "Report bugs to <support@neo-natura.com>.\n",
      prog_name
      );
}


int main(int argc, char *argv[])
{
  shjson_t *resp;
  char *args[SHCON_MAX_ARGS];
  char prog_name[PATH_MAX+1];
  char *ptr;
  int arg_idx;
  int err;
  int i;

  for (i = 1; i < argc; i++) {
    if (0 == strcmp(argv[i], "-v") ||
        0 == strcmp(argv[i], "--version")) {
      shcon_tool_version(argv[0]);
      return (0);
    }
    if (0 == strcmp(argv[i], "-h") ||
        0 == strcmp(argv[i], "--help")) {
      shcon_tool_usage(argv[0]);
      return (0);
    }
  }

  shcon_init();

  memset(prog_name, 0, sizeof(prog_name));
  strncpy(prog_name, argv[0], sizeof(prog_name));
  ptr = strrchr(prog_name, '/'); /* from end */
#ifdef WIN32
  if (!ptr)
    ptr = strrchr(prog_name, '\\'); /* from end */
#endif
  if (!ptr)
    ptr = prog_name;
  else
    ptr++;
  strtok(ptr, ".");
  if (!*ptr) ptr = "shc"; /* default */
  opt_str_set(OPT_IFACE, ptr);

  arg_idx = -1;
  for (i = 1; i < argc && i < (SHCON_MAX_ARGS-1); i++) {
    if (argv[i][0] == '-') {
      if (0 == strcmp(argv[i], "-V") ||
          0 == strcmp(argv[i], "--verbose")) {
        opt_bool_set(OPT_VERBOSE, TRUE);
      }
      if (0 == strcmp(argv[i], "-q") ||
          0 == strcmp(argv[i], "--quiet")) {
        opt_bool_set(OPT_QUIET, TRUE);
      }
/* DEBUG: TODO: "--output", "--input", "--host", "--port" */
      continue;
    }

    args[++arg_idx] = argv[i];
  }
  args[++arg_idx] = NULL;

  if (arg_idx == 0) {
/* DEBUG: TODO: command-line interpreter mode. */
    shcon_tool_usage(argv[0]);
    return (1);
  }

  resp = NULL;
  err = shcon_command(args, arg_idx, &resp);
  if (err) {
    shcon_log(err, "send command");
  } else if (resp) {
    command_print(stdout, resp);
  }  

  shcon_term();

  return (0);
}


