
/*
 * @copyright
 *
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
 *
 *  @endcopyright
 */  

#include "shcon.h"

static char _input_buffer[10240];
static int run_state;

#define RUN_NONE 0
#define RUN_IDLE 10
#define RUN_PROMPT 20
#define RUN_EXEC 30

#define BS 8    /* backspace */
#define LF 10   /* newline */ 

int has_input(FILE *stream)
{
  struct timeval tv;
  fd_set read_fd;
  int err;
  int fd;

  fd = fileno(stream);
  if (fd < 0) {
    return (FALSE);
  }

  FD_ZERO(&read_fd);
  FD_SET(fd, &read_fd);

  memset(&tv, 0, sizeof(tv));
  err = select(fd + 1, &read_fd, NULL, NULL, &tv);
  if (err > 0)
    return (TRUE);

  return (FALSE);
}

#define MAX_ARGS 256
int shcon_stream_exec(char *text, shjson_t **resp_p)
{
  char *args[MAX_ARGS];
  size_t text_len;
  size_t of;
  int in_quote;
  int arg_idx;
  int err;
  int i;

  if (0 == strcasecmp(text, "exit") ||
      0 == strcasecmp(text, "quit")) {
    /* terminate program. */
    run_state = RUN_NONE;
    return (0);
  }

  for (i = 0; i < MAX_ARGS; i++)
    args[i] = NULL;

  of = 0;
  arg_idx = 0;
  in_quote = FALSE;
  text_len = strlen(text);
  for (i = 0; i < text_len; i++) {
    if (text[i] == '"') {
      if (!in_quote)
        in_quote = TRUE;
      else
        in_quote = FALSE;
      continue;
    }

    if (!in_quote && text[i] == ' ') {
      if (i > 0 && text[i-1] == ' ') continue; /* skip ws */
      /* alloc */
      args[arg_idx] = (char *)strdup(text + of);
      args[arg_idx][(i - of)] = '\000';
      arg_idx++;

      of = (i + 1);
      continue;
    }

    /* .. */
  }
  if (of < (text_len - 1)) {
    /* alloc */
    args[arg_idx] = (char *)strdup(text + of);
    args[arg_idx][(i - of)] = '\000';
    arg_idx++;
  }

  err = shcon_command(args, arg_idx, resp_p);

  for (i = 0; args[i]; i++)
    free(args[i]);

  return (err);
}

void shcon_stream_idle(void)
{
  usleep(50000); /* 100ms */
}

void shcon_stream_print(char *text)
{
  FILE *stream = _shcon_fout;

  if (!stream)
    return;

  fprintf(stream, "%s", text);
#if 0
  if (text[0] && text[0] > 32 && strlen(text) > 1)
    fprintf(stream, "\n");
#endif
  fflush(stream);
}

void shcon_stream_cycle(FILE *stream)
{
  static const char *prompt_str = "> ";
  shjson_t *resp;
  char buf[64];
  int err;
  int ch;

  /* header */
  shcon_stream_print("Type \"help\" for a list of commands.\n");
  shcon_stream_print("Type \"help <command>\" for command usage.\n");
  shcon_stream_print("\n");

  shcon_stream_print(prompt_str);

  run_state = RUN_IDLE;
  while (run_state != RUN_NONE) {
    switch (run_state) {
      case RUN_PROMPT:
        run_state = RUN_IDLE;
        shcon_stream_print(prompt_str);
        break;

      case RUN_EXEC:
        if (*_input_buffer) {
          resp = NULL;
          err = shcon_stream_exec(_input_buffer, &resp);
          if (err == 0) {
            if (resp)
              command_print(_shcon_fout, resp);
            shcon_stream_print("\n");
          } else {
            sprintf(buf, "error: %s [code %d].\n", sherrstr(err), err);
            shcon_stream_print(buf);
          }
        }

        if (run_state == RUN_EXEC)
          run_state = RUN_PROMPT;
        memset(_input_buffer, 0, sizeof(_input_buffer));
        break;

      case RUN_IDLE:
        if (!has_input(stream)) {
          shcon_stream_idle();
//          break;
        }

        ch = getc(stream);
        if (ch == '\000')
          break;
        if (ch == EOF) {
          /* halt program due to no more input available. */
          run_state = RUN_NONE;
          break;
        }

        if (ch == BS) {
          if (*_input_buffer)
            _input_buffer[strlen(_input_buffer)-1] = '\000';
          break;
        }

        if (ch == LF) {
          run_state = RUN_EXEC;
          break;
        }

        if (ch < 32) {
          /* ignore control chars */
          fprintf(stderr, "DBEUG: ignore char %d\n", ch);
          break;
        }

        if (strlen(_input_buffer) > sizeof(_input_buffer) - 2) {
          /* overflow */
          shcon_stream_print("error: input overflow.");
          memset(_input_buffer, 0, sizeof(_input_buffer));
          break;
        }

        /* add char to input buffer */
        sprintf(_input_buffer+strlen(_input_buffer), "%c", (unsigned char)ch);
        break;
    }
  }

}


