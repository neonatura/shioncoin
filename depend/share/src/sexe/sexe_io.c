
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

#define LUA_CORE
#include "sexe.h"
#include <stdio.h>

static FILE *sexe_stdin;
static FILE *sexe_stdout;
static FILE *sexe_stderr;
static FILE *sexe_null;

FILE *get_sexe_null(void)
{
	if (!sexe_null) {
		sexe_null = fopen("/dev/null", "rb+");
	}
	return (sexe_null);
}

void set_sexe_stdin(FILE *in)
{
	sexe_stdin = in;
}

void set_sexe_stdout(FILE *out)
{
	sexe_stdout = out;
}

void set_sexe_stderr(FILE *err)
{
	sexe_stderr = err;
}

FILE *get_sexe_stdin(void)
{
	if (!sexe_stdin)
		return (get_sexe_null());
	return (sexe_stdin);
}

FILE *get_sexe_stdout(void)
{
	if (!sexe_stdout)
		return (get_sexe_null());
	return (sexe_stdout);
}

FILE *get_sexe_stderr(void)
{
	if (!sexe_stderr)
		return (get_sexe_null());
	return (sexe_stderr);
}


/* combines string "tag" with a unique key referencing the module's name. */
static shkey_t *_sexe_serialize_key(lua_State *L, char *tag)
{
	static shkey_t ret_key;
	shkey_t *tkey;
	shkey_t tag_key;

	memcpy(&tag_key, ashkey_str(tag), sizeof(tag_key));
	tkey = shkey_xor(&L->pname, &tag_key);
	memcpy(&ret_key, tkey, sizeof(ret_key));
	shkey_free(&tkey);

	return (&ret_key);
}

int sexe_io_serialize(sexe_t *S, char *tag, shjson_t *j)
{
  shkey_t *key;
  char path[PATH_MAX+1];
  char *ptr;
  int err;
  int fd;

	if (tag) {
		/* module + tag = key */
    key = _sexe_serialize_key(S, tag);
	} else {
		/* psuedo-null */
    key = ashkey_num(0);
	}

  sprintf(path, "/sys/data/sexe/io/%s", shkey_hex(key));

	if (!j) {
		/* erase serialized content */
		shfs_t *fs = shfs_init(NULL);
		err = shfs_unlink(fs, path);
		shfs_free(&fs);
	}
/*else*/ {
		/* store serialized [JSON] content */
		fd = shopen(path, "wb", NULL);
		if (fd < 0)
			return (errno2sherr());

		if (j) {
			ptr = shjson_print(j);
			shwrite(fd, ptr, strlen(ptr));
			free(ptr);
		}

		(void)shclose(fd);
	}

	return (0);
}

int sexe_io_unserialize(sexe_t *S, char *tag, shjson_t **j_p)
{
	struct stat st;
	shkey_t *key;
	shjson_t *j;
	char *json_text;
	char path[PATH_MAX+1];
	char *ptr;
	int err;
	int fd;

	*j_p = NULL;

	if (tag) {
		key = _sexe_serialize_key(S, tag);
	} else {
		key = ashkey_num(0);
	}

	sprintf(path, "/sys/data/sexe/io/%s", shkey_hex(key));
	fd = shopen(path, "rb", NULL);
	if (fd < 0)
		return (fd);

	memset(&st, 0, sizeof(st));
	(void)shfstat(fd, &st);

	json_text = (char *)calloc(st.st_size + 1, sizeof(char));
	if (!json_text)
		return (SHERR_NOMEM);

	err = shread(fd, json_text, st.st_size);
	shclose(fd);
	if (err < 0) {
		free(json_text);
		return (err);
	}

	j = shjson_init(json_text);
	free(json_text);
	if (!j)
		return (SHERR_ILSEQ);

	*j_p = j;
	return (0);
}

