/*
 * syntax: gcc -Wall -g -o test_run -lshare -lshare_sexe test_run.c
 *
 * A program to perform a test call against a SEXE shioncoin class.
 *
 * example: test_run BaseObject.sx verify
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <share.h>
#include <sexe.h>

static int sexe_ExecUpdateEvent(lua_State *L)
{
#if 0
	shjson_t *arg;

	lua_pop(L, 1); /* event name (second arg) */

	arg = sexe_table_get(L);
	if (arg)
		shjson_free(&arg);
#endif

	sexe_pushboolean(L, TRUE);
	return (1);
}

static int sexe_ContextGetTable(lua_State *L)
{
	const char *label = lua_tostring(L, 1);
	shjson_t *j;

	j = shjson_init(NULL);
	if (!j) {
		lua_pushnil(L);
		return (1);
	}

	shjson_str_add(j, "label", (char *)label);
	shjson_str_add(j, "value", "value");

	/* return JSON as an object table */
	sexe_table_set(L, j);
	shjson_free(&j);
	return (1);
}


static int sexe_ContextCreateEvent(lua_State *L)
{
	shjson_t *param;
	shjson_t *arg;
	int err;

	/* skip event name */
	lua_pop(L, 1);

	/* "Context Create" table argument */
	arg = sexe_table_get(L);

	/* runtime parameters */
	param = NULL;
	(void)sexe_pget(L, "param", &param);

	shjson_t *ctx_ar = shjson_array_add(param, "context");
	shjson_t *ctx_json = shjson_obj_add(ctx_ar, NULL);
	shjson_str_add(ctx_json, "label", shjson_str(arg, "label", ""));
	shjson_str_add(ctx_json, "value", shjson_str(arg, "value", ""));

	err = sexe_pset(L, "param", param);
	if (err) {
		sexe_pushboolean(L, FALSE);
		return (1);
	}

	/* return success */
	sexe_pushboolean(L, TRUE);
	return (1);
}


int main(int argc, char **argv)
{
	sexe_t *S;
	shjson_t *param;
	shjson_t *call_arg;
	shbuf_t *buff;
	char *ptr;
	char method[PATH_MAX+1];
	char *args[64];
	char *path;
	char *func;
	char *text;
	char class[PATH_MAX+1];
	size_t text_len;
	int err;
	int i;

	if (argc < 2) {
		fprintf(stderr, "syntax: test_run <class.sx> [<method> [<arg>, ..]]\n");
		return(1);
	}

	for (i = 0; i < 64; i++) {
		args[i] = NULL;
	}

	/* file containing class source code. */
	path = argv[1];

	/* class function being called */
	if (argc < 3)
		func = "verify";
	else
		func = argv[2];

	buff = shbuf_init();
	err = shfs_mem_read(path, buff);
	if (err) {
		return(1);
	}

	memset(class, 0, sizeof(class));
	ptr = strchr(path, '/');
	if (ptr) ptr++;
	else ptr = path;
	strncpy(class, ptr, sizeof(class)); 
	strtok(class, ".");

	param = NULL;
	err = shfs_read_mem("test_run.conf", &text, &text_len);
	if (!err) {
		param = shjson_init(text);
		if (!param)fprintf(stderr, "invalid config: %s\n", text);
		free(text);
	}
	if (!param) {
		param = shjson_init(NULL);
		shjson_str_add(param, "class", class);
		shjson_str_add(param, "sender", "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
		shjson_num_add(param, "value", 100);
		shjson_num_add(param, "height", 0);
	}
	shjson_str_add(param, "method", func);
	printf("PARAM: %s\n", shjson_print(param));

	/* load executable data */
	err = sexe_popen(buff, &S);
	shbuf_free(&buff);
	if (err) {
fprintf(stderr, "sexe_exec_popen: %s", sherrstr(err)); 
		return(1);
	}

//	sexe_pset(S, "param", param);

	/* process executable data into class */
	args[0] = argv[1];
	err = sexe_prun(S, 1, args);
	if (err) {
		fprintf(stderr, "ERROR: sexe_exec_prun: %s", sherrstr(err)); 
		return(1);
	}

	call_arg = shjson_array_add(param, "argument");
	for (i = 3; i < argc; i++)
		shjson_str_add(call_arg, NULL, argv[i]);

	/* call "InitEvent" event */
	if (!sexe_pevent(S, "InitEvent", param)) {
		fprintf(stderr, "ERROR: InitEvent\n");
		return (1);
	}


	lua_register(S, "shc_context_get", sexe_ContextGetTable);

	sexe_event_register(S, "ExecUpdateEvent", sexe_ExecUpdateEvent);
	sexe_event_register(S, "ContextCreateEvent", sexe_ContextCreateEvent);


	sprintf(method, "%s.%s", class, func); 
	err = sexe_pcall_json(S, method, param);
	if (err) {
		fprintf(stderr, "ERROR: %d = sexe_pcall_json('%s'): %s\n", err, method, shjson_print(param));
		return(1);
	}
	printf("CALL: %s\n", shjson_print(param));

	err = sexe_pget(S, "param", &param);
	if (err) {
		fprintf(stderr, "ERROR: sexe_exec_pget[arg]: %s", sherrstr(err)); 
		return(1);
	}
	printf("RUNTIME: %s\n", shjson_print(param));
	shjson_free(&param);

	sexe_pclose(S);
	return (0);
}
