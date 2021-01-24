
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
 *
 *  @file sexe.h
 *  @brief Utilities to compile and run SEXE bytecode.
 *  @date 2014
 *
 */


#ifndef __SHARE_LIB__SEXE_H__
#define __SHARE_LIB__SEXE_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "share.h"
#include <stdio.h>
#include <string.h>

/**
 * @mainpage SEXE Programming Language Reference Manual
 *
 *  SEXE is a programming language based on Lua. This libshare project aims to introduce the ability to run compiled SEXE bytecode on local disk, sharefs partition, and on remote machines (i.e. modular deployment).
 *
 *  All source code for SEXE compiled bytecode is written in the Lua programming language syntax. (PUC RIO: http://www.lua.org/)
 *
 *  The compiler "sxc", interpreter "sx", and symbol lister "readsexe" progams distributed with libshare will use your current working directory when reading and writing files.
 *
 * <p>
 * Reserved keywords:
 *  - \subpage sexe_reserved_public "public"

 * <p>
 * System Libraries:
 *  - \subpage sexe_lib_string "String Functions"
 *  - \subpage sexe_lib_math "Math Functions"
 *  - \subpage sexe_lib_time "Time Functions"
 *  - \subpage sexe_lib_io "File I/O"
 *  - \subpage sexe_lib_crypt "Crypt Functions"
 *  - \subpage sexe_lib_event "Event Functions"
 *  - \subpage sexe_lib_debug "Debug Functions"
 */

/**
	*  @page sexe_reserved_public The reserved public directive
	*  The "public" directive is used in order to declare functions or
	*  variables as persistently accessible. 
 *
	*  When a variable is declared as public a global variable will be created
	*  (with the same name) that is filled with the previous value assigned to
	*  it from when the script was ran previous. If the value has not been
	*  previously assigned value then it will be "nil". When the script returns 
	*  (is done running) the value will automatically be saved.
	* 
	*  Public variables are saved in the "userdata" global environment area. 
	*/

/**
	*  @page sexe_lib_string The standard sexe time library.
	*
	*  Syntax:
	*  lib "string"
	*
	*  SEXE String Library Functions:
	*
	*  - string.byte(_str[, _of[, _end]])
	*    Return a byte value of from a string.
	*  - string.char(_num[, _num[, ..]])
	*    Convert a series of numbers into a character string.
	*  - string.find(_str, _sub)
	*    Returns the start and end offset or nil.
	*
	*/

/**
	*  @page sexe_lib_time The standard sexe time library.
	*  
	*  Syntax:
	*  lib "time"
	*
	*  SEXE Time Library Functions:
	*
	*  * time.time()
  *
	*    Obtain a decimal-point representation of the current time.
  *
  *    <small><i>local t = time()</i></small>
	*
	*  * time.ctime(<time>)
	*
	*    Obtain a string displaying the specified <time>.
	*
	*    <small><i>print(time.ctime(time.time())</i></small>
	*
	*  * (int) time.utime(<time>)
	*
	*    Obtain a unix time-stamp from the specified <time>.
	*
	*    local unixtime = time.utime(time.time())
	*
	*  * time.strftime(<time>, <format>)
  *
	*    Generate a string using a posix (strftime) format.
	*
	*  * time.clock()
  *
	*    Return the current clock cycle as a fraction of a second
	*
	*  * time.date()
	*
	*    Retrieve the current time as an object. Format is: { year=%Y, month=%m, day=%d, hour=%H, min=%M, sec=%S, wday=%w+1, yday=%j, isdst=? }
	*
	*  * time.difftime(_time1, _time2)
	*
	*    Return the difference in seconds between _time1 and _time2. 
	*/
/**
	*  @page sexe_lib_io The standard sexe I/O library.
	*  
	*  Syntax:
	*  require 'io'
	*
	*
 *  The I/O library provides two different styles for file manipulation. The first one uses implicit file descriptors, that is, there are operations to set a default input file and a default output file, and all input/output operations are over those default files. The second style uses explicit file descriptors.
 * 
 * When using implicit file descriptors, all operations are supplied by table io. When using explicit file descriptors, the operation io.open returns a file descriptor and then all operations are supplied as methods by the file descriptor.
 * 
 * The table io also provides three predefined file descriptors with their usual meanings from C: io.stdin, io.stdout, and io.stderr.
 * 
 * A file descriptor is a userdata containing the file stream (FILE*), with a distinctive metatable created by the I/O library.
 * 
 * Unless otherwise stated, all I/O functions return nil on failure (plus an error message as a second result) and some value different from nil on success.
 * 
 *     file = io.open (filename [, mode])
 * 
 * This function opens a file, in the mode specified in the string mode. It returns a new file descriptor, or, in case of errors, nil plus an error message.
 * 
 * The mode string can be any of the following:
 * 
 *     "r" read mode (the default);
 *     "w" write mode;
 *     "a" append mode;
 *     "r+" update mode, all previous data is preserved;
 *     "w+" update mode, all previous data is erased;
 *     "a+" append update mode, previous data is preserved, writing is only allowed at the end of file. 
 * 
 * The mode string may also have a b at the end, which is needed in some systems to open the file in binary mode. This string is exactly what is used in the standard C function fopen.
 * 
 *     io.close ([file])
 * 
 * Equivalent to file:close. Without a file, closes the default output file.
 * 
 *     io.flush ()
 * 
 * Equivalent to file:flush over the default output file.
 * 
 *     io.input ([file])
 * 
 * When called with a file name, it opens the named file (in text mode), and uses it as the default input descriptor. When called with a file descriptor, it simply sets that file descriptor as the default input file. When called without parameters, it returns the current default input file descriptor.
 * 
 * In case of errors this function raises the error, instead of returning an error code.
 * 
 *     io.lines ([filename])
 * 
 * Opens the given file name in read mode and returns an iterator function that, each time it is called, returns a new line from the file. Therefore, the construction
 * 
 *     for line in io.lines(filename) do ... end
 * 
 * will iterate over all lines of the file. When the iterator function detects the end of file, it closes the file and returns nil (to finish the loop).
 * 
 * The call io.lines() (without a file name) is equivalent to io.input():lines(), that is, it iterates over the lines of the default input file.
 * 
 * io.output ([file])
 * 
 * Similar to io.input, but operates over the default output file.
 * 
 *     io.read (format1, ...)
 * 
 * Equivalent to io.input():read.
 * 
 *     io.tmpfile ()
 * 
 * Returns a descriptor for a temporary file. This file is open in update mode and it is automatically removed when the program ends.
 * 
 *     io.type (obj)
 * 
 * Checks whether obj is a valid file descriptor. Returns the string "file" if obj is an open file descriptor, "closed file" if obj is a closed file descriptor, and nil if obj is not a file descriptor.
 * 
 *     io.write (value1, ...)
 * 
 * Equivalent to io.output():write.
 * 
 *     f:close ()
 * 
 * Closes file f.
 * 
 *     f:flush ()
 * 
 * Saves any written data to file f.
 * 
 *     f:lines ()
 * 
 * Returns an iterator function that, each time it is called, returns a new line from file f. Therefore, the construction
 * 
 *     for line in f:lines() do ... end
 * 
 * will iterate over all lines of file f. (Unlike io.lines, this function does not close the file when the loop ends.)
 * 
 *     f:read (format1, ...)
 * 
 * Reads the file f, according to the given formats, which specify what to read. For each format, the function returns a string (or a number) with the characters read, or nil if it cannot read data with the specified format. When called without formats, it uses a default format that reads the entire next line (see below).
 * 
 * The available formats are
 * 
 *     "*n" reads a number; this is the only format that returns a number instead of a string.
 *     "*a" reads the whole file, starting at the current position. On end of file, it returns the empty string.
 *     "*l" reads the next line (skipping the end of line), returning nil on end of file. This is the default format.
 *     number reads a string with up to that number of characters, returning nil on end of file. If number is zero, it reads nothing and returns an empty string, or nil on end of file. 
 * 
 *     f:seek ([whence] [, offset])
 * 
 * Sets and returns the index position for file f, measured from the beginning of the file, to the position given by offset plus a base specified by the string whence, as follows:
 * 
 *     "set" base is position 0 (beginning of the file);
 *     "cur" base is current position;
 *     "end" base is end of the file; 
 * 
 * In case of success, function seek returns the final file position, measured in bytes from the beginning of the file. If this function fails, it returns nil, plus a string describing the error.
 * 
 * The default value for whence is "cur", and for offset is 0. Therefore, the call file:seek() returns the current file position, without changing it; the call file:seek("set") sets the position to the beginning of the file (and returns 0); and the call file:seek("end") sets the position to the end of the file, and returns its size.
 * 
 *     f:write (value1, ...)
 * 
 * Writes the value of each of its arguments to file f. The arguments must be strings or numbers. To write other values, use tostring or string.format before write. 
	*/

/**
	*  @page sexe_lib_crypt The standard sexe crypt library.
	*  
	*  Syntax:
	*  lib "crypt"
	*
	*  SEXE Crypt Library Functions:
	*
	*  * crypt.key(<string>|<number>)
  *
	*    Obtain a text-formatted key for encrypting or decrypting.
  *
  *    <small><i>local key = crypt.key(math.rand())</i></small>
	*
	*  * crypt.encrypt(<string>, <key>)
	*
	*    Encrypt a string using the provided key.
	*  
	*    <small><i>local enc_str = crypt.encrypt("hello", crypt.key("key"))</i></small>
	*
	*  * crypt.decrypt(<string>, <key>)
	*
	*    Decrypt an encrypted segment.
	*
	*    <small></i>local str = crypt.decrypt(crypt.encrypt("hellow", crypt.key("key")))</i></small>
	*
	*  * crypt.crc(<string>)
	*
	*    Create a checksum number representing the string.
	*
	*    <small><i>local crc = crypt.crc("hellow")</i></small>
	*
	*  * crypt.sha2(<string>)
	*
	*    Create a SHA-2 (256-byte) hash digest of the string.
	*
	*    <small><i>local sha = crypt.sha2("hellow")</i></small>
	*/
 
/**  @defgroup sexe SEXE Programming Language
 *  @{
 */

/**
 * The length (including null terminator) of a generic sexe name.
 */
#define MAX_SEXE_NAME_LENGTH 24


/**
 *  @defgroup sexe_lua The lua runtime sub-system.
 *  @{
 */
#include "sexe_lua.h"
#ifdef SEXELIB
#include "lobject.h"
#include "llimits.h"
#include "lauxlib.h"
#include "lstate.h"
#include "ldo.h"
#endif
/**
 *  @}
 */

/* execution binary bytecode prefix */
#define SEXE_SIGNATURE "\033sEX"

#define EVENT_INIT 0xff0001
#define EVENT_TERM 0xff0002
#define EVENT_TIMER 0xff0003

#ifdef SEXELIB
#include "lobject.h"
#include "llimits.h"
#include "lauxlib.h"
#include "lstate.h"
#include "sexe_bin.h"
#include "sexe_compile.h"
#include "sexe_public.h"
#include "sexe_test.h"
#include "sexe_event.h"
#include "sys/sexe_sys.h"
#else
typedef uint32_t Instruction;

void sexe_table_set(lua_State *L, shjson_t *json);

shjson_t *sexe_table_get(lua_State *L);

shjson_t *sexe_table_getdef(lua_State *L);



#endif

/**
 * Run an entire SEXE process from file.
 */
int sexe_exec(char *path, char **argv);

/**
 * Run an entire SEXE process from memory.
 */
int sexe_execm(shbuf_t *buff, char **argv);


/** 
 * Create a SEXE instance handle from a file.
 */
int sexe_popen_file(char *path, sexe_t **mod_p);

/** 
 * Create a SEXE instance handle from memory.
 */
int sexe_popen(shbuf_t *buff, sexe_t **mod_p);

/**
 * Run the main method from a pre-loaded SEXE process.
 *
 * @param S The SEXE process handle.
 * @param argc The number of arguments being passed.
 * @param argv An array of "main" arguments to pass to the process.
 * @note The first argument should be the path name of the executable.
 */
int sexe_prun(sexe_t *S, int argc, char **argv);

/**
 * Call a SEXE function.
 *
 * @param S The SEXE process handle.
 * @param func The global name of the function.
 * @param call A JSON object which optionally contains a "argument" array, which is passed into the function, and a "void" boolean which indicates that the function does not return a value.
 * @returns A zero (0) on success or a share library error code on failure.
 */
int sexe_pcall_json(sexe_t *S, char *func, shjson_t *call);

/** Close a SEXE process handle. */
void sexe_pclose(sexe_t *S);


int sexe_pgetdef(sexe_t *S, char *name, shjson_t **arg_p);

int sexe_pget(sexe_t *S, char *name, shjson_t **arg_p);

int sexe_pset(sexe_t *S, char *name, shjson_t *arg);

int sexe_pevent(sexe_t *S, char *event_name, shjson_t *data);




int sexe_compile_pmain(sexe_t *L);

sexe_t *sexe_init(void);

int sexe_compile_writer(lua_State* L, const void* p, size_t size, void* u);


/* v1 instruction operations. (tx_vm_t.vm_op) */
#define SEOP_NONE 0
#define SEOP_REQ 1
#define SEOP 2
#define SEOP_WRITE 3
#define SEOP_COMPARE 4 
#define SEOP_SYN 5
/** Request for a session to be opened. */
#define SEOP_OPEN 10
/** An confirmation that a session may be established. */
#define SEOP_ACCEPT 11
/** An rejection that a session may be established. */
#define SEOP_REJECT 12
/** A notification that a session will be closed. */
#define SEOP_CLOSE 13
/** A confirmation that the session has been closed. */
#define SEOP_ABEND 14



/* task modes (tx_run_t.run_mode) */
#define SEM_NONE 0
#define SEM_PREP 1
#define SEM_REQUEST 2
#define SEM_CONFIRM 3 
#define SEM_REJECT 4 
#define SEM_REGISTER 5
#define SEM_RUN 10
#define SEM_STATUS 11
#define SEM_CHECK 12
#define SEM_TERM_INFO 13
#define SEM_TERMINATE 14
#define SEM_COMPLETE 15
#define SEM_INACTION 20
#define SEM_RELOAD 21
#define SEM_SUSPEND 22
#define SEM_RESUME 23
#define SEM_SIGNAL 24
#define SEM_TIMER 25

/* mem operations (tx_mem_t.mem_op) */
#define SEMEM_SEEK 1 /* request */
#define SEMEM_READ 2
#define SEMEM_WRITE 3
#define SEMEM_COMPARE 4
#define SHMEM_LOCK 5
#define SHMEM_UNLOCK 6



/* stack modes */
#define SESTACK_NONE 0
#define SESTACK_INSTRUCTION 1
#define SESTACK_UPVAL 2
#define SESTACK_DEBUG 3
#define SESTACK_CONSTANT 4
#define SESTACK_FUNCTION 5
#define SESTACK_LITERAL 6 
#define SESTACK_UPVAL_DEBUG 10
#define SESTACK_LOCALVAR_DEBUG 11
#define SESTACK_INSTRUCTION_DEBUG 12

/* a "un-set" stack mode. */
#define SESTACK_MASK 250


#if 0
/* constant types */
#define SECON_NIL 0
#define SECON_LITERAL 1
#define SECON_BOOL 2
#define SECON_NUMBER 3
#endif






/* vm operations. */
/** Request a 'virtual machine' be utilized. */
#define SEVM_REQUEST 1
/** Inform that a 'virtual machine' may be utilized. */
#define SEVM_NOTIFY 2







/** Perform job's tasks simutaneously. */
#define SEF_FRAGMENT (1 << 0)
/** Perform job's tasks in a sequence. */
#define SEF_SEQUENCE (1 << 1)
/** Undo job's actions if result code is failure. */
#define SEF_TRANSACTION (1 << 2)



/**
 * A segment of data being transferred to another host. 
 * @note Not currently used.
 */
typedef struct sexe_data_t
{
  shkey_t data_sink;
  uint64_t data_sink_of;
  shkey_t data_src;
  uint64_t data_src_of;
  uint32_t data_len;
  unsigned char data[0];
} sexe_data_t;

/**
 * @note Not currently used.
 */
typedef struct sexe_mem_t
{
  /** The length of the virtual memory segment. */
  uint64_t seg_len;
  /** The 64-bit virtual memory address. */
  uint64_t seg_addr;
} sexe_mem_t;


struct sexe_upval_t
{
  /* upval in stack? */
  uint8_t upv_instack;
  uint8_t upv_reserved[3];
  /* index of upval */
  uint32_t upv_index;
};
typedef struct sexe_upval_t sexe_upval_t;


struct sexe_const_t
{
  uint32_t con_type;
  uint64_t con_val;
};
typedef struct sexe_const_t sexe_const_t; 

struct sexe_debug_lvar_t 
{
  char lvar_name[MAX_SEXE_NAME_LENGTH];
  uint32_t lvar_startpc;
  uint32_t lvar_endpc;
};
typedef struct sexe_debug_lvar_t sexe_debug_lvar_t;

#define SEPARAMF_VARARG (1 << 0)
struct sexe_func_t
{
  uint32_t func_source; /* checksum of 'source' name */

  uint32_t func_line;
  uint32_t func_lline;

  uint32_t stack_max;

  uint8_t param_max;
  uint8_t param_flag;

	uint8_t __reserved_0__;
	uint8_t __reserved_1__;
};
typedef struct sexe_func_t sexe_func_t;

struct sexe_stack_t 
{
  uint8_t type; /* function, param, local, or constant */
	uint8_t __reserved_0__;
	uint8_t __reserved_1__;
	uint8_t __reserved_2__;
  uint32_t size; /* number of members */
  union {
    Instruction instr[0];
    unsigned char lit[0];
    sexe_const_t con[0];
    sexe_upval_t upv[0];
    sexe_func_t func[0];
    sexe_debug_lvar_t dbg_lvar[0];
  } stack;
};
typedef struct sexe_stack_t sexe_stack_t;




struct sexe_mod_t
{
  uint8_t sig[4]; /* SEXE_SIGNATURE */
  uint8_t ver;
  uint8_t fmt; /* 0 */ 
  uint8_t end; /* 1 */
  uint8_t sz_int; /* sizeof(int) */
  uint8_t sz_sizet; /* sizeof(size_t) */
  uint8_t sz_instr; /* sizeof(Intruction) */
  uint8_t sz_lnum; /* sizeof(lua_Number) */
  uint8_t integral; /* (lua_Number)0.5 == 0 */ 
  char name[MAX_SEXE_NAME_LENGTH];
  uint8_t tail[6]; /* SEXE_TAIL */
};
typedef struct sexe_mod_t sexe_mod_t;


#if 0
/**
 * A task specifying a set of instructions to perform.
 */
struct sexe_task_t {
  shkey_t task_id;

  /** The input argument for the task. */
  sexe_mem_t task_arg;

  /** The version capability of the instruction set. */
  uint32_t instr_ver;

  uint32_t mod_max;
  sexe_mod_t mod[0];
};
typedef struct sexe_task_t sexe_task_t;

/**
 * A vm thread performing a task.
 */
typedef struct sexe_thread_t 
{
  /** The current task being performed by the session. */
  sexe_task_t th_task;
  /* The task's instruction sequence index. */
  uint32_t th_instr_idx;
  /** A key unique to the originating job. */
  shkey_t th_job;
  /** A key reference to the memory pool used by the thread. */
  shkey_t th_pool;
  /** The time-stamp of when the thread was generated. */
  shtime_t th_birth;
} sexe_thread_t;

/**
 * A single job requested by an application containing a set of tasks.
 * @note Each job has an isolated 64-bit virtual memory-address space. 
 * @note The tasks are not required to be ran on the same vm.
 */
typedef struct sexe_job_t 
{
  /* A unique key representing the job. */
  shkey_t job_id;

  /** The time the job was created. */
  shtime_t job_stamp;

  /** The maximum execution time of the job. */
  shtime_t job_expire;

  /** The operational parameters for processing the intructions. */
  uint32_t job_flags;

  /** The priority of the job. */
  uint32_t job_prio;

  /** The machine platform associated with this job's execution. */
  uint32_t job_arch;

#if 0
  /** A set of tasks the job is compiled of. */
  uint32_t stack_max;
  sexe_task_t *stack;
#endif
} sexe_job_t;


/**
 * A session dedicated to running tasks on a virtual machine.
 */
typedef struct sexe_sess_t {
  uint32_t sess_op;
  shkey_t sess_id;
} sexe_sess_t;


/**
 * A virtual machine capable of handling a session.
 */
typedef struct sexe_vm_t {
 /** The machine platform associated with this thread's execution. */
  uint32_t vm_arch;
  /** A general priority established to perform remote tasks. */
  uint32_t vm_prio;
  /** The priveleged peer identity of the process running the vm. */
  shpeer_t vm_app;
  /** The time-stamp that the vm went 'online'. */
  shtime_t vm_stamp;
} sexe_vm_t;
#endif

#if 0
#define SEXE_OP_JUMP 10
#define SEXE_OP_CALL 11
#define SEXE_OP_RETURN 12
#define SEXE_OP_NOP 13
#define SEXE_OP_PRINT 14 /* to log */
#define SEXE_OP_LIFETIME 15

#define SEXE_CODE_MOVE 21
#define SEXE_CODE_CALL 32

#define SEXE_MEM_ALLOC 30
#define SEXE_MEM_ADDR 31 /* info ack */
#define SEXE_MEM_FREE 32

#define SEXE_OBJ_DATA_REQ 40
#define SEXE_OBJ_WRITE 41
#define SEXE_OBJ_COMPARE 42
#define SEXE_OBJ_CALL_NUM 43
#define SEXE_OBJ_CALL_NAME 44
#define SEXE_OBJ_PROC_NUM 45 /* get name of procedure in obj */
#define SEXE_OBJ_NEW 46
#define SEXE_OBJ_SYN 47 /* response to 'new obj' op */
#define SEXE_OBJ_DELETE 48
#define SEXE_OBJ_SEEK 49
#define SEXE_OBJ_NAME 50
#endif


#ifdef SEXELIB
#define RUNF_TEST (1 << 0)
#define RUNF_STRIP (1 << 1)
#define RUNF_VERBOSE (1 << 2)
#define RUNF_INPUT (1 << 3)
#define RUNF_LOCAL (1 << 4)
#define RUNF_OUTPUT (1 << 5)

#define VERBOSE(_fmt, ...) \
  ((run_flags & RUNF_VERBOSE) ? \
   printf(_fmt, __VA_ARGS__) : 0)

extern int run_flags;

void sexe_header(lu_byte* h, char *name);
#else
#define VERBOSE(_fmt, ...) (0)
#endif

extern double SEXE_VERSION;


const char *sexe_checkstring(sexe_t *S, int narg);

lua_Number sexe_checknumber(sexe_t *S, int narg);

char ac_sexe(void);

/**
 * Create a new C callback for a particular event.
 * @note The C callback must return a single boolean on success/failure.
 */
void sexe_event_register(lua_State *L, char *e_name, lua_CFunction f);

int sexe_io_serialize(sexe_t *S, char *tag, shjson_t *j);

int sexe_io_unserialize(sexe_t *S, char *tag, shjson_t **j_p);


/**
 *  @}
 */

#ifdef __cplusplus
}
#endif


#endif /* ndef __SHARE_LIB__SEXE_H__ */
