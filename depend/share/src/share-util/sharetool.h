
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

#ifndef __SHARETOOL_H__
#define __SHARETOOL_H__

#undef __STRICT_ANSI__ 

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>

#include "share.h"
#include "sharetool_pref.h"
#include "sharetool_file.h"
#include "sharetool_rev.h"
#include "sharetool_info.h"
#include "sharetool_appinfo.h"
#include "sharetool_pwd.h"
#include "sharetool_pkg.h"
#include "sharetool_cert.h"
#include "sharetool_db.h"
#include "sharetool_arch.h"
#include "file/file_cat.h"
#include "file/file_import.h"
#include "file/file_list.h"
#include "file/file_mkdir.h"
#include "file/file_unlink.h"
#include "file/file_attr.h"
#include "file/file_rev.h"
#include "file/file_copy.h"
#include "file/file_link.h"
#include "info/info_table.h"


#define SHM_NONE 0
#define SHM_PREF 1
#define SHM_INFO 4
#define SHM_PAM 6
#define SHM_PEER 8
#define SHM_FILE_LIST 10
#define SHM_FILE_INFO 11
#define SHM_FILE_CAT 12
#define SHM_FILE_COPY 14
#define SHM_FILE_MKDIR 16
#define SHM_FILE_REMOVE 18
#define SHM_FILE_ATTR 20
#define SHM_FILE_DIFF 22
#define SHM_FILE_DELTA 23
#define SHM_FILE_MERGE 24
#define SHM_FILE_PATCH 26
#define SHM_FILE_REV 28
#define SHM_FILE_LINK 29
#define SHM_FS_CHECK  30
#define SHM_ARCHIVE 40
#define SHM_PACKAGE 52
#define SHM_CERTIFICATE 54
#define SHM_DATABASE 56
#define SHM_GEO 58
#define SHM_ALG 60

#define PFLAG_VERBOSE (1 << 0) /* -l */
#define PFLAG_SYNTAX (1 << 1) /* -h */
#define PFLAG_VERSION (1 << 2) /* -v */
#define PFLAG_CHECKSUM (1 << 3)
#define PFLAG_INODE (1 << 4)
#define PFLAG_LOCAL (1 << 5)
#define PFLAG_RECURSIVE (1 << 6) /* -r */
#define PFLAG_QUIET (1 << 7) /* --quiet */
#define PFLAG_IGNORE (1 << 8) /* --ignore */
#define PFLAG_VERIFY (1 << 9) /* --verify */
#define PFLAG_DECODE (1 << 10)
#define PFLAG_BINARY (1 << 11) /* -b | --binary */
#define PFLAG_JSON (1 << 12) /* -j | --json */
#define PFLAG_UPDATE (1 << 13) /* -s | --set */

/* psuedo-standard ports for shnet operations */
#define SHARE_PING_PORT 32200

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE !FALSE
#endif

#ifndef MIN
#define MIN(a,b) \
  (a < b ? a : b)
#endif

#ifndef MAX
#define MAX(a,b) \
  (a > b ? a : b)
#endif

extern char process_path[PATH_MAX + 1];
extern char process_file_path[PATH_MAX + 1];
extern char process_socket_host[PATH_MAX + 1];
extern unsigned int process_socket_port;
extern FILE *sharetool_fout;
extern int run_flags;

#endif /* __SHARETOOL_H__ */

