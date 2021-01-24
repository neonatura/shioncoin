/*
 * @copyright
 *
 *  Copyright 2013 Neo Natura 
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
 *  @file shfs.h
 */

#ifndef __FS__SHFS_H__
#define __FS__SHFS_H__

#include <sys/stat.h>
#include <sys/types.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#undef fcntl
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifndef __MEM__SHMEM_H__
#include "shmem.h"
#endif


#ifndef DOXYGEN_SHOULD_SKIP_THIS

#ifndef NAME_MAX
#define NAME_MAX 4095
#endif

#ifndef PATH_MAX
#define PATH_MAX NAME_MAX
#endif

#endif



/**
 * The share library 'share-fs' file system consists of multiple partitions.
 *
 * The share-fs partitions can be accessed through via the shcat, shcp, shfsck, shln, shls, shrev, shrm, and shstat command-line programs.
 *  *  - \subpage shareutil "Share Utility Programs"
 *
 * @ingroup libshare
 * @defgroup libshare_fs The Share File-system
 * @{
 */



#define SHFS_LEVEL_PUBLIC 0
#define SHFS_MAX_LEVELS 1




#if 0
/**
 * Overlay sharefs on top of current filesystem.
 * @note Use 'shnet --nosync' for example behavior of this flag.
 */ 
#define SHFS_OVERLAY        (1 << 0)
/**
 * Track all revisions of file modifications.
 * @note Use 'shnet --track' for example behavior of this flag.
 */
#define SHFS_TRACK          (1 << 1)
/**
 * A sharefs filesystem that is externally unaccessible beyond 
 * the scope of this application.
 */
#define SHFS_PRIVATE        (1 << 2)
/**
 * Disabling caching and asynchronous file operations.
 */
#define SHFS_SYNC           (1 << 3)
/**
 * The partition is located on a remote machine.
 */
#define SHFS_REMOTE         (1 << 4)
#endif



/**
 * A type defintion for the sharefs filesytem structure.
 */
typedef struct shfs_t shfs_t;



/**
 * A sharefs filesystem inode.
 */
typedef struct shfs_ino_t shfs_ino_t;



/**
 * An inode reference to nothing.
 */
#define SHINODE_NULL          0

/**
 * Inode is in reference to an application-specific directory.
 * @note See also: @c shfs_node.d_type
 */
#define SHINODE_APP          100

/**
 * Inode is the root of an entire sharefs partition.
 * @note See also: @c shfs_node.d_type
 */
#define SHINODE_PARTITION     101

/**
 * Inode is a reference to a remote sharefs partition.
 * @note See also: @c shfs_node.d_type
 */
#define SHINODE_PEER          102

/**
 * An archive of files and/or directories.
 * @note See also: @c shfs_node.d_type
 */
#define SHINODE_ARCHIVE       104

/**
 * A reference to another inode.
 * @note The referenced inode may be local or remote.
 */
#define SHINODE_REFERENCE     105

/**
 * A meta definition hashmap (meta map).
 * @note The referenced inode may be local or remote.
 */
#define SHINODE_META          106

/**
 * A directory containing multiple file references.
 */
#define SHINODE_DIRECTORY     107

/**
 * An auxillary unparseable data segment stored in the sharefs sub-system.
 */
#define SHINODE_AUX           108

/**
 * A generic reference to a path which contains further references to data.
 */
#define SHINODE_FILE          109 

/**
 * Raw binary data referenced by a @see SHINODE_FILE inode.
 * @note A SHINODE_BINARY inode contains SHINODE_AUX referencing the raw binary data segments.
 */
#define SHINODE_BINARY        110


/**
 * A zlib compressed binary segment.
 */
#define SHINODE_COMPRESS 112

/**
 * A TEA encoded binary segment.
 */
#define SHINODE_CRYPT 113

/**
 * A reference to a sqlite database.
 */
#define SHINODE_DATABASE 114

/**
 * Inode specific permissions based on credentials.
 */
#define SHINODE_ACCESS 115

/**
 * Inode specific access mutex.
 */ 
#define SHINODE_FILE_LOCK 116

#define SHINODE_LICENSE 117

#define SHINODE_EXTERNAL 118

/**
 * A repository of file revisions.
 */
#define SHINODE_REPOSITORY 120

/**
 * A reference to a particular version of a file.
 */
#define SHINODE_REVISION 121

/**
 * Inode is a reference to a binary delta of a file revision.
 */
#define SHINODE_DELTA 122


/**
 * A generic reference to a collection of data. 
 */
#define SHINODE_OBJECT 130

#define SHINODE_OBJECT_KEY 131

/**
 * A libshare inode type used for testing purposes.
 */
#define SHINODE_TEST 140

/**
 * A libshare inode containing auxillary SEXE bytecode.
 * The SEXE bytecode is executed in order to pipe a read / write stream.
 */
#define SHINODE_DEVICE 150

#define IS_INODE_CONTAINER(_type) \
  (_type != SHINODE_AUX && \
   _type != SHINODE_REFERENCE && \
   _type != SHINODE_EXTERNAL && \
   _type != SHINODE_LICENSE && \
   _type != SHINODE_FILE_LOCK && \
   _type != SHINODE_OBJECT_KEY)

/**
 * The maximum size a single block can contain.
 * @note Each block segment is 4096 bytes which is equal to the size of @c shfs_ino_t structure. 
 */
#define SHFS_MAX_BLOCK_SIZE 4096 

/**
 * The size of the data segment each inode contains.
 */
#define SHFS_BLOCK_DATA_SIZE (SHFS_MAX_BLOCK_SIZE - sizeof(shfs_hdr_t))

/**
 * The maximum number of blocks in a sharefs journal.
 */
#define SHFS_MAX_BLOCK 57344

/**
 * The maximum length of a sharefs file name.
 * @note The length is subtracted by 16 bytes of a hash tag incase to track longer filenames and 1 byte for a null-terminator.
 */
#define SHFS_PATH_MAX (SHFS_BLOCK_DATA_SIZE - 34)

/** The character tokens representing the inode attributes. */
#define SHFS_ATTR_BITS "abcdefhlmrstvwxz"

/** Indicates the inode contains an SHINODE_ARCHIVE file containing stored directories and/or files. */
#define SHATTR_ARCH (1 << 0)
/* Reserved for future use */
#define SHATTR_BLOCK (1 << 1)
/** Indicates the inode has SHINODE_ACCESS credentials. */
#define SHATTR_CRED (1 << 2)
/** Indicates the inode is a database. */
#define SHATTR_DB (1 << 3)
/** Indicates the inode is encrypted. */
#define SHATTR_ENC (1 << 4)
/** Indicates the inode has a SHINODE_FILE_LOCK lock blocking access. */
#define SHATTR_FLOCK (1 << 5)
/** Indicates the inode is not listed in a directory listing. */
#define SHATTR_HIDDEN (1 << 6)
/** Indicates the inode is a SHINODE_REFERENCE to another inode. */
#define SHATTR_LINK (1 << 7)
/** This inode has supplementatal SHINODE_META information.  */
#define SHATTR_META (1 << 8)
/** Indicates the inode has global read access. */
#define SHATTR_READ (1 << 9)
/** Indicates the inode synchronizes with the share daemon. */
#define SHATTR_SYNC (1 << 10)
/** Indicates that inode is not persistent. */
#define SHATTR_TEMP (1 << 11)
/** This inode has multiple revision versions. */
#define SHATTR_VER (1 << 12)
/** This inode has global write access. */
#define SHATTR_WRITE (1 << 13)
/** This inode has global execute access. */
#define SHATTR_EXE (1 << 14)
/** Indicates the inode is storing compressed data. */
#define SHATTR_COMP (1 << 15)
/** A SHINODE_EXTERNAL inode referencing a local-disk path. */
#define SHATTR_LINK_EXT (SHATTR_LINK)

#define HAS_SHMETA_INODE(_ino) \
  ( (_ino->blk.hdr.attr & SHATTR_META) || \
  )

/** 
 * The default format for data contained by a SHINODE_FILE inode.
 * @note Does not apply to SHINODE_LINK references.
 */ 
#define SHINODE_DEFAULT_ATTR_FORMAT(_attr) \
  ( \
    ((_attr) & SHATTR_DB) ? SHINODE_DATABASE : \
    ((_attr) & SHATTR_VER) ? SHINODE_REVISION : \
    ((_attr) & SHATTR_ENC) ? SHINODE_CRYPT : \
    ((_attr) & SHATTR_COMP) ? SHINODE_COMPRESS : \
    SHINODE_BINARY \
  )

//    ((_attr) & SHATTR_LINK) ? SHINODE_REFERENCE :
//    ((_attr) & SHATTR_LINK_EXT) ? SHINODE_EXTERNAL :

/** can inode be archived. */
#define IS_SHINODE_ARCHIVABLE(_ino) \
  (shfs_format(_ino) == SHINODE_DIRECTORY)

/** can inode be compressed. */
#define IS_SHINODE_COMPRESSABLE(_ino) \
  (shfs_format(_ino) == SHINODE_BINARY)

/** can inode be encrypted. */
#define IS_SHINODE_ENCRYPTABLE(_ino) \
  (shfs_format(_ino) == SHINODE_BINARY || \
   shfs_format(_ino) == SHINODE_COMPRESS)

/** can inode be converted into a revision repository. */
#define IS_SHINODE_VERSIONABLE(_ino) \
  (shfs_format(_ino) == SHINODE_BINARY)

/**
 * A sharefs filesystem inode or journal reference.
 */
typedef __uint16_t shfs_inode_off_t;

/**
 * A sharefs inode type definition.
 */
typedef __uint16_t shfs_ino_type_t;

/**
 * A sharefs inode attribute definitions.
 */
typedef __uint32_t shfs_attr_t;


/**
 * A sharefs filesystem inode position header.
 */
typedef struct shfs_idx_t shfs_idx_t;

struct shfs_idx_t 
{

  /**
   * The journal number where the inode presides.
   */ 
  shfs_inode_off_t jno;             

  /**
   * An inode index in journal to initial data block.
   */ 
  shfs_inode_off_t ino;             

}; /* 4b */




/**
 * A sharefs filesystem inode header.
 * @see shfs_meta() SHINODE_DIRECTORY
 */
struct shfs_hdr_t 
{

  /**
   * A hashed reference of the inode.
   */
  shkey_t name;

  /**
   * A hashed reference of the inode's owner id.
   */
  shkey_t owner;

  /**
   * The total size of the data segment being referenced.
   */
  shsize_t size;

  /**
   * The time that the inode was created.
   */
  shtime_t ctime;

  /**
   * The last time this inode was written to.
   */
  shtime_t mtime;

  /**
   * A crc checksum representation of the underlying data.
   */
  uint64_t crc;

  /**
   * A bitvector specifying inode attributes.
   */
  shfs_attr_t attr;

  /**
   * Type of inode.
   * @see SHINODE_FILE
   */
  shfs_ino_type_t type;

  /**
   * Type of inode data contained.
   */
  shfs_ino_type_t format;

  /**
   * Inode position in the partition.
   */
  shfs_idx_t pos;

  /**
   * The position of the next inode in a chain.
   */
  shfs_idx_t npos;

  /**
   * The position of the first inode in a chain.
   */
  shfs_idx_t fpos;

  uint16_t salt;

}; /* 96b (2.3% of block) */

typedef struct shfs_hdr_t shfs_hdr_t;

typedef struct shfs_block_t shfs_block_t;


/**
 * A convienence macro for accessing a sharefs file partition.
 */
typedef struct shfs_t SHFS;
/**
 * A convienence macro for accessing a sharefs file node.
 */
typedef struct shfs_ino_t SHFL;


struct shfs_root_t
{
  shpeer_t peer;
};
typedef struct shfs_root_t shfs_root_t;

/**
 * A partition inode is the containing class which encapsulates all forms of data stored on a share-fs partition.
 * @ingroup libshare_fs
 * @defgroup libshare_fsinode Partition Inode Blocks
 * @{
 */


/**
 * The contents of a sharefs inode.
 */
struct shfs_block_t 
{

  /**
   * The definition header of the inode block. */
  shfs_hdr_t hdr;

  /**
   * The data segment of the inode block.
   */
  unsigned char raw[SHFS_BLOCK_DATA_SIZE];

};


/**
 * A sharefs filesystem inode.
 */
struct shfs_ino_t 
{

  /**
   * A 2k block of data stored on the sharefs partition.
   */
  shfs_block_t blk;

  /**
   * The sharefs partition this inode is a part of.
   */
  shfs_t *tree;

  /**
   * The parent inode containing this inode.
   * @note The root inode will have a parent of NULL.
   * @note This variable is not saved as part of the fileystem inode.
   */
  struct shfs_ino_t *parent;

  /**
   * The root directory inode of the partition.
   * @note The root inode is self-circular for the root inode.
   * @note This variable is not saved as part of the fileystem inode.
   */
  struct shfs_ino_t *base;

  /**
   * Inode entities that are contained inside this inode.
   */
  shmap_t *cache;

  /**
   * Primary meta definitions associated with the inode.
   */
  shmap_t *meta;

  /**
   * Type-specific allocated memory pool for inode.
   */
  unsigned char *pool;


};




struct shstat 
{

  /** A unique number representing the share-fs partition. */
  uint32_t st_dev; /* shfs parition # */

  /** A unique number representing the inode [in the partition]. */
  uint32_t st_ino;

  /** The type of inode (file, directory, etc) using unix-style stat() constants. */
  uint32_t st_mode;    /* protection */
  uint64_t __reserved_0__;

  /** The total byte size of the underlying data content. */
  uint64_t st_size;    /* total size, in bytes */

  /** The block size used by the sharefs file-system. */
  uint64_t st_blksize;

  /** The number of blocks (inodes) that compose the underlying data. */
  uint64_t st_blocks;

  /** A unique number representing the owner of the file. */
  uint64_t uid;
  uint64_t __reserved_1__;

  /** A unique checksum representing the inode and it's underlying data content. */
  uint64_t crc;
  uint64_t __reserved_2__;

  /** The time when the inode was initially created. */
  shtime_t ctime;

  /** The last time that the inode was modified. */
  shtime_t mtime;
};
typedef struct shstat shstat;






/**
 * Retrieve a sharefs inode entry based on a given parent inode and path name.
 * @note Searches for a reference to a sharefs inode labelled "name" in the @a parent inode.
 * @note A new inode is created if a pre-existing one is not found.
 * @param parent The parent inode such as a directory where the file presides.
 * @param name The relational pathname of the file being referenced.
 * @param mode The type of information that this inode is referencing (SHINODE_XX).
 * @returns A @c shfs_node is returned based on the @c parent, @c name, @c and mode specified. If one already exists it will be returned, and otherwise a new entry will be created.
 * @note A new inode will be linked to the sharefs partition if it does not exist.
 */
shfs_ino_t *shfs_inode(shfs_ino_t *parent, char *name, int mode);

/**
 * Retrieve a sharefs inode child entry based on a token key.
 */
shfs_ino_t *shfs_inode_load(shfs_ino_t *parent, shkey_t *key);

/**
 * Obtain the shfs partition associated with a particular inode.
 * @param inode The inode in reference.
 */
shfs_t *shfs_inode_tree(shfs_ino_t *inode);

shpeer_t *shfs_inode_peer(shfs_ino_t *inode);

/**
 * Obtain the root partition inode associated with a particular inode.
 * @param inode The inode in reference.
 */
shfs_ino_t *shfs_inode_root(shfs_ino_t *inode);

/**
 * Obtain the parent [directory/container] inode associated with a particular inode.
 * @param inode The inode in reference.
 */
shfs_ino_t *shfs_inode_parent(shfs_ino_t *inode);

/**
 * Write an entity such as a file inode.
 */
int shfs_inode_write_entity(shfs_ino_t *ent);

/**
 * Truncates the inode's underlying data to a specified size if the size is greater than the size of the inode or increases the size with blank data if the specified size is greater.
 * @param inode The non-container inode to adjust data size.
 * @param ino_len The desired length of the inode's underlying data segment.
 * @note Increasing the file size does not immediately increase the underlying data content size.
 */
int shfs_inode_truncate(shfs_ino_t *inode, shsize_t ino_len);

shsize_t shfs_size(shfs_ino_t *file);

/**
 * Writes a single inode block to a sharefs filesystem journal.
 */
int shfs_inode_write_block(shfs_t *tree, shfs_block_t *blk);


/**
 * Retrieve a single data block from a sharefs filesystem inode. 
 * @see shfs_init()
 * @param tree The sharefs partition allocated by shfs_init().
 * @param inode The inode whose data is being retrieved.
 * @param hdr A specification of where the block is location in the sharefs filesystem partition.
 * @param inode The inode block data to be filled in.
 * @returns Returns 0 on success and a SHERR_XXX on failure.
 */
int shfs_inode_read_block(shfs_t *tree, shfs_idx_t *pos, shfs_block_t *blk);


/**
 * Returns a unique key token representing an inode.
 * @param parent The parent inode of the inode being referenced.
 * @note free the returned key with shkey_free()
 */
shkey_t *shfs_token_init(shfs_ino_t *parent, int mode, char *fname);

/**
 * Assign an inode a filename.
 */
void shfs_filename_set(shfs_ino_t *inode, char *name);

/**
 * Returns the filename of the inode.
 */
char *shfs_filename(shfs_ino_t *inode);

char *shfs_inode_path(shfs_ino_t *inode);

/**
 * A unique hexadecimal string representing a sharefs inode.
 */
char *shfs_inode_id(shfs_ino_t *inode);



char *shfs_inode_print(shfs_ino_t *inode);
char *shfs_inode_block_print(shfs_block_t *jblk);

char *shfs_inode_size_str(shsize_t size);


/**
 * Create a inode checksum.
 */
uint64_t shfs_crc_init(shfs_block_t *blk);
/**
 * The share library file inode's data checksum.
 */
uint64_t shfs_crc(shfs_ino_t *file);

shsize_t shfs_size(shfs_ino_t *inode);


/** The type of an inode block. */
int shfs_block_type(shfs_block_t *blk);
/** The type of inode. */
int shfs_type(shfs_ino_t *inode);
/** The format of an inode block. */
int shfs_block_format(shfs_block_t *blk);
/** The format of an inode. */
int shfs_format(shfs_ino_t *inode);
/** Convert the inode to hold a different data format. */
int shfs_format_set(shfs_ino_t *file, int format);
/** A string representation of an inode type. */
char *shfs_type_str(int type);
/** A single-character reference to an inode type. */
char shfs_type_char(int type);
/** A string representation of an inode format. */
char *shfs_format_str(int format);




int shfs_block_stat(shfs_block_t *blk, shstat *st);

/**
 * Obtain inode attribute information.
 * An SHERR_NOENT error occurs if inode format is not set.
 * @param The inode to generate info for.
 * @param st The result info structure.
 * @returns Zero (0) on success or a libshare error code.
 */
int shfs_fstat(shfs_ino_t *file, shstat *st);

/**
 * Obtain inode attribute information for a path.
 */
int shfs_stat(shfs_t *fs, const char *path, shstat *st);

shkey_t *shfs_token(shfs_ino_t *inode);

int shfs_inode_remove(shfs_ino_t *file);

/** Clear the contents of a sharefs inode. */
int shfs_unlink(shfs_t *fs, char *path);

shtime_t shfs_ctime(shfs_ino_t *ino);

shtime_t shfs_mtime(shfs_ino_t *ino);

/**
 * @}
 */




/**
 * The maximum number of sharefs journals (and sub-sequent file descriptor) open at once.
 */
#define MAX_JOURNAL_CACHE_SIZE 256
//#define MAX_JOURNAL_CACHE_SIZE 192



/**
 * A sharefs filesystem journal.
 */
typedef struct shfs_journal_t {

  /**
   * The index number of the journal. 
   */
  int index;

  /**
   * The data segment of the journaled sharefs file system.
   */
  shbuf_t *buff;

  /**
   * The path to the sharefs partition journal on the local filesystem.
   */
  char path[PATH_MAX+1];

  shtime_t stamp;

  /**
   * The previleged key of the associated parition.
   */
  shkey_t fs_key;

} shfs_journal_t;


/**
 * The sharefs filesystem structure.
 * @note See also: @c shfs_ino_t
 */
struct shfs_t {
  /**
   * The flags associated with the sharefs partition.
   */
  int flags;

  /**
   * The machine related to the sharefs inode's partition.
   * @note This variable is not saved as part of the fileystem inode.
   */
  shpeer_t peer;

  /**
   * Working root directory.
   * @see shchroot()
   */
  shfs_ino_t *base_ino;

  /**
   * Root directory.
   */
  shfs_ino_t *fsbase_ino;

};






/**
 * The number of journals a sharefs filesystem contains.
 * @seealso shfs_journal_t.index
 */
#define SHFS_MAX_JOURNAL 57344 

/**
 * The maximum number of bytes in a sharefs file-system journal.
 */
#define SHFS_MAX_JOURNAL_SIZE (SHFS_MAX_BLOCK * SHFS_MAX_BLOCK_SIZE)






#define SHMETA_READ   "read"
#define SHMETA_WRITE  "write"
#define SHMETA_EXEC   "exec"
/**
 * The read-access group assigned to the inode.
 */
#define SHMETA_USER   "user"
#define SHMETA_GROUP  "group"

/**
 * A digital signature.
 */
#define SHMETA_SIGNATURE "signature"

/**
 * A textual description of the inode.
 */
#define SHMETA_DESC   "desc"

/** login user's real name */
#define SHMETA_USER_NAME "user.name"
/** login user's email address. */
#define SHMETA_USER_EMAIL "user.email"

#define SHMETA_USER_GEO "user.geo"

/** login user's password key. */
#define SHMETA_USER_PASS "sys.pass"

/** login user's password salt. */
#define SHMETA_USER_SALT "sys.salt"

/** login user's password salt. */
#define SHMETA_MIME_TYPE "mime.name"

/**
 * A directory prefix referencing file meta information.
 */
#define BASE_SHMETA_PATH "meta"

/**
 * Free an instance to a sharedfs meta definition hashmap.
 * @note Directly calls @c shmap_free().
  */
#define shfs_meta_free(_meta_p) shmap_free(_meta_p)









/**
 * File-system specific process runtime functionality.
 * @ingroup libshare_fs
 * @defgroup libshare_fsproc Process Runtime Routines
 * @{
 */

char *shfs_app_name(char *app_name);

char *shfs_app_path(char *exec_path);

int shfs_proc_lock(char *process_path, char *runtime_mode);

/**
 * @}
 */













/**
 * The share file-system is composed of multiple partitions which each contain a directory hierarchy.
 * @ingroup libshare_fs
 * @defgroup libshare_fspartition Share Filesystem Partition
 * @{
 */

/** The system-level certificate directory. */
#define SHFS_DIR_CERTIFICATE "crt"
/** The system-level password authentification module directory. */
#define SHFS_DIR_PAM "pam"
/** The system-level package hierarchy. */
#define SHFS_DIR_PACKAGE "pkg"
/** The system-level application hierarchy. */ 
#define SHFS_DIR_APPLICATION "app"
/** The system-level mime-type directory. */
#define SHFS_DIR_MIME "mime"
/** The system-level license directory. */
#define SHFS_DIR_LICENSE "lic"
/** THe system-level database directory. */
#define SHFS_DIR_DATABASE "db"

/* A tag reference to an executable file. */
#define SHFS_FILE_EXECUTABLE "exec"


/**
 * Creates a reference to a sharefs filesystem.
 * @param peer A local or remote reference to a sharefs partition.
 * @a flags A combination of SHFS_PARTITION_XXX flags.
 * @returns shfs_t A share partition associated with the peer specified or the local default partition if a NULL peer is specified.
 * @todo write local file '/system/version' with current version.
 */
shfs_t *shfs_init(shpeer_t *peer);

char *shfs_sys_dir(char *sys_dir, char *fname);

/**
 * Access the system-level sharefs partition.
 */
shfs_t *shfs_sys_init(char *sys_dir, char *fname, shfs_ino_t **file_p);

shpeer_t *shfs_peer(shfs_t *fs);

/**
 * Free a reference to a sharefs partition.
 * @param tree_p A reference to the sharefs partition instance to free.
 */
void shfs_free(shfs_t **tree_p);

/**
 * Obtain the partition id for a sharefs partition.
 * @note The local parition will always return zero (0).
 */
shkey_t *shfs_partition_id(shfs_t *tree);

/**
 * Obtain the share-fs and optional file for a share-fs URI path.
 */
shfs_t *shfs_uri_init(char *path, int flags, shfs_ino_t **ino_p);

/**
 * The total number of megabytes available on the file-system utilized.
 */ 
size_t shfs_avail(void);


/**
 * @}
 */







/**
 * A share file-system journal is a sequential set of inodes. A set of journals may hold data for one or more share file-system partitions.
 * @ingroup libshare_fs
 * @defgroup libshare_fsjournal Partition Journal Management
 * @{
 */


/**
 * The local file-system path where a sharefs journal is stored.
 */
void shfs_journal_path(shfs_t *tree, int index, char *ret_path);

/**
 * Returns an instance to a sharefs filesystem journal.
 */
shfs_journal_t *shfs_journal_open(shfs_t *tree, int index);


/**
 * Search for the first empty inode entry in a journal.
 * @param tree The sharefs filesystem partition.
 * @param key The token name of the inode being referenced.
 * @param idx The index number of the journal.
 * @returns A inode index number or zero (0) on failure.
 * @note Inode index #0 is reserved for system use.
 */
int shfs_journal_scan(shfs_t *tree, shkey_t *key, shfs_idx_t *idx);

/**
 * Release all resources being used to reference a shared partition journal.
 * @param jrnl_p A reference to the journal.
 * @returns A zero (0) on success and a negative error code on failure.
 */
int shfs_journal_close(shfs_journal_t **jrnl_p);

/**
 * Retrieve an inode block from a journal.
 */
shfs_block_t *shfs_journal_block(shfs_journal_t *jrnl, int ino);

/**
 * Calculates the byte size of a sharefs partition journal.
 */
size_t shfs_journal_size(shfs_journal_t *jrnl);

void shfs_journal_cache_free(shfs_t *tree);

/**
 * Identify the default journal number for a inode's name.
 * @returns A sharefs filesystem journal index number.
 * @note Journal #0 is reserved for system use. 
 */
int shfs_journal_index(shkey_t *key);

/**
 * @}
 */








/**
 * Provides the capability to manage symbolic link references to other inodes.
 * @ingroup libshare_fs
 * @defgroup libshare_fslink Symbolic Link Management
 * @{
 */




struct shfs_dirent_t
{
  char d_name[SHFS_PATH_MAX];
  struct stat d_stat; 
  uint64_t d_crc;
  shfs_ino_type_t d_type;
  shfs_ino_type_t d_format;
  shfs_attr_t d_attr;
};
typedef struct shfs_dirent_t shfs_dirent_t;


/**
 * Link a child inode inside a parent's directory listing.
 * @note The birth timestamp and token key is assigned on link.
 */
int shfs_link(shfs_ino_t *parent, shfs_ino_t *inode);

/**
 * Find an inode in it's parent using it's key name.
 */
int shfs_link_find(shfs_ino_t *parent, shkey_t *key, shfs_block_t *ret_blk);

/** Obtain the number of inode's contained by a parent. */
int shfs_link_count(shfs_ino_t *parent);


/**
 * Frees a list of directory entries.
 * @param ent_p A reference to the array of entries.
 */
void shfs_list_free(shfs_dirent_t **ent_p);

/**
 * @}
 */




/**
 * Provides capabilities to list inode contents such as files in directories.
 * @ingroup libshare_fs
 * @defgroup libshare_fslist Inode Indexing 
 * @{
 */

typedef int (*shfs_list_f)(shfs_ino_t *file, void *arg);
#define SHLIST_F(_f) ((shfs_list_f)(_f))

/**
 * Obtain a list of inode's contained by the parent.
 * @param file The inode to list the contents of. 
 * @param fspec NULL to list all entries or a file-spec format (i.e. "file*name")
 * @returns The number of directory entries returned or a negative libshare error code.
 */
int shfs_list(shfs_ino_t *file, char *fspec, shfs_dirent_t **ent_p);

void shfs_list_free(shfs_dirent_t **ent_p);

int shfs_list_cb(shfs_ino_t *parent, char *fspec, shfs_list_f cb, void *arg);


/**
 * @}
 */






/**
 * Provides the ability to create semaphores associated with a particular inode.
 * @ingroup libshare_fs
 * @defgroup libshare_fslock File-system Locks
 * @{
 */

int shfs_lock(shfs_ino_t *inode, int mask);

int shfs_lock_of(shfs_ino_t *inode, int mask, size_t of, size_t len);

int shfs_unlock(shfs_ino_t *inode);

int shfs_locked(shfs_ino_t *inode);

/**
 * @}
 */





/**
 * Provides the ability to manage the contents of a Directory Inode.
 * @ingroup libshare_fs
 * @defgroup libshare_fsdir Directory Inode Management
 * @{
 */

struct shfs_dir_t
{
  char path[SHFS_PATH_MAX];
  shfs_t *fs;
  shfs_t *alloc_fs;
  
  int ino_tot;
  int ino_idx;
  shfs_dirent_t *ino;
};
typedef struct shfs_dir_t shfs_dir_t;
typedef shfs_dir_t *SHDIR;


/**
 * The base SHINODE_PARTITION type inode for a sharefs partition.
 */
shfs_ino_t *shfs_dir_base(shfs_t *tree);

/**
 * The current working inode directory for a sharefs partition.
 */
shfs_ino_t *shfs_dir_cwd(shfs_t *tree);

/**
 * @returns The SHINODE_DIRECTORY parent of an inode.
 */
shfs_ino_t *shfs_dir_parent(shfs_ino_t *inode);

/**
 * Return an inode from a directory inode.
 */
shfs_ino_t *shfs_dir_entry(shfs_ino_t *inode, char *fname);

/**
 * Locate a directory inode on a sharefs partition by an absolute pathname. 
 */
shfs_ino_t *shfs_dir_find(shfs_t *tree, char *path);

/**
 * Open a directory to be listed. 
 * @param fs The sharefs partition to use or NULL for default.
 * @returns A resource for tracking a directory list.
 */
shfs_dir_t *shfs_opendir(shfs_t *fs, char *path);
/* Read the next directory entry. */
shfs_dirent_t *shfs_readdir(shfs_dir_t *dir);
/* Close the directory list resources. */
int shfs_closedir(shfs_dir_t *dir);

int shfs_chroot(shfs_t *fs, shfs_ino_t *dir);
int shfs_chroot_path(shfs_t *fs, char *path);

int shfs_dir_remove(shfs_ino_t *dir);

int shfs_list_fnmatch(shfs_ino_t *file, char *fspec, shfs_dirent_t **ent_p);

/**
 * @}
 */




/**
 * Provides the manage auxiliary meta information associated with a particula Inode.
 * @ingroup libshare_fs
 * @defgroup libshare_fsmeta Auxiliary Meta Definition
 * @{
 */

/**
 * Obtain a reference to the meta definition hashmap associated with the inode entry.
 * @note The @c shfs_ino_t inode will cache the hashmap reference.
 * @param ent The inode entry.
 * @param val_p A memory reference to the meta definition hashmap being filled in.
 */
int shfs_meta(shfs_t *tree, shfs_ino_t *ent, shmap_t **val_p);

/**
 * Flush the inode's meta map to disk.
 * @param The inode associated with the meta map.
 * @param val The meta map to store to disk.
 * @returns A zero (0) on success and a negative one (-1) on failure.
 */
int shfs_meta_save(shfs_t *tree, shfs_ino_t *ent, shmap_t *h);


/**
 * Retrieve a SHMETA_XX meta defintion from a share library file.
 */
const char *shfs_meta_get(shfs_ino_t *file, char *def);


int shfs_meta_perm(shfs_ino_t *file, char *def, shkey_t *user);
int shfs_meta_set(shfs_ino_t *file, char *def, char *value);


/* shfs_sig.c */

shkey_t *shfs_sig_get(shfs_ino_t *file);

int shfs_sig_set(shfs_ino_t *file, shkey_t *sig_key);

int shfs_sig_verify(shfs_ino_t *file, shkey_t *sig_key);

/**
 * @}
 */





/**
 * Provides the capability to read and write data to a File Inode.
 * @ingroup libshare_fs
 * @defgroup libshare_fsfile File I/O Access
 * @{
 */

/**
 * Write auxillary data to a sharefs file inode.
 */
int shfs_write(shfs_ino_t *file, shbuf_t *buff);

/** Obtain a segment from a file's data content. 
 * @note An SHERR_NOENT error occurs if file format is not set.
 */
int shfs_read_of(shfs_ino_t *file, shbuf_t *buff, off_t of, size_t size);

/**
 * Obtain file data content.
 * @note An SHERR_NOENT error occurs if file format is not set.
 */
int shfs_read(shfs_ino_t *file, shbuf_t *buff);


int shfs_file_read(shfs_ino_t *file, unsigned char *data, size_t data_len);
int shfs_file_write(shfs_ino_t *file, unsigned char *data, size_t data_len);


shfs_ino_t *shfs_file_find(shfs_t *tree, char *path);

int shfs_file_pipe(shfs_ino_t *file, int fd);

int shfs_file_notify(shfs_ino_t *file);

int shfs_file_copy(shfs_ino_t *src_file, shfs_ino_t *dest_file);

int shfs_file_remove(shfs_ino_t *file);

/** 
 * Change the file size of a formatted inode.
 * @note Only SHFS_BINARY is currently supported.
 */
int shfs_truncate(shfs_ino_t *file, shsize_t len);

/**
 * @}
 */





/**
 * Inodes are temporarily stored in memory until they are no longer needed.
 * @ingroup libshare_fs
 * @defgroup libshare_fscache File-system Cache
 * @{
 */


shfs_ino_t *shfs_cache_get(shfs_ino_t *parent, shkey_t *name);

void shfs_cache_set(shfs_ino_t *parent, shfs_ino_t *inode);

void shfs_inode_cache_free(shfs_ino_t *inode);

/**
 * @}
 */








/**
 * Provices the core data storage functionality.
 * @ingroup libshare_fs
 * @defgroup libshare_fsaux Auxiliary Binary Storage
 * @{
 */

/**
 * Retrieve a full data segment of a sharefs filesystem inode.
 * @param inode The inode whose data is being retrieved.
 * @param ret_buff The @c shbuf_t return buffer.
 * @returns A zero (0) on success or an libshare error code no failure.
 */
int shfs_aux_read(shfs_ino_t *inode, shbuf_t *ret_buff);

/**
 * Retrieve a full or partial data segment of a sharefs filesystem inode.
 * @param inode The inode whose data is being retrieved.
 * @param ret_buff The @c shbuf_t return buffer.
 * @param seek_of The offset to begin reading data from the inode.
 * @param seek_max The length of data to be read or zero (0) to indicate no limit.
 * @returns A zero (0) on success or an libshare error code no failure.
 */
int shfs_aux_pread(shfs_ino_t *inode, shbuf_t *ret_buff, 
    off_t seek_of, size_t seek_max);

/**
 * Stores a full data segment to a sharefs filesystem inode.
 * @param inode The inode whose data is being retrieved.
 * @param buff The data segment to write to the inode.
 * @returns A zero (0) on success or an libshare error code no failure.
 * @note A inode must be linked before it can be written to.
 */
int shfs_aux_write(shfs_ino_t *inode, shbuf_t *buff);

/**
 * Stores a full or partial data segment to a sharefs filesystem inode.
 * @param inode The inode whose data is being retrieved.
 * @param buff The data segment to write to the inode.
 * @param seek_of The offset to begin writing data to the inode.
 * @param seek_max The length of data to be write or zero (0) to indicate no limit.
 * @returns A zero (0) on success or an libshare error code no failure.
 * @note A inode must be linked before it can be written to.
 */
int shfs_aux_pwrite(shfs_ino_t *inode, shbuf_t *buff, off_t seek_of, size_t seek_max);

/**
 * Writes the auxillary contents of the inode to the file descriptor.
 * @param inode The sharefs filesystem inode to print from.
 * @param fd A posix file descriptor number representing a socket or local filesystem file reference.
 * @returns The size of the bytes written or a SHERR_XX error code on error.
 * On error one of the following error codes will be set:
 *   SHERR_BADF  fd is not a valid file descriptor or is not open for writing.
 */ 
ssize_t shfs_aux_pipe(shfs_ino_t *inode, int fd);

uint64_t shfs_aux_crc(shfs_ino_t *inode);

/**
 * @}
 */







/**
 * Provides the ability to manage inode attributes. 
 *
 * Read, write, and execution permissions may be applied.
 *
 * Here is a summary of the boolean inode attributes supported:
 * - SHATTR_ARCH A directory composed of an archive of files.
 * - SHATTR_DB A (sqlite) database inode. 
 * - SHATTR_ENC An inode that has been encrypted.
 * - SHATTR_FLOCK An inode that has been locked.
 * - SHATTR_LINK An inode referencing another inode.
 * - SHATTR_SYNC An inode that is synchronized with sharenet.
 * - SHATTR_VER An inode that tracks a revision history.
 * - SHATTR_COMP An inode that is stored in compressed format.
 * @ingroup libshare_fs
 * @defgroup libshare_fsattr Inode Attributes 
 * @{
 */

/** Check whether a user has read permission to an inode.  */
int shfs_access_read(shfs_ino_t *file, shkey_t *id_key);

/** Check whether a user has write permission to an inode.  */
int shfs_access_write(shfs_ino_t *file, shkey_t *id_key);

/** Check whether a user has exec permission to an inode.  */
int shfs_access_exec(shfs_ino_t *file, shkey_t *id_key);

/** Set the owner of a file to an identity key. */
int shfs_access_owner_set(shfs_ino_t *file, shkey_t *id_key);

/** Get a file owner's identity key. */
shkey_t *shfs_access_owner_get(shfs_ino_t *file);


char *shfs_attr_label(int attr_idx);
shfs_attr_t shfs_block_attr(shfs_block_t *blk);
shfs_attr_t shfs_attr(shfs_ino_t *inode);
char *shfs_attr_str(shfs_attr_t attr);

int shfs_attr_set(shfs_ino_t *file, int attr);
int shfs_attr_unset(shfs_ino_t *file, int attr);


int shfs_cred_store(shfs_ino_t *file, shkey_t *key, unsigned char *data, size_t data_len);
int shfs_cred_load(shfs_ino_t *file, shkey_t *key, unsigned char *data, size_t max_len);

/**
 * @}
 */



/**
 * Provides the capability to compress an Inode using the ZLIB inflate library routine.
 * @ingroup libshare_fs
 * @defgroup libshare_fszlib Inode Compression
 * @{
 */

int shfs_zlib_read(shfs_ino_t *file, shbuf_t *buff);

int shfs_zlib_write(shfs_ino_t *file, shbuf_t *buff);


/**
 * @}
 */



/**
 * Provides a Binary Inode which encapsulates auxiliary data.
 * @ingroup libshare_fs
 * @defgroup libshare_fsbin Binary Data Encapsulation
 * @{
 */

/** Read binary segment from a file. */
int shfs_bin_read_of(shfs_ino_t *file, shbuf_t *buff, off_t of, size_t size);

/** Read binary content from a file. */
int shfs_bin_read(shfs_ino_t *file, shbuf_t *buff);

/** Write binary content to a file. */
int shfs_bin_write(shfs_ino_t *file, shbuf_t *buff);


/**
 * @}
 */



/**
 * Provides the core functionality for referencing inodes.
 * @ingroup libshare_fs
 * @defgroup libshare_fsref Inode Reference
 * @{
 */

#define SHFS_MAX_REFERENCE_HIERARCHY \
  ( (SHFS_BLOCK_DATA_SIZE - sizeof(shpeer_t)) / sizeof(shkey_t) )

/** Retrieve information about a reference share-fs inode. */
int shfs_ref_read(shfs_ino_t *file, shbuf_t *buff);

/** Create a reference to another share-fs inode. */
int shfs_ref_write(shfs_ino_t *file, shbuf_t *buff);

/** Create a reference to another share-fs inode. */
int shfs_ref_set(shfs_ino_t *file, shfs_ino_t *ref_file);

/** Obtain a reference to another share-fs inode. */
int shfs_ref_get(shfs_ino_t *file, shfs_t **ref_fs_p, shfs_ino_t **ref_file_p);

/**
 * @}
 */




/**
 * Provides the ability to read and write entire files on the local hard-disk.
 * @ingroup libshare_fs
 * @defgroup libshare_fsmem Local File Buffer
 * @{
 */

/** Read a file from the local filesystem into a memory buffer. */
int shfs_mem_read(char *path, shbuf_t *buff);

/**
 * Read a file from the local filesystem into memory.
 */
int shfs_read_mem(char *path, char **data_p, size_t *data_len_p);

/** Write a file from a memory buffer to the local filesystem. */
int shfs_mem_write(char *path, shbuf_t *buff);

/**
 * Write a file from memory to the local filesystem.
 */
int shfs_write_mem(char *path, void *data, size_t data_len);

/**
 * @}
 */





/**
 * Provides the capabilities to track ongoing revisions to a file.
 * @ingroup libshare_fs
 * @defgroup libshare_fsrev Content Revision History
 * @{
 */

int shfs_rev_init(shfs_ino_t *file);
int shfs_rev_clear(shfs_ino_t *file);

/** Obtain a revision inode from a branch name. */
shfs_ino_t *shfs_rev_branch_resolve(shfs_ino_t *repo, char *name);

/** Obtain a revision inode from a tag name. */
shfs_ino_t *shfs_rev_tag_resolve(shfs_ino_t *repo, char *name);

/** Obtain the current committed revision. */
shfs_ino_t *shfs_rev_base(shfs_ino_t *repo);

int shfs_rev_ref_read(shfs_ino_t *file, char *group, char *name, shbuf_t *buff);
int shfs_rev_ref_write(shfs_ino_t *file, char *group, char *name, shbuf_t *buff);

shfs_ino_t *shfs_rev_prev(shfs_ino_t *rev);

int shfs_rev_delta_read(shfs_ino_t *rev, shbuf_t *buff);
int shfs_rev_delta_write(shfs_ino_t *rev, shbuf_t *buff);

const char *shfs_rev_desc_get(shfs_ino_t *rev);

int shfs_rev_commit(shfs_ino_t *file, shfs_ino_t **rev_p);

int shfs_rev_cat(shfs_ino_t *file, shkey_t *rev_key, shbuf_t *buff, shfs_ino_t **rev_p);

/** Obtain a binary delta containing the differences between the current file's data-content and the last committed revision's data-content. */
int shfs_rev_delta(shfs_ino_t *file, shbuf_t *diff_buff);

int shfs_rev_branch(shfs_ino_t *repo, char *name, shfs_ino_t *rev);

int shfs_rev_tag(shfs_ino_t *repo, char *name, shfs_ino_t *rev);

int shfs_rev_switch(shfs_ino_t *file, char *ref_name, shfs_ino_t **rev_p);

int shfs_rev_revert(shfs_ino_t *file);

int shfs_rev_checkout(shfs_ino_t *file, shkey_t *key, shfs_ino_t **rev_p);

int shfs_rev_diff(shfs_ino_t *file, shkey_t *rev_key, shbuf_t *buff);

void shfs_rev_desc_set(shfs_ino_t *rev, char *desc);

/**
 * @}
 */




/**
 * Manage auxiliary keys associated with an Inode.
 * @ingroup libshare_fs
 * @defgroup libshare_fsobj Object Key Reference
 * @{
 */
struct shfs_block_obj_t
{
  char name[SHFS_PATH_MAX];
  shkey_t key;
};
typedef struct shfs_block_obj_t shfs_block_obj_t;

int shfs_obj_set(shfs_ino_t *file, char *name, shkey_t *key);
int shfs_obj_get(shfs_ino_t *file, char *name, shkey_t **key_p);

/**
 * @}
 */





/**
 * Provides the functionality to manage a privatized area that is associated with a particular identity.
 * @ingroup libshare_fs
 * @defgroup libshare_fshome Home Directory Access
 * @{
 */

shfs_t *shfs_home_fs(shkey_t *id_key);

shfs_ino_t *shfs_home_file(shfs_t *fs, char *path);

shpeer_t *shfs_home_peer(shkey_t *id_key);

/**
 * @}
 */







/**
 * Access share-fs file I/O using a streamed buffer.
 * @ingroup libshare_fs
 * @defgroup libshare_fsstream File Buffered Stream
 * @{
 */

#define SHFS_STREAM_OPEN (1 << 0)
#define SHFS_STREAM_READ (1 << 1) /* unused */
#define SHFS_STREAM_WRITE (1 << 2) /* unused */
#define SHFS_STREAM_FSALLOC (1 << 3)
#define SHFS_STREAM_DIRTY (1 << 4)
//#define SHFS_STREAM_MEMORY (1 << 5)
#define SHFS_STREAM_CREATE (1 << 6)
/** Incremental writes cannot be made until a full write occurs. */
#define SHFS_STREAM_SYNC (1 << 7)

/**
 * The current stream positioned when stream-based I/O is performed.
 * @see shfopen()
 */
struct shfstream_t
{
  /** An allocated partition private to the stream. */
  shfs_t *fs;
  /** The file being streamed. */
  shfs_ino_t *file;
  /** buffered data segment of inode data */
  shbuf_t *buff;  
#if 0
  /** RESERVED/UNUSED: offset for data segment from beginning inode data */
  off_t buff_of;
  /** minimum offset of dirty region. */
  off_t buff_wof;
#endif
  /** current IO read/write index position of data segment (buff). */
  off_t buff_pos;
  /** current limit of stream size */
  size_t buff_max;
  /** file stream state modifiers */
  int flags;
};

typedef struct shfstream_t shfstream_t;



/**
 * Initialize a file stream.
 */
int shfstream_init(shfstream_t *stream, SHFL *file);

/**
 * Open a file stream.
 */
int shfstream_open(shfstream_t *stream, const char *path, shfs_t *fs);

/**
 * Obtain a file stream's descriptor data.
 */
shfstream_t *shfstream_get(int fd);

/**
 * Get the next available file stream descriptor number.
 */
int shfstream_getfd(void);

/**
 * Set the current byte position of a file stream.
 */
int shfstream_setpos(shfstream_t *stream, size_t pos);

/**
 * Obtain the current byte position of a file stream.
 */
size_t shfstream_getpos(shfstream_t *stream);

/**
 * Transition file stream into a closed state.
 */
int shfstream_close(shfstream_t *stream);

int shfstream_stat(shfstream_t *stream, struct stat *buf);

int shfstream_truncate(shfstream_t *stream, size_t len);

int shfstream_alloc(shfstream_t *stream, size_t size);

int shfstream_flush(shfstream_t *stream);

ssize_t shfstream_read(shfstream_t *stream, void *ptr, size_t size);

ssize_t shfstream_write(shfstream_t *stream, const void *ptr, size_t size);

/**
 * Flushes any unwritten data to the file-system.
 * @note Flushes at a maximum rate of once per second.
 */
int shfstream_sync(shfstream_t *stream);

/**
 * @}
 */







/**
 * Provides share-filesystem Inode certification and licensing.
 * @ingroup libshare_fs
 * @defgroup libshare_fslic Certification and Licensing
 * @{
 */

#define SHCERT_VERSION_1 1
#define SHCERT_VERSION_2 2
#define SHCERT_VERSION_3 3

/** An indication that the certificate is issued by an individual. */
#define SHCERT_ENT_INDIVIDUAL (1 << 0)
/** An indication that the certificate is issued by an organization. */
#define SHCERT_ENT_ORGANIZATION (1 << 2)
/** An indication that the certificate is issued by a company. */
#define SHCERT_ENT_COMPANY (1 << 3)
/** An indication that the certificate is in a private state. */
#define SHCERT_ENT_PRIVATE (1 << 4)

/** The certificate contains supplemental encipher authorization. */
#define SHCERT_CERT_NONREPUDIATION_ENCIPHER (1 << 8)
/** The certificate can allocate new rights to derived entities. */
#define SHCERT_CERT_RIGHTS_ISSUER (1 << 9)
/** Indicates the certificate has a parent authority. */
#define SHCERT_CERT_CHAIN (1 << 10)
/** The public key is capable of being used as a digital signature. */
#define SHCERT_CERT_SIGN (1 << 11)
/** Indicates the ability to sign a CRL. */
#define SHCERT_CERT_CRL (1 << 12)
/** Indicates the ability to act as a digital signature. */
#define SHCERT_CERT_DIGITAL (1 << 13)
/** The public key is capability of being used for a key agreement. */
#define SHCERT_CERT_KEY (1 << 14)
/** The public key is capability of being used for data encipherment. */
#define SHCERT_CERT_ENCIPHER (1 << 16)
/** An authentication that can be asserted to be genuine with high assurance */
#define SHCERT_CERT_NONREPUDIATION (1 << 17)
/** The public key is capable of being used for licensing. */
#define SHCERT_CERT_LICENSE (1 << 18)

/** Indiciates that the certificate can be validated by a web client. */
#define SHCERT_AUTH_WEB_CLIENT (1 << 20)
/** Indiciates that the certificate can be validated via a web server. */
#define SHCERT_AUTH_WEB_SERVER (1 << 21)
/** An indication that the certificate can be validated via a system certificate file. */
#define SHCERT_AUTH_FILE (1 << 22)
#define SHCERT_AUTH_DEVICE (1 << 23)


struct shlic_t
{

  /** privileged key of the sharefs partition where license presides. */
  shkey_t lic_fs;

  /** token key of file that is licensed */
  shkey_t lic_ino;

  /* licence parent certificate ID */
  shkey_t lic_pid;

  uint64_t lic_crc;

  shesig_t esig;

};
typedef struct shlic_t shlic_t;


#if 0
/**
 * Save a certificate to the system-level certificate directory.
 * @param cert The certificate to store.
 * @param ref_path A optional relative path [to the sys cert dir] to reference the certificate.
 * @param buff The data to store or NULL to only store the "cert" structure
 */
int shfs_cert_save(shesig_t *cert, char *ref_path);

/**
 * Save raw certificate data to the system-level certificate directory.
 * @param cert The certificate to store.
 * @param ref_path A optional relative path [to the sys cert dir] to reference the certificate.
 * @param buff The data to store or NULL to only store the "cert" structure
 */
int shfs_cert_save_buff(shesig_t *cert, char *ref_path, shbuf_t *buff);

int shfs_cert_apply(SHFL *file, shesig_t *cert);

int shfs_cert_get(SHFL *fl, shesig_t **cert_p, shlic_t **lic_p);

shesig_t *shfs_cert_load_ref(char *ref_path);

int shfs_cert_remove_ref(char *ref_path);

char *shfs_cert_filename(shesig_t *cert);
#endif


/**
 * @}
 */






/**
 * Provides the definitions for common data formats.
 * @ingroup libshare_fs
 * @defgroup libshare_fsmime Inode Mime Type
 * @{
 */


/** A non-specific mime definition directive. */
#define SHMIMEOP_NONE 0
/** A SEXE executable path to process the mime type. */
#define SHMIMEOP_SEXE 1

#define SHMIME_BINARY "application/octet-stream"
#define SHMIME_TEXT_PLAIN "text/plain"
#define SHMIME_APP_GZIP "application/x-gzip"
#define SHMIME_APP_LINUX "application/octet-stream/elf"
#define SHMIME_APP_LINUX_32 "application/octet-stream/elf-32"
#define SHMIME_APP_TAR "application/x-tar"
#define SHMIME_APP_PEM "application/x-pem-file"
#define SHMIME_APP_SQLITE "application/x-sqlite3"
#define SHMIME_APP_SEXE "application/x-sexe"

#define SHMIME_APP_BZ2 "application/bz2"
#define SHMIME_APP_RAR "application/rar"
#define SHMIME_APP_ZIP "application/zip"
#define SHMIME_APP_XZ "application/xz"
#define SHMIME_APP_WIN "application/exe"

#define SHMIME_IMG_GIF "image/gif"
#define SHMIME_IMG_PNG "image/png"
#define SHMIME_IMG_JPEG "image/jpeg"

#define MAX_DEFAULT_SHARE_MIME_TYPES 18

/**
 * Maximum length of a file's header to scan in order to detect mime type.
 */
#define MAX_MIME_HEADER_SIZE 512 /* < SHFS_BLOCK_DATA_SIZE  */


struct shmime_def_t
{
  /** a mime definition directive */
  int def_op;
  /** the directive's content value */
  char def_val[MAX_SHARE_NAME_LENGTH];
};
typedef struct shmime_def_t shmime_def_t;

typedef struct shmime_t
{
  /* standard ISO/IEC 15444 mime-type name */
  char mime_name[MAX_SHARE_NAME_LENGTH];
  /* file-spec pattern */
  char mime_pattern[SHFS_PATH_MAX];
  /* default installation system sharefs directory */
  char mime_dir[SHFS_PATH_MAX];
  /** a regex format representation of a file header segment. */
  char mime_header[64];
  /** the content of the binary header's prefix to compare against. */
  uint32_t mime_header_len;
  /** total number of file content definitions. */
  uint32_t mime_def_len;
  /* file content definition(s). */
  struct shmime_def_t mime_def[0]; 
} shmime_t;

shmime_t *shmime(char *type);

shmime_t *shmime_file(shfs_ino_t *file);

char *shmime_print(shmime_t *mime);
char **shmime_default_dirs(void);

/**
 * @}
 */







/**
 * Provides the capabilities to perform SQL database operations on a Database Inode.
 * @ingroup libshare_fs
 * @defgroup libshare_fsdb Database Inode Access
 * @{
 */

typedef struct sqlite3 shdb_t;

typedef int (*shdb_cb_t)(void *, int, char **, char **); 

typedef uint64_t shdb_idx_t;


shdb_t *shdb_open(char *db_name);

shdb_t *shdb_open_peer(char *db_name, shpeer_t *peer);

int shdb_exec(shdb_t *db, char *sql);

void shdb_close(shdb_t *db);

int shdb_row_find(shdb_t *db, char *table, uint64_t *rowid_p, char *col, char *val, int flags);

int shdb_col_num_cb(void *p, int arg_nr, char **args, char **cols);

int shdb_col_value_cb(void *p, int arg_nr, char **args, char **cols);

char *shdb_row_value(shdb_t *db, char *table, shdb_idx_t rowid, char *col);

int shdb_row_delete(shdb_t *db, char *table, shdb_idx_t rowid);

/**
 * Obtain a set of rows from a shdb database table in JSON format.
 * @param db The database to obtain the records from.
 * @param rowid_of The rowid offset or 0 for none.
 * @param rowid_len The maximum number of records to obtain or 0 for unlimited.
 * @returns An allocated JSON hierarchy compatible with libshare.
 * @see shjson_free
 */
shjson_t *shdb_json_write(shdb_t *db, char *table, shdb_idx_t rowid_of, shdb_idx_t rowid_len);

/**
 * Parse JSON into a database.
 */
int shdb_json_read(shdb_t *db, shjson_t *json);

int shdb_row_set_time_adj(shdb_t *db, char *table, shdb_idx_t rowid, char *col, unsigned int dur);

int shdb_row_set(shdb_t *db, char *table, shdb_idx_t rowid, char *col, char *text);

int shdb_row_new(shdb_t *db, char *table, shdb_idx_t *rowid_p);

int shdb_exec_cb(shdb_t *db, char *sql, shdb_cb_t func, void *arg);

int shdb_col_new(shdb_t *db, char *table, char *col);

int shdb_table_new(shdb_t *db, char *table);

/**
 * @}
 */





/**
 * An archived directory can be read in order to retrieve a SHZ formatted file of the directory's content. An archived directory may have SHZ formatted file data written to it in order to populate it's heirarchy.
 * @ingroup libshare_fs
 * @defgroup libshare_fsarch Archived Directory Storage
 * @{
 */

/** Read an 'archive' directory inode into SHZ format. */
int shfs_arch_read(SHFL *file, shbuf_t *buff);

/** Write SHZ formatted data to a directory. */
int shfs_arch_write(SHFL *file, shbuf_t *buff);


/**
 * @}
 */




/**
 * @}
 */




/**
 * Standard libc implementations of the core file and network I/O routines.
 * @ingroup libshare
 * @defgroup libshare_posix File and Network POSIX Compatilibity 
 * @{
 */

/**
 * Open a sharefs file inode for stream-based I/O
 * @param fs The sharefs partition or NULL for default.
 */
int shopen(const char *path, const char *mode, shfs_t *fs);

/**
 * Close a previously opened stream.
 */
int shclose(int fd);

int shtmpfile(void);

/** Set the current seek offset in a sharefs file stream. */
int shfsetpos(int fd, size_t pos);

/** Get the current seek offset of a sharefs file stream. */
int shfgetpos(int fd, size_t *pos);

/** Get the current seek offset of a sharefs file stream. */
size_t shftell(int fd);

/** Set the current seek offset to the beginning of the stream. */
int shrewind(int fd);

/** 
 * Set the current seek offset in a sharefs file stream.
 * @see fseek()
 */
ssize_t shfseek(int fd, size_t offset, int whence);

/**
 * Read a segment of data from a stream.
 */
int shread(int fd, void *ptr, size_t size);

/**
 * Write a segment of data to a stream.
 */
int shwrite(int fd, void *ptr, size_t size);

/** Flush any pending data to be written from a buffered stream to a file */
int shflush(int fd);

/** Truncate a data stream to a specified length. */
int shftruncate(int fd, size_t len);

/** Obtain file information using POSIX style "stat" struct. */
int shfstat(int fd, struct stat *buf);

ssize_t shfsize(int fd);

int shfgetc(int fd);

/**
 * @}
 */



#endif /* ndef __FS__SHFS_H__ */



