
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
*/  

#ifndef __MEM__SHMEM_H__
#define __MEM__SHMEM_H__

#if defined(HAVE_PTHREAD_MUTEX_LOCK) && defined(HAVE_PTHREAD_MUTEX_UNLOCK)
#include <pthread.h>
#endif
#include <sys/types.h>
#include <sys/time.h>


#ifndef DOXYGEN_SHOULD_SKIP_THIS 

#ifndef DBL_EPSILON
#define DBL_EPSILON 2.2204460492503131E-16
#endif

#ifndef INT_MAX
#define INT_MAX 0x7FFF/0x7FFFFFFF
#endif

#ifndef INT_MIN
#define INT_MIN ((int) 0x8000/0x80000000)
#endif

#if !defined(HAVE_GETTID) && defined(HAVE_PTHREAD_SELF)
#define gettid() \
((pid_t)pthread_self())
#endif

#ifndef HAVE_HTONLL
#define htonll(x) ((1==htonl(1)) ? (x) : ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#endif

#ifndef HAVE_NTOHLL
#define ntohll(x) ((1==ntohl(1)) ? (x) : ((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))
#endif

#endif /* ndef DOXYGEN_SHOULD_SKIP_THIS */



/**
 * Memory manipulation routines.
 * @ingroup libshare
 * @defgroup libshare_mem Encryption, memory pools, and hashmaps.
 * @{
 */


/**
 * A 64bit arbitrary number which is gauranteed to be the same on high and low endian computers.
 * @see shmap_value_t shencode()
 */
#define SHMEM_MAGIC 0x2288882222888822
/**
 * A 32bit arbitrary number which is gauranteed to be the same on high and low endian computers.
 * @see shmap_value_t shencode()
 */
#define SHMEM32_MAGIC ((SHMEM_MAGIC >> 32) & 0xFFFFFFFF)
/**
 * A 16bit arbitrary number which is gauranteed to be the same on high and low endian computers.
 */
#define SHMEM16_MAGIC ((SHMEM_MAGIC >> 24) & 0xFFFF)
/**
 * A single arbitrary byte (8 bits).
 */
#define SHMEM8_MAGIC ((SHMEM_MAGIC >> 16) & 0xFF)
/**
 * A arbitrary 32bit number which is gauranteed to different on both and low endian computers.
 * @note Specifies a hard-coded value that identifies a @c shmap_value_t data segment.
 */
#define SHMEM_ENDIAN_MAGIC 0x12345678

/**
 * A arbitrary 16bit number which is gauranteed to different on both and low endian computers.
 * @note Specifies a hard-coded value that identifies a @c shmap_value_t data segment.
 */
#define SHMEM16_ENDIAN_MAGIC ((SHMEM_ENDIAN_MAGIC >> 16) & 0xFFFF)


/**
 * The byte padding size when allocating a stored value.
 * @see shencode() shmap_set()
 */
#define SHMEM_PAD_SIZE 32 






/**
 * Dynamic memory buffer allocation utilities.
 * @ingroup libshare_mem
 * @defgroup libshare_membuf Dynamic Memory Buffer
 * @{
 */

/* The data buffer is pre-allocated by the user and cannot be enlarged. */
#define SHBUF_PREALLOC (1 << 0)

/* The data buffer linked to a posix file memory-map. */
#define SHBUF_FMAP (1 << 1)

#define SHBUF_MUTEX (1 << 2)

/**
 * A memory buffer that utilizes that re-uses available memory to reduce OS overhead and dynamically grows to a user specific need.
 * @see shbuf_init shbuf_free
 *
 */
struct shbuf_t {

	/* The underlying data segment. */
  unsigned char *data;

	/* The current used size of the data segment. */
  size_t data_of;

	/* The current allocated space to use for the data segment. */
  size_t data_max;

	/* An I/O seek offset into the data segment. */
  size_t data_pos;
	/* Modifier flags for the data segment. */
  int flags;

	/* An optional file descriptor mapping the data segment. */
  int fd;

#ifdef USE_LIBPTHREAD
	/* A mutex lock for data segment access concurrency. */
	pthread_mutex_t lk;
#endif
};

/*
 * A memory buffer.
 */
typedef struct shbuf_t shbuf_t;

/**
 * @returns TRUE or FALSE whether buffers contain identical data.
 */
int shbuf_cmp(shbuf_t *buff, shbuf_t *cmp_buff);


/**
 * Initialize a memory buffer for use.
 * @note A @c shbuf_t memory buffer handles automatic allocation of memory.
 */
shbuf_t *shbuf_init(void);

/**
 * Inserts a string into a @c shbuf_t memory pool.
 */
void shbuf_catstr(shbuf_t *buf, char *data);

/**
 * Inserts a binary data segment into a @c shbuf_t memory pool.
 */
void shbuf_cat(shbuf_t *buf, void *data, size_t data_len);

void shbuf_memcpy(shbuf_t *buf, void *data, size_t data_len);

/**
 * The current size of the data segement stored in the memory buffer.
 */
size_t shbuf_size(shbuf_t *buf);

unsigned char *shbuf_data(shbuf_t *buf);

/**
 * Clear the contents of a @c shbuf_t libshare memory buffer.
 */
void shbuf_clear(shbuf_t *buf);

/**
 * Reduce the data size of a memory buffer.
 * @param buf The memory buffer.
 * @param len The size of bytes to reduce by.
 * @note This removes data from the beginning of the data segment. 
 */
void shbuf_trim(shbuf_t *buf, size_t len);

void shbuf_truncate(shbuf_t *buf, size_t len);

void shbuf_dealloc(shbuf_t *buf);

/**
 * Frees the resources utilizited by the memory buffer.
 */
void shbuf_free(shbuf_t **buf_p);

/**
 * Grow the memory buffer to atleast the size specified.
 * @param buf The @ref shbuf_t memory buffer.
 * @param data_len The minimum byte size the memory buffer should be allocated.
 */
int shbuf_grow(shbuf_t *buf, size_t data_len);

/**
 * Map a file into a memory buffer.
 */
shbuf_t *shbuf_file(char *path);

int shbuf_growmap(shbuf_t *buf, size_t data_len);

shbuf_t *shbuf_map(unsigned char *data, size_t data_len);
shbuf_t *ashbuf_map(unsigned char *data, size_t data_len);
unsigned char *shbuf_unmap(shbuf_t *buf);

size_t shbuf_pos(shbuf_t *buff);

void shbuf_pos_set(shbuf_t *buff, size_t pos);

void shbuf_pos_incr(shbuf_t *buff, size_t pos);

size_t shbuf_idx(shbuf_t *buf, unsigned char ch);

void shbuf_padd(shbuf_t *buff, size_t len);

void shbuf_lock(shbuf_t *buff);

void shbuf_unlock(shbuf_t *buff);
 
/**
 * @}
 */







/**
 * Utility functions to generate unique checksums of data.
 * @ingroup libshare_mem
 * @defgroup libshare_memkey ShareKey Hash Digest
 * @{
 */

typedef struct shkey_t shkey_t;

/**
 * The maximum word size of the share key.
 */
#define SHKEY_WORDS 7

#define SHR224_SIZE 28
#define SHR224_BLOCKS 12
#define SHR224_BLOCK_SIZE (SHR224_BLOCKS * sizeof(uint64_t))

#define SHR224_IPAD_MAGIC (uint8_t)SHMEM8_MAGIC
#define SHR224_OPAD_MAGIC (uint8_t)~SHMEM8_MAGIC

typedef struct shr224_t
{

  /* hash */
  uint64_t data[SHR224_BLOCKS];
  size_t data_idx;

  uint32_t crc_a;
  uint64_t crc_b;

  /* pending input */
  unsigned char buff[8];
  size_t buff_len;

  /** A suffix to apply in an HMAC digest. */
  unsigned char suff[SHR224_SIZE];
  size_t suff_len;

} shr224_t;



/**
 * A key used to represent a hash code of an object.
 */
struct shkey_t 
{

  /** The code algorythm (SHALG_XXX). */
  uint16_t alg;

  /** An optional checksum. */
  uint16_t crc;

  /** The checksum values comprimising the key. */
  uint32_t code[SHKEY_WORDS];

};


/** A 160-bit key */
typedef uint32_t sh160_t[5];


/**
 * Generates a unique 192-bit key from a segment of data.
 * @note Algorythm is a combination of adler32 and sha256.
 */
shkey_t *shkey_bin(char *data, size_t data_len);

shkey_t *ashkey_bin(char *data, size_t data_len);

/**
 * Create a @c shkey_t hashmap key reference from @c kvalue
 * @a kvalue The string to generate into a @c shkey_t
 * @returns A @c shkey_t referencing #a kvalue
 */
shkey_t *shkey_str(char *kvalue);

/**
 * Create a @c shkey_t hashmap key reference from a 32bit number.
 * @a kvalue The number to generate into a @c shkey_t
 * @returns A statically allocated version of @kvalue 
 */
shkey_t *shkey_num(long kvalue);

/**
 * Create a @c shkey_t hashmap key reference from a 64bit number.
 * @a kvalue The number to generate into a @c shkey_t
 * @returns A statically allocated version of @kvalue 
 */
shkey_t *shkey_num64(uint64_t kvalue);

/**
 * Create a unique @c shkey_t hashmap key reference.
 * @returns A @c shkey_t containing a unique key value.
 */
shkey_t *shkey_uniq(void);

shkey_t *ashkey_uniq(void);

/**
 * A 64-bit numeric representation of a @ref shkey_t
 */
uint64_t shkey_crc(shkey_t *key);

void shkey_free(shkey_t **key_p);

uint64_t shrand(void);

shkey_t *shkey_xor(shkey_t *key1, shkey_t *key2);

shkey_t *ashkey_xor(shkey_t *key1, shkey_t *key2);

shkey_t *shkey_dup(shkey_t *key);

shkey_t *shkey(int alg, unsigned char *data, size_t data_len);




/**
 * A ascii string representation of a libshare key.
 * @note The string returned will be 36 characters long in a format similar to base64.
 */ 
const char *shkey_print(shkey_t *key);

/**
 * Generates a @ref shkey_t from a string that does not need to be freed.
 * @see shkey_free()
 * @bug psuedo thread-safe
 */
shkey_t *ashkey_str(char *name);

/**
 * Generates a @ref shkey_t from a number that does not need to be freed.
 * @see shkey_free()
 * @bug psuedo thread-safe
 */
shkey_t *ashkey_num(long num);

/**
 * Compare two @ref shkek_t key tokens.
 * @returns TRUE is keys are ientical and FALSE if not.
 */
int shkey_cmp(shkey_t *key_1, shkey_t *key_2);

/**
 * Generates a blank @ref shkey_t key token.
 * @returns A statically allocated blank key token.
 * @note Do not free the returned value.
 */
#define ashkey_blank() \
  ((shkey_t *)&_shkey_blank)

/**
 * Determines whether a @ref shkey_t has been initialized.
 * @returns FALSE is key is not blank, and TRUE is the key is blank.
 * @note It is possible to generate keys which equal a blank key, for example a key generated from a zero-length data segment. This macro should be utilitized only when it is known that the key being compared against has a unique value.
 */
#define shkey_is_blank(_key) \
  (0 == memcmp((_key), &_shkey_blank, sizeof(shkey_t)))

extern shkey_t _shkey_blank;

shkey_t *shkey_clone(shkey_t *key);

/**
 * Creates a certificate's signature key based off content attributes.
 */
shkey_t *shkey_cert(shkey_t *key, uint64_t crc, shtime_t stamp);

/**
 * Verifies whether content attributes match a generated certificate signature key.
 */
int shkey_verify(shkey_t *sig, uint64_t crc, shkey_t *key, shtime_t stamp);

/**
 * Converts a hex string into a binary key.
 */
shkey_t *shkey_gen(char *hex_str);

/**
 * A string hexadecimal representation of a libshare key.
 * @note The string returned will be 48 characters long.
 */ 
const char *shkey_hex(shkey_t *key);

/**
 * Generate a libshare key from a 48-character long hexadecimal string.
 */
shkey_t *shkey_hexgen(char *hex_str);

/**
 * Generate a allocated share-key from a 160bit binary segment.
 */
shkey_t *shkey_shr160(sh160_t raw);

/**
 * Generate a share-key on the stack from a 160bit binary segment.
 * @note Do not free the return value.
 */
shkey_t *ashkey_shr160(sh160_t raw);

/**
 * Obtain a 160bit binary segment from a pre-set 160-bit share-key.
 */
void sh160_key(shkey_t *in_key, sh160_t u160);


/** Generate a SHA256+RIPEMD160 20-byte hash in the form of a share-key. */
void shkey_shr160_hash(shkey_t *ret_key, unsigned char *data, size_t data_len);

/** Generate a 'u160' key from a printed key string. */
shkey_t *shkey_shr160_gen(char *key_str);

char *shkey_shr160_print(shkey_t *key);

int shkey_shr160_ver(shkey_t *key);







int shr224(unsigned char *data, size_t data_len, unsigned char *ret_digest);

int shr224_init(shr224_t *ctx);

int shr224_write(shr224_t *ctx, unsigned char *data, size_t data_len);

int shr224_result(shr224_t *ctx, unsigned char *ret_digest);

int shr224_hmac(unsigned char *key, size_t key_len, unsigned char *data, size_t data_len, unsigned char *ret_digest);

int shr224_hmac_init(shr224_t *ctx, unsigned char *key, size_t key_len);

int shr224_hmac_write(shr224_t *ctx, unsigned char *data, size_t data_len);

int shr224_hmac_result(shr224_t *ctx, unsigned char *ret_digest);

int shr224_expand(unsigned char *digest, unsigned char *data, size_t data_len);

int shr224_shrink(uint64_t crc, unsigned char *data, size_t data_len, unsigned char *ret_digest);

uint64_t shr224_crc(shr224_t *ctx);

shkey_t *ashkey_shr224(void *data, size_t data_len);

shkey_t *shkey_shr224(void *data, size_t data_len);

int shkey_shr224_ver(shkey_t *key, unsigned char *data, size_t data_len);

int shr224_result_key(shr224_t *ctx, shkey_t *key);

uint64_t shr224_result_crc(shr224_t *ctx, shkey_t *key);





void *memxor (void *dest, const void *src, size_t n);

int shkey_alg(shkey_t *key);

void shkey_alg_set(shkey_t *key, int alg);


/** 64-bit hexadecimal bcrc checksum of a string. */
char *bcrc_strhex(char *str);

/** 64-bit hexadecimal bcrc checksum. */
char *bcrc_hex(unsigned char *data, size_t data_len);

/** 64-bit integer bcrc checksum of a string. */
uint64_t bcrc_str(char *str);

/** 64-bit integer bcrc checksum. */
uint64_t bcrc(unsigned char *data, size_t data_len);


/**
 * @}
 */




/**
 * Multi-precision integers allow for the use of "big numbers" that would otherwise not be compatuable directly on the registers of common computers.
 * @ingroup libshare_mem
 * @defgroup libshare_memmpi Multi-precision Integer Library
 * @{
 */

#ifdef SHARELIB
#include "mem/shmem_mpi.h"
#endif

#define SHMPI_MAX_SIZE                              1024     /**< Maximum number of bytes for usable MPIs. */
#define SHMPI_MAX_BITS                              ( 8 * SHMPI_MAX_SIZE )    /**< Maximum number of bits for usable MPIs. */


#define SHMPI_ERR_FILE_IO_ERROR                     -0x0002  /**< An error occurred while reading from or writing to a file. */
#define SHMPI_ERR_BAD_INPUT_DATA                    -0x0004  /**< Bad input parameters to function. */
#define SHMPI_ERR_INVALID_CHARACTER                 -0x0006  /**< There is an invalid character in the digit string. */
#define SHMPI_ERR_BUFFER_TOO_SMALL                  -0x0008  /**< The buffer is too small to write to. */
#define SHMPI_ERR_NEGATIVE_VALUE                    -0x000A  /**< The input arguments are negative or result in illegal output. */
#define SHMPI_ERR_DIVISION_BY_ZERO                  -0x000C  /**< The input argument for division is zero, which is not allowed. */
#define SHMPI_ERR_NOT_ACCEPTABLE                    -0x000E  /**< The input arguments are not acceptable. */
#define SHMPI_ERR_MALLOC_FAILED                     -0x0010  /**< Memory allocation failed. */


/*
 * Define the base integer type, architecture-wise
 */
#if defined(MPI_HAVE_INT8)
typedef   signed char  t_sint;
typedef unsigned char  t_uint;
typedef uint16_t       t_udbl;
#define MPI_HAVE_UDBL
#else
#if defined(MPI_HAVE_INT16)
typedef  int16_t t_sint;
typedef uint16_t t_uint;
typedef uint32_t t_udbl;
#define MPI_HAVE_UDBL
#else
  /*
   * 32-bit integers can be forced on 64-bit arches (eg. for testing purposes)
   * by defining MPI_HAVE_INT32 and undefining MPI_HAVE_ASM
   */
  #if ( ! defined(MPI_HAVE_INT32) && \
          defined(_MSC_VER) && defined(_M_AMD64) )
    #define MPI_HAVE_INT64
    typedef  int64_t t_sint;
    typedef uint64_t t_uint;
  #else
    #if ( ! defined(MPI_HAVE_INT32) &&               \
          defined(__GNUC__) && (                          \
          defined(__amd64__) || defined(__x86_64__)    || \
          defined(__ppc64__) || defined(__powerpc64__) || \
          defined(__ia64__)  || defined(__alpha__)     || \
          (defined(__sparc__) && defined(__arch64__))  || \
          defined(__s390x__) || defined(__mips64) ) )
       #define MPI_HAVE_INT64
       typedef  int64_t t_sint;
       typedef uint64_t t_uint;
       typedef unsigned int t_udbl __attribute__((mode(TI)));
       #define MPI_HAVE_UDBL
    #else
       #define MPI_HAVE_INT32
       typedef  int32_t t_sint;
       typedef uint32_t t_uint;
       #if ( defined(_MSC_VER) && defined(_M_IX86) )
         typedef uint64_t t_udbl;
         #define MPI_HAVE_UDBL
       #else
         #if defined( MPI_HAVE_LONGLONG )
           typedef unsigned long long t_udbl;
           #define MPI_HAVE_UDBL
         #endif
       #endif
    #endif /* !MPI_HAVE_INT32 && __GNUC__ && 64-bit platform */
  #endif /* !MPI_HAVE_INT32 && _MSC_VER && _M_AMD64 */
#endif /* MPI_HAVE_INT16 */
#endif /* MPI_HAVE_INT8  */


/**
 * The multi-precision integer context
 */
typedef struct {
  int s;              /*!<  integer sign      */
  size_t n;           /*!<  total # of limbs  */
  t_uint *p;          /*!<  pointer to limbs  */
} shmpi;

/**
 * \brief           Initialize one MPI (make internal references valid)
 *                  This just makes it ready to be set or freed,
 *                  but does not define a value for the MPI.
 *
 * \param X         One MPI to initialize.
 */
void shmpi_init( shmpi *X );

/**
 * \brief          Unallocate one MPI
 *
 * \param X        One MPI to unallocate.
 */
void shmpi_free( shmpi *X );

/**
 * \brief          Enlarge to the specified number of limbs
 *
 * \param X        MPI to grow
 * \param nblimbs  The target number of limbs
 *
 * \return         0 if successful,
 *                 MPI_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
int shmpi_grow( shmpi *X, size_t nblimbs );

/**
 * \brief          Resize down, keeping at least the specified number of limbs
 *
 * \param X        MPI to shrink
 * \param nblimbs  The minimum number of limbs to keep
 *
 * \return         0 if successful,
 *                 MPI_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
int shmpi_shrink( shmpi *X, size_t nblimbs );

/**
 * \brief          Copy the contents of Y into X
 *
 * \param X        Destination MPI
 * \param Y        Source MPI
 *
 * \return         0 if successful,
 *                 MPI_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
int shmpi_copy( shmpi *X, const shmpi *Y );

/**
 * \brief          Swap the contents of X and Y
 *
 * \param X        First MPI value
 * \param Y        Second MPI value
 */
void shmpi_swap( shmpi *X, shmpi *Y );

/**
 * \brief          Safe conditional assignement X = Y if assign is 1
 *
 * \param X        MPI to conditionally assign to
 * \param Y        Value to be assigned
 * \param assign   1: perform the assignment, 0: keep X's original value
 *
 * \return         0 if successful,
 *                 MPI_ERR_MPI_MALLOC_FAILED if memory allocation failed,
 *
 * \note           This function is equivalent to
 *                      if( assign ) shmpi_copy( X, Y );
 *                 except that it avoids leaking any information about whether
 *                 the assignment was done or not (the above code may leak
 *                 information through branch prediction and/or memory access
 *                 patterns analysis).
 */
int shmpi_safe_cond_assign( shmpi *X, const shmpi *Y, unsigned char assign );

/**
 * \brief          Safe conditional swap X <-> Y if swap is 1
 *
 * \param X        First shmpi value
 * \param Y        Second shmpi value
 * \param assign   1: perform the swap, 0: keep X and Y's original values
 *
 * \return         0 if successful,
 *                 MPI_ERR_MPI_MALLOC_FAILED if memory allocation failed,
 *
 * \note           This function is equivalent to
 *                      if( assign ) shmpi_swap( X, Y );
 *                 except that it avoids leaking any information about whether
 *                 the assignment was done or not (the above code may leak
 *                 information through branch prediction and/or memory access
 *                 patterns analysis).
 */
int shmpi_safe_cond_swap( shmpi *X, shmpi *Y, unsigned char assign );

/**
 * \brief          Set value from integer
 *
 * \param X        MPI to set
 * \param z        Value to use
 *
 * \return         0 if successful,
 *                 MPI_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
int shmpi_lset( shmpi *X, t_sint z );

/**
 * \brief          Get a specific bit from X
 *
 * \param X        MPI to use
 * \param pos      Zero-based index of the bit in X
 *
 * \return         Either a 0 or a 1
 */
int shmpi_get_bit( const shmpi *X, size_t pos );

/**
 * \brief          Set a bit of X to a specific value of 0 or 1
 *
 * \note           Will grow X if necessary to set a bit to 1 in a not yet
 *                 existing limb. Will not grow if bit should be set to 0
 *
 * \param X        MPI to use
 * \param pos      Zero-based index of the bit in X
 * \param val      The value to set the bit to (0 or 1)
 *
 * \return         0 if successful,
 *                 MPI_ERR_MPI_MALLOC_FAILED if memory allocation failed,
 *                 MPI_ERR_MPI_BAD_INPUT_DATA if val is not 0 or 1
 */
int shmpi_set_bit( shmpi *X, size_t pos, unsigned char val );

/**
 * \brief          Return the number of zero-bits before the least significant
 *                 '1' bit
 *
 * Note: Thus also the zero-based index of the least significant '1' bit
 *
 * \param X        MPI to use
 */
size_t shmpi_lsb( const shmpi *X );

/**
 * \brief          Return the number of bits up to and including the most
 *                 significant '1' bit'
 *
 * Note: Thus also the one-based index of the most significant '1' bit
 *
 * \param X        MPI to use
 */
size_t shmpi_msb( const shmpi *X );

/**
 * \brief          Return the total size in bytes
 *
 * \param X        MPI to use
 */
size_t shmpi_size( const shmpi *X );

/**
 * \brief          Import from an ASCII string
 *
 * \param X        Destination MPI
 * \param radix    Input numeric base
 * \param s        Null-terminated string buffer
 *
 * \return         0 if successful, or a MPI_ERR_MPI_XXX error code
 */
int shmpi_read_string( shmpi *X, int radix, const char *s );

/**
 * \brief          Export into an ASCII string
 *
 * \param X        Source MPI
 * \param radix    Output numeric base
 * \param s        String buffer
 * \param slen     String buffer size
 *
 * \return         0 if successful, or a MPI_ERR_MPI_XXX error code.
 *                 *slen is always updated to reflect the amount
 *                 of data that has (or would have) been written.
 *
 * \note           Call this function with *slen = 0 to obtain the
 *                 minimum required buffer size in *slen.
 */
int shmpi_write_string( const shmpi *X, int radix, char *s, size_t *slen );

#if defined(MPI_FS_IO)
/**
 * \brief          Read X from an opened file
 *
 * \param X        Destination MPI
 * \param radix    Input numeric base
 * \param fin      Input file handle
 *
 * \return         0 if successful, MPI_ERR_MPI_BUFFER_TOO_SMALL if
 *                 the file read buffer is too small or a
 *                 MPI_ERR_MPI_XXX error code
 */
int shmpi_read_file( shmpi *X, int radix, FILE *fin );

/**
 * \brief          Write X into an opened file, or stdout if fout is NULL
 *
 * \param p        Prefix, can be NULL
 * \param X        Source MPI
 * \param radix    Output numeric base
 * \param fout     Output file handle (can be NULL)
 *
 * \return         0 if successful, or a MPI_ERR_MPI_XXX error code
 *
 * \note           Set fout == NULL to print X on the console.
 */
int shmpi_write_file( const char *p, const shmpi *X, int radix, FILE *fout );
#endif /* MPI_FS_IO */

/**
 * \brief          Import X from unsigned binary data, big endian
 *
 * \param X        Destination MPI
 * \param buf      Input buffer
 * \param buflen   Input buffer size
 *
 * \return         0 if successful,
 *                 MPI_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
int shmpi_read_binary( shmpi *X, const unsigned char *buf, size_t buflen );

/**
 * \brief          Export X into unsigned binary data, big endian.
 *                 Always fills the whole buffer, which will start with zeros
 *                 if the number is smaller.
 *
 * \param X        Source MPI
 * \param buf      Output buffer
 * \param buflen   Output buffer size
 *
 * \return         0 if successful,
 *                 MPI_ERR_MPI_BUFFER_TOO_SMALL if buf isn't large enough
 */
int shmpi_write_binary( const shmpi *X, unsigned char *buf, size_t buflen );

/**
 * \brief          Left-shift: X <<= count
 *
 * \param X        MPI to shift
 * \param count    Amount to shift
 *
 * \return         0 if successful,
 *                 MPI_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
int shmpi_shift_l( shmpi *X, size_t count );

/**
 * \brief          Right-shift: X >>= count
 *
 * \param X        MPI to shift
 * \param count    Amount to shift
 *
 * \return         0 if successful,
 *                 MPI_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
int shmpi_shift_r( shmpi *X, size_t count );

/**
 * \brief          Compare unsigned values
 *
 * \param X        Left-hand MPI
 * \param Y        Right-hand MPI
 *
 * \return         1 if |X| is greater than |Y|,
 *                -1 if |X| is lesser  than |Y| or
 *                 0 if |X| is equal to |Y|
 */
int shmpi_cmp_abs( const shmpi *X, const shmpi *Y );

/**
 * \brief          Compare signed values
 *
 * \param X        Left-hand MPI
 * \param Y        Right-hand MPI
 *
 * \return         1 if X is greater than Y,
 *                -1 if X is lesser  than Y or
 *                 0 if X is equal to Y
 */
int shmpi_cmp_mpi( const shmpi *X, const shmpi *Y );

/**
 * \brief          Compare signed values
 *
 * \param X        Left-hand MPI
 * \param z        The integer value to compare to
 *
 * \return         1 if X is greater than z,
 *                -1 if X is lesser  than z or
 *                 0 if X is equal to z
 */
int shmpi_cmp_int( const shmpi *X, t_sint z );

/**
 * \brief          Unsigned addition: X = |A| + |B|
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param B        Right-hand MPI
 *
 * \return         0 if successful,
 *                 MPI_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
int shmpi_add_abs( shmpi *X, const shmpi *A, const shmpi *B );

/**
 * \brief          Unsigned subtraction: X = |A| - |B|
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param B        Right-hand MPI
 *
 * \return         0 if successful,
 *                 MPI_ERR_MPI_NEGATIVE_VALUE if B is greater than A
 */
int shmpi_sub_abs( shmpi *X, const shmpi *A, const shmpi *B );

/**
 * \brief          Signed addition: X = A + B
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param B        Right-hand MPI
 *
 * \return         0 if successful,
 *                 MPI_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
int shmpi_add_mpi( shmpi *X, const shmpi *A, const shmpi *B );

/**
 * \brief          Signed subtraction: X = A - B
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param B        Right-hand MPI
 *
 * \return         0 if successful,
 *                 MPI_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
int shmpi_sub_mpi( shmpi *X, const shmpi *A, const shmpi *B );

/**
 * \brief          Signed addition: X = A + b
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param b        The integer value to add
 *
 * \return         0 if successful,
 *                 MPI_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
int shmpi_add_int( shmpi *X, const shmpi *A, t_sint b );

/**
 * \brief          Signed subtraction: X = A - b
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param b        The integer value to subtract
 *
 * \return         0 if successful,
 *                 MPI_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
int shmpi_sub_int( shmpi *X, const shmpi *A, t_sint b );

/**
 * \brief          Baseline multiplication: X = A * B
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param B        Right-hand MPI
 *
 * \return         0 if successful,
 *                 MPI_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
int shmpi_mul_mpi( shmpi *X, const shmpi *A, const shmpi *B );

/**
 * \brief          Baseline multiplication: X = A * b
 *                 Note: despite the functon signature, b is treated as a
 *                 t_uint.  Negative values of b are treated as large positive
 *                 values.
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param b        The integer value to multiply with
 *
 * \return         0 if successful,
 *                 MPI_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
int shmpi_mul_int( shmpi *X, const shmpi *A, t_sint b );

/**
 * \brief          Division by shmpi: A = Q * B + R
 *
 * \param Q        Destination MPI for the quotient
 * \param R        Destination MPI for the rest value
 * \param A        Left-hand MPI
 * \param B        Right-hand MPI
 *
 * \return         0 if successful,
 *                 MPI_ERR_MPI_MALLOC_FAILED if memory allocation failed,
 *                 MPI_ERR_MPI_DIVISION_BY_ZERO if B == 0
 *
 * \note           Either Q or R can be NULL.
 */
int shmpi_div_mpi( shmpi *Q, shmpi *R, const shmpi *A, const shmpi *B );

/**
 * \brief          Division by int: A = Q * b + R
 *
 * \param Q        Destination MPI for the quotient
 * \param R        Destination MPI for the rest value
 * \param A        Left-hand MPI
 * \param b        Integer to divide by
 *
 * \return         0 if successful,
 *                 MPI_ERR_MPI_MALLOC_FAILED if memory allocation failed,
 *                 MPI_ERR_MPI_DIVISION_BY_ZERO if b == 0
 *
 * \note           Either Q or R can be NULL.
 */
int shmpi_div_int( shmpi *Q, shmpi *R, const shmpi *A, t_sint b );

/**
 * \brief          Modulo: R = A mod B
 *
 * \param R        Destination MPI for the rest value
 * \param A        Left-hand MPI
 * \param B        Right-hand MPI
 *
 * \return         0 if successful,
 *                 MPI_ERR_MPI_MALLOC_FAILED if memory allocation failed,
 *                 MPI_ERR_MPI_DIVISION_BY_ZERO if B == 0,
 *                 MPI_ERR_MPI_NEGATIVE_VALUE if B < 0
 */
int shmpi_mod_mpi( shmpi *R, const shmpi *A, const shmpi *B );

/**
 * \brief          Modulo: r = A mod b
 *
 * \param r        Destination t_uint
 * \param A        Left-hand MPI
 * \param b        Integer to divide by
 *
 * \return         0 if successful,
 *                 MPI_ERR_MPI_MALLOC_FAILED if memory allocation failed,
 *                 MPI_ERR_MPI_DIVISION_BY_ZERO if b == 0,
 *                 MPI_ERR_MPI_NEGATIVE_VALUE if b < 0
 */
int shmpi_mod_int( t_uint *r, const shmpi *A, t_sint b );

/**
 * \brief          Sliding-window exponentiation: X = A^E mod N
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param E        Exponent MPI
 * \param N        Modular MPI
 * \param _RR      Speed-up MPI used for recalculations
 *
 * \return         0 if successful,
 *                 MPI_ERR_MPI_MALLOC_FAILED if memory allocation failed,
 *                 MPI_ERR_MPI_BAD_INPUT_DATA if N is negative or even or
 *                 if E is negative
 *
 * \note           _RR is used to avoid re-computing R*R mod N across
 *                 multiple calls, which speeds up things a bit. It can
 *                 be set to NULL if the extra performance is unneeded.
 */
int shmpi_exp_mod( shmpi *X, const shmpi *A, const shmpi *E, const shmpi *N, shmpi *_RR );

/**
 * \brief          Fill an MPI X with size bytes of random
 *
 * \param X        Destination MPI
 * \param size     Size in bytes
 * \param f_rng    RNG function
 * \param p_rng    RNG parameter
 *
 * \return         0 if successful,
 *                 MPI_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
int shmpi_fill_random( shmpi *X, size_t size,
                     int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng );

/**
 * \brief          Greatest common divisor: G = gcd(A, B)
 *
 * \param G        Destination MPI
 * \param A        Left-hand MPI
 * \param B        Right-hand MPI
 *
 * \return         0 if successful,
 *                 MPI_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
int shmpi_gcd( shmpi *G, const shmpi *A, const shmpi *B );

/**
 * \brief          Modular inverse: X = A^-1 mod N
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param N        Right-hand MPI
 *
 * \return         0 if successful,
 *                 MPI_ERR_MPI_MALLOC_FAILED if memory allocation failed,
 *                 MPI_ERR_MPI_BAD_INPUT_DATA if N is negative or nil
                   MPI_ERR_MPI_NOT_ACCEPTABLE if A has no inverse mod N
 */
int shmpi_inv_mod( shmpi *X, const shmpi *A, const shmpi *N );

/**
 * \brief          Miller-Rabin primality test
 *
 * \param X        MPI to check
 * \param f_rng    RNG function
 * \param p_rng    RNG parameter
 *
 * \return         0 if successful (probably prime),
 *                 MPI_ERR_MPI_MALLOC_FAILED if memory allocation failed,
 *                 MPI_ERR_MPI_NOT_ACCEPTABLE if X is not prime
 */
int shmpi_is_prime( shmpi *X,
                  int (*f_rng)(void *, unsigned char *, size_t),
                  void *p_rng );

/**
 * \brief          Prime number generation
 *
 * \param X        Destination MPI
 * \param nbits    Required size of X in bits
 *                 ( 3 <= nbits <= MPI_MPI_MAX_BITS )
 * \param dh_flag  If 1, then (X-1)/2 will be prime too
 * \param f_rng    RNG function
 * \param p_rng    RNG parameter
 *
 * \return         0 if successful (probably prime),
 *                 MPI_ERR_MPI_MALLOC_FAILED if memory allocation failed,
 *                 MPI_ERR_MPI_BAD_INPUT_DATA if nbits is < 3
 */
int shmpi_gen_prime( shmpi *X, size_t nbits, int dh_flag,
                   int (*f_rng)(void *, unsigned char *, size_t),
                   void *p_rng );

#define SHMEM_ALG_GENPRIME

/**
 * @returns The the number of bits.
 */
size_t shmpi_bitlen( const shmpi *X );


/**
 * @}
 */











/**
 * Cryptographic algorythms supported include a 128-bit, 224-bit, 256-bit, 384-bit, or 512-bit hash digest.

 * The following algorythms are available for use:
 * - SHALG_SHR160      A RIPEMD32 compatible algorithm.
 * - SHALG_SHR224      A proprietary 224-bit algorithm with a 28 byte digest.
 * - SHALG_SHA1        A 128-bit SHA hash with a 20 byte digest.
 * - SHALG_SHA224      A 224-bit SHA hash with a 28 byte digest.
 * - SHALG_SHA256      A 256-bit SHA hash with a 32 byte digest.
 * - SHALG_SHA384      A 384-bit SHA hash with a 48 byte digest.
 * - SHALG_SHA512      A 512-bit SHA hash with a 64 byte digest.
 * - SHALG_CRYPT256    A libcrypt compatible SHA 256-bit algorithm.
 * - SHALG_CRYPT512    A libcrypt compatible SHA 512-bit algorithm.
 *
 * The SHALG_CRYPT256 and SHALG_CRYPT512 use the standard SHA-256 and SHA-512 method of "shadow password account validation" used on linux.
 *
 * The SHALG_SHA1, SHALG_SHA224, SHALG_SHA256, SHALG_SHA384, and SHALG_SHA512 algorythms provide the various implementations of the Secure Hash Algorythm. Supplemental HMAC and HKDF encoding is provided. 
 *
 * The SHALG_ECDSA128R, SHALG_ECDSA160R, SHALG_ECDSA160K, SHALG_ECDSA224R, SHALG_ECDSA224K, SHALG_ECDSA256R, SHALG_ECDSA256K, SHALG_ECDSA384R, and SHALG_ECDSA512R algorythms provide the various implementions of the Elliptic Curve DSA encryption method. 
 *
 * The SHALG_RIPEMD160 algorythm is synonymous with the SHALG_SHR160 algorythm.
 *
 * The SHALG_SHR160 algorythm provides a private key generation via the RIPEMD160 implementation and a ECDSA256K public-private key validation method. 
 *
 * The SHALG_SHR224 algorythm is a proprietary libshare runtime library. The computation speed to calculate regular or HMAC SHR224 digests is much faster than the SHA or ECDSA algorythms. The method used combines aspects of both checksum computation and bit operations. 
 * 
 * Specifications for the Secure Hash Algorithm (SHA) algorithm can be found at "http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf" and "https://tools.ietf.org/html/rfc6234".
 *
 * Specifications on the Elliptic Curve (ECDSA) algorithm can be found at "http://csrc.nist.gov/publications/fips/fips186-3/fips_186-3.pdf" and "https://www.ietf.org/rfc/rfc6979.txt".
 * @ingroup libshare_mem
 * @defgroup libshare_memalg Cryptological and Hash Digest Algorithms
 * @{
 */

#define SHFMT_HEX 0
#define SHFMT_BASE32 1
#define SHFMT_BASE58 2
#define SHFMT_BASE64 3
#define SHFMT_SHR56 4
#define MAX_SHFMT 5


/** A 16-byte hash */
#define SHALG_128BIT (1 << 0)
/** A 20-byte hash */
#define SHALG_160BIT (1 << 1)
/** A 28-byte hash */
#define SHALG_224BIT (1 << 2)
/** A 32-byte hash */
#define SHALG_256BIT (1 << 3)
/** A 48-byte hash */
#define SHALG_384BIT (1 << 4)
/** A 64-byte hash */
#define SHALG_512BIT (1 << 5)
/** Share Library Algorythm */
#define SHALG_SHR (1 << 8)
/** Secure Hash Algorythm */
#define SHALG_SHA (1 << 9)
/** Pubkey Encryption Algorythm (circa 1977) */
#define SHALG_RSA (1 << 10)
/** Elliptic Curve Algorythm */
#define SHALG_ECDSA (1 << 11)
/* A SHA derivative used primarily used for account validation. */
#define SHALG_CRYPT (1 << 12)
/** Indicates that the algorythm is 'verifiably random'. */
#define SHALG_VR (1 << 15)


/** The libshare 160-bit hash algorithm. */
#define SHALG_SHR160 (SHALG_SHR | SHALG_160BIT)

/** The libshare 224-bit hash algorithm. */
#define SHALG_SHR224 (SHALG_SHR | SHALG_224BIT)

/** The libshare 224-bit "crypt" hash algorithm designed towards password authentication purposes. */
#define SHALG_SHCR224 (SHALG_CRYPT | SHALG_SHR | SHALG_224BIT)

#define SHALG_SHA1 (SHALG_SHA | SHALG_128BIT)
#define SHALG_SHA224 (SHALG_SHA | SHALG_224BIT)
#define SHALG_SHA256 (SHALG_SHA | SHALG_256BIT)
#define SHALG_SHA384 (SHALG_SHA | SHALG_384BIT)
#define SHALG_SHA512 (SHALG_SHA | SHALG_512BIT)
#define SHALG_ECDSA128R (SHALG_ECDSA | SHALG_128BIT | SHALG_VR)
#define SHALG_ECDSA160R (SHALG_ECDSA | SHALG_160BIT | SHALG_VR)
#define SHALG_ECDSA160K (SHALG_ECDSA | SHALG_160BIT)
#define SHALG_ECDSA224R (SHALG_ECDSA | SHALG_224BIT | SHALG_VR)
#define SHALG_ECDSA224K (SHALG_ECDSA | SHALG_224BIT)
#define SHALG_ECDSA256R (SHALG_ECDSA | SHALG_256BIT | SHALG_VR)
#define SHALG_ECDSA256K (SHALG_ECDSA | SHALG_256BIT)
#define SHALG_ECDSA384R (SHALG_ECDSA | SHALG_384BIT | SHALG_VR)
#define SHALG_ECDSA512R (SHALG_ECDSA | SHALG_512BIT | SHALG_VR)
#define SHALG_RSA128 (SHALG_RSA | SHALG_128BIT)

/* The GNU-Crypt 256-bit hash digest. */
#define SHALG_CRYPT256 (SHALG_CRYPT | SHALG_256BIT)

/* The GNU-Crypt 512-bit hash digest. */
#define SHALG_CRYPT512 (SHALG_CRYPT | SHALG_512BIT)

/** An indicator to use the default available algorythm. */
#define SHALG_DEFAULT 0

/** A generic 224-bit key generated by the shkey() function set. */
#define SHALG_SHKEY 0

/** A convience macro for referencing the RIPEMD160 algorythm. */
#define SHALG_RIPEMD160 SHALG_SHR160

/** @returns TRUE if the alg matches the given flags */
#define SHALG(_alg, _flag) \
  ((_alg) == (_flag))




#define MAX_ALG_SIZE ((MAX_ALG_WORD_SIZE - 1) * sizeof(uint32_t))


#define shalg_size(_a) \
  ((_a)[MAX_ALG_WORD_SIZE - 1])



#define MAX_ALG_WORD_SIZE 78

/** A key or signature. */
typedef uint32_t shalg_t[MAX_ALG_WORD_SIZE];




char *shhex_str(unsigned char *data, size_t data_len);

void shhex_bin(char *hex_str, unsigned char *data, size_t data_max);



/** Print the algorythm parameters. */
const char *shalg_str(int alg);

int shalg_fmt(char *label);

char *shalg_fmt_str(int fmt);

/** Print a binary segment in the format specified. */
char *shalg_encode(int fmt, unsigned char *data, size_t data_len);

int shalg_decode(int fmt, char *in_data, unsigned char *data, size_t *data_len_p);

/** Generate a random 512-bit private signature. */
int shalg_priv_rand(int alg, shalg_t ret_key);

/** Generate a private signature from a 'secret' binary segment. */
int shalg_priv(int alg, shalg_t ret_key, unsigned char *data, size_t data_len);

/** Print a key or signature in the format specified. */
char *shalg_print(int fmt, shalg_t key);

int shalg_gen(int fmt, char *in_data, shalg_t ret_key);

/** Generate a public key from a private key. */
int shalg_pub(int alg, shalg_t priv_key, shalg_t ret_key);

int shalg_sign(int alg, shalg_t priv_key, shalg_t ret_sig, unsigned char *data, size_t data_len);

int shalg_ver(int alg, shalg_t pub_key, shalg_t sig_key, unsigned char *data, size_t data_len);

int shalg_mode_str(char *mode_str);

int shalg_cmp(shalg_t alg_a, shalg_t alg_b);



/* alg - sha */

enum {
    SHA1_Message_Block_Size = 64, SHA224_Message_Block_Size = 64,
    SHA256_Message_Block_Size = 64, SHA384_Message_Block_Size = 128,
    SHA512_Message_Block_Size = 128,
    USHA_Max_Message_Block_Size = SHA512_Message_Block_Size,
    SHA1HashSize = 20, SHA224HashSize = 28, SHA256HashSize = 32,
    SHA384HashSize = 48, SHA512HashSize = 64,
    USHAMaxHashSize = SHA512HashSize,
    SHA1HashSizeBits = 160, SHA224HashSizeBits = 224,
    SHA256HashSizeBits = 256, SHA384HashSizeBits = 384,
    SHA512HashSizeBits = 512, USHAMaxHashSizeBits = SHA512HashSizeBits
};
typedef struct sh_sha1_t {
  uint32_t Intermediate_Hash[SHA1HashSize/4]; /* Message Digest */
  uint32_t Length_High;               /* Message length in bits */
  uint32_t Length_Low;                /* Message length in bits */
  int_least16_t Message_Block_Index;  /* Message_Block array index */
  uint8_t Message_Block[SHA1_Message_Block_Size]; /* 512-bit message blocks */
  int Computed;                   /* Is the hash computed? */
  int Corrupted;                  /* Cumulative corruption code */
} sh_sha1_t;
typedef struct sh_sha256_t {
  uint32_t Intermediate_Hash[SHA256HashSize/4]; /* Message Digest */
  uint32_t Length_High;               /* Message length in bits */
  uint32_t Length_Low;                /* Message length in bits */
  int_least16_t Message_Block_Index;  /* Message_Block array index */
  uint8_t Message_Block[SHA256_Message_Block_Size]; /* 512-bit message blocks */
  int Computed;                   /* Is the hash computed? */
  int Corrupted;                  /* Cumulative corruption code */
} sh_sha256_t;
typedef struct sh_sha512_t {
  uint64_t Intermediate_Hash[SHA512HashSize/8]; /* Message Digest */
  uint64_t Length_High, Length_Low;   /* Message length in bits */
  int_least16_t Message_Block_Index;  /* Message_Block array index */
  uint8_t Message_Block[SHA512_Message_Block_Size]; /* 1024-bit message blocks */
  int Computed;                   /* Is the hash computed?*/
  int Corrupted;                  /* Cumulative corruption code */
} sh_sha512_t;

/** This structure holds context information for the SHA hashing operations. */
typedef struct sh_sha_t
{
  int alg;
  union {
    sh_sha1_t sha1;
    sh_sha256_t sha256;
    sh_sha512_t sha512;
  } ctx;
} sh_sha_t;

/** Context information for the HMAC keyed-hashing operation.  */
typedef struct sh_hmac_t 
{
  /** The SHA algorythm. */
  int alg;

  int hashSize;               /* hash size of SHA being used */
  int blockSize;              /* block size of SHA being used */

  /** SHA context */
  sh_sha_t shaContext;  

  /** outer padding - key XORd with opad */
  unsigned char k_opad[USHA_Max_Message_Block_Size];

  int Computed;               /* Is the MAC computed? */
  int Corrupted;              /* Cumulative corruption code */
} sh_hmac_t;


/**
 * Context information for the HKDF extract-and-expand Key Derivation Functions.
 */
typedef struct sh_hkdf_t {

  int alg;

  sh_hmac_t hmacContext;

  /** hash size of SHA being used */
  int hashSize; 

  /** pseudo-random key - output of hkdfInput */
  unsigned char prk[USHAMaxHashSize];

  int Computed;               /* Is the key material computed? */

  int Corrupted;              /* Cumulative corruption code */
} sh_hkdf_t;

typedef struct shesig_t
{
  uint64_t magic;

  shalg_t sig;

  shalg_t data_sig;

  shalg_t pub;

  shkey_t id; /* (shr224) ser :: expire :: uid :: pub */

  /** The "name key" for auxiliary context information. */
  shkey_t ctx;

  uint32_t alg;

  uint32_t pk_alg;

  /** Certification attributes (SHCERT_XXX) */
  uint32_t flag; 

  uint32_t ver;

  shtime_t stamp;

  shtime_t expire;

  uint64_t size;

  /** libshare user id number */
  uint64_t uid;

  /** serial number (128-bit number) */
  uint8_t ser[16];

  /** The name of the entity or a pseudonym. */
  char ent[MAX_SHARE_NAME_LENGTH];

  /** The namer of the issuer entity. */
  char iss[MAX_SHARE_NAME_LENGTH];

} shesig_t;




/** Digest a single message into hexadecimal format. */
int shsha_hex(int alg, unsigned char *ret_digest, unsigned char *data, size_t data_len);

/** Digest a single message into binary format. */
int shsha(int alg, unsigned char *ret_bin, unsigned char *data, size_t data_len);

/** The byte size of the resulting SHA digest hash. */
size_t shsha_size(int alg);


int shsha_init(sh_sha_t *ctx, int alg);
int shsha_write(sh_sha_t *ctx, unsigned char *data, size_t data_len);
int shsha_result(sh_sha_t *ctx, unsigned char *ret_bin);


/**
 * This function will compute an HMAC message digest.
 *
 * @param alg One of SHALG_SHA1, SHALG_SHA224, SHALG_SHA256, SHALG_SHA384, or SHALG_SHA512.
 * @param message_array An array of octets representing the message.
 * @param length The length of the message in message_array.
 * @param key The secret shared key.
 * @param key_len The length of the secret shared key.
 * @param digest Where the digest is to be returned.
 * @returns A libshare error code.
 * @note The length of the digest is determined by the value of whichSha.
 */
int shhmac(int alg, unsigned char *key, size_t key_len, const unsigned char *message_array, int length, unsigned char *digest);

/**
 * This function will initialize the hmacContext in preparation for computing a new HMAC message digest.
 *
 * @param context The context to reset.
 * @param alg One of SHALG_SHA1, SHALG_SHA224, SHALG_SHA256, SHALG_SHA384, or SHALG_SHA512.
 * @param key The secret shared key.
 * @param key_len The length of the secret shared key.
 * @returns A libshare error code.
 */
int shhmac_init(sh_hmac_t *context, int alg, unsigned char *key, int key_len);

/**
 * Accepts an array of octets as the next portion of the message. 
 *
 * @param context The HMAC context to update.
 * @param text An array of octets representing the next portion of the message.
 * @param text_len The length of the message in text.
 * @returns A libshare error code.
 * @note This function may be called multiple times.
 */
int shhmac_write(sh_hmac_t *context, const unsigned char *text, int text_len);

/**
 * This function will return the N-byte message digest into the Message_Digest array provided by the caller.
 *
 * @param context The context to use to calculate the HMAC hash.
 * @param digest Where the digest is returned.
 * @returns A libshare error code. 
 * @note The length of the hash is determined by the value of alg that was passed to hmacReset().
 */
int shhmac_result(sh_hmac_t *context, uint8_t *digest);

/**
 * The HKDF algorithm (HMAC-based Extract-and-Expand Key Derivation Function, RFC 5869), expressed in terms of the various SHA algorithms.
 *
 * @param alg One of SHA1, SHA224, SHA256, SHA384, SHA512
 * @param salt The optional salt value (a non-secret random value); if not provided (salt == NULL), it is set internally to a string of HashLen(whichSha) zeros.
 * @param salt_len The length of the salt value.  (Ignored if salt == NULL.)
 * @param ikm Input keying material.
 * @param ikm_len The length of the input keying material.
 * @param info The optional context and application specific information.  If info == NULL or a zero-length string, it is ignored.
 * @param info_len The length of the optional context and application specific information.  (Ignored if info == NULL.)
 * @param okm Where the HKDF is to be stored.
 * @param okm_len The length of the buffer to hold okm.  okm_len must be <= 255 * shsha_size(alg) * 2
 * @returns A libshare error code.
 */
int shhkdf(int alg, unsigned char *salt, int salt_len, unsigned char *ikm, int ikm_len, unsigned char *info, int info_len, uint8_t *okm, int okm_len);

/**
 * This function will perform HKDF extraction.
 *
 * @param alg One of SHALG_SHA1, SHALG_SHA224, SHALG_SHA256, SHALG_SHA384, SHALG_SHA512
 * @param salt The optional salt value (a non-secret random value); if not provided (salt == NULL), it is set internally to a string of HashLen(whichSha) zeros.
 * @param salt_len The length of the salt value.  (Ignored if salt == NULL.)
 * @param ikm[ ] Input keying material.
 * @param ikm_len The length of the input keying material.
 * @param prk Array where the HKDF extraction is to be stored.  Must be larger than shsha_size(alg)
 * @returns A libshare error code.
 */
int shhkdf_extract(int alg, unsigned char *salt, int salt_len, unsigned char *ikm, int ikm_len, uint8_t *prk);

/**
 * This function will perform HKDF expansion.
 *
 * @param whichSha One of SHA1, SHA224, SHA256, SHA384, SHA512
 * @param prk The pseudo-random key to be expanded; either obtained directly from a cryptographically strong, uniformly distributed pseudo-random number generator, or as the output from hkdfExtract().
 * @param prk_len The length of the pseudo-random key in prk; should at least be equal to shsha_size(alg).
 * @param info The optional context and application specific information. If info == NULL or a zero-length string, it is ignored.
 * @param info_len The length of the optional context and application specific information.  (Ignored if info == NULL.)
 * @param okm Where the HKDF is to be stored.
 * @param okm_len The length of the buffer to hold okm. The okm_len must be <= 255 * shsha_size(alg) * 2.
 * @returns A libshare error code.
 */
int shhkdf_expand(int alg, uint8_t *prk, int prk_len, unsigned char *info, int info_len, uint8_t *okm, int okm_len);

/**
 * This function will initialize the hkdfContext in preparation for key derivation using the modular HKDF interface for arbitrary length inputs.
 *
 * @param context The context to reset.
 * @param alg One of SHALG_SHA1, SHALG_SHA224, SHALG_SHA256, SHALG_SHA384, or SHALG_SHA512.
 * @param salt The optional salt value (a non-secret random value); if not provided (salt == NULL), it is set internally to a string of HashLen(whichSha) zeros.
 * @param salt_len The length of the salt value.  (Ignored if salt == NULL.)
 * @returns A libshare error code.
 */
int shhkdf_init(sh_hkdf_t *context, int alg, unsigned char *salt, int salt_len);

/**
 * This function accepts an array of octets as the next portion of the input keying material.
 *
 * @param context The HKDF context to update.
 * @param ikm An array of octets representing the next portion of the input keying material.
 * @param ikm_len The length of ikm.
 * @returns A libshare error code.
 * @note This function may be called multiple times.
 */
int shhkdf_write(sh_hkdf_t *context, unsigned char *ikm, int ikm_len);

/**
 * This function will finish the HKDF extraction and perform the final HKDF expansion.
 *
 * @param context The HKDF context to use to calculate the HKDF hash.
 * @param prk NULL or a location to store the HKDF extraction. The buffer  must be larger than shsha_size(whichSha).
 * @param info NULL or context and application specific information.
 * @param info_len The length of the optional context and application specific
 * @param okm Where the HKDF is to be stored.
 * @param okm_len The length of the buffer to hold okm. The okm_len must be <= 255 * shsha_size(whichSha) * 2
 * @returns A libshare error code.
 */
int shhkdf_result(sh_hkdf_t *context, uint8_t *prk, unsigned char *info, int info_len, uint8_t *okm, int okm_len);






/**
 * This function will initialize the sh_sha1_t in preparation for computing a new SHA1 message digest.
 *
 * @param context The context to reset [in/out]
 * @returns A share error code.
 */
int sh_sha1_init(sh_sha_t *sha);

/**
 * This function accepts an array of octets as the next portion of the message.
 *
 * @param context The SHA context to update. [in/out]
 * @param message_array An array of octets representing the next portion of the message.
 * @param length The length of the message in message_array. [in]
 * @returns A libshare error code. 
 */
int sh_sha1_write(sh_sha_t *sha, const uint8_t *message_array, unsigned length);

/**
 * This function will return the 160-bit message digest into the Message_Digest array provided by the caller.
 *
 * @param context The context to use to calculate the SHA-1 hash.
 * @param Message_Digest Where the digest is returned.
 * @returns A libshare error code.
 * @note The first octet of hash is stored in the element with index 0, the last octet of hash in the element with index 19.
 */
int sh_sha1_result(sh_sha_t *sha, uint8_t *Message_Digest);

void sh_sha224(const unsigned char *message, unsigned int len, unsigned char *digest);

/**
 * This function will initialize the sh_sha256_t in preparation for computing a new SHA256 message digest.
 *
 * @param context The context to reset.
 * @returns A libshare error code.
 */
int sh_sha256_init(sh_sha_t *sha);

/**
 * This function accepts an array of octets as the next portion of the message.
 *
 * @param context The SHA context to update.
 * @param message_array An array of octets representing the next portion of the message.
 * @param length The length of the message in message_array.
 * @returns A libshare error code.
 */
int sh_sha256_write(sh_sha_t *sha, const uint8_t *message_array, unsigned int length);

/**
 * This function will return the 256-bit message digest into the Message_Digest array provided by the caller.
 *
 * @param context The context to use to calculate the SHA hash.
 * @param Message_Digest Where the digest is returned.
 * @returns A libshare error code.
 * @note The first octet of hash is stored in the element with index 0. The last octet of hash in the element with index 31.
 */
int sh_sha256_result(sh_sha_t *sha, uint8_t *Message_Digest);

void sh_sha256(const unsigned char *message, unsigned int len, unsigned char *digest);

/**
 * This function will initialize the sh_sha512_t in preparation for computing a new SHA512 message digest.
 *
 * @param  context The context to reset.
 * @returns A libshare error code.
 */
int sh_sha512_init(sh_sha_t *sha);

/**
 * This function accepts an array of octets as the next portion of the message.
 *
 * @param context The SHA context to update.
 * @param message_array An array of octets representing the next portion of the message.
 * @param length The length of the message in message_array.
 * @returns A libshare error code.
 */
int sh_sha512_write(sh_sha_t *sha, const uint8_t *message_array, unsigned int length);

/**
 * This function will return the 512-bit message digest into the Message_Digest array provided by the caller.
 *
 * @param context The context to use to calculate the SHA hash.
 * @param Message_Digest Where the digest is returned.
 * @returns A libshare error code.
 * @note The first octet of hash is stored in the element with index 0, *    the last octet of hash in the element with index 63.
 */
int sh_sha512_result(sh_sha_t *sha, uint8_t *Message_Digest);

void sh_sha512(const unsigned char *message, unsigned int len, unsigned char *digest);



char *shdigest(void *data, int32_t len);




/** Generate a RIPEMD160 20-byte hash from a binary segment. */
void sh_ripemd160(unsigned char *data, size_t data_len, sh160_t digest);







/**
 * @param secret_str A 16 character "base 32" string.
 * @returns A pin that will invalidate after aproximately one minute.
 */
uint32_t shsha_2fa(char *secret_str);

/**
 * @param secret_str A 16 character "base 32" string.
 * @returns 0 on success and SHERR_ACCESS when pin is invalid.
 */
int shsha_2fa_verify(char *secret_str, uint32_t pin);

/**
 * Generate a random secret key usable for 2fa purposes.
 * @returns A 16-character string in base-32 format. 
 */
char *shsha_2fa_secret(void);

uint32_t shsha_2fa_bin(int alg, unsigned char *secret, size_t secret_len, int freq);

int shsha_2fa_bin_verify(int alg, unsigned char *secret, size_t secret_len, int freq, uint32_t pin);

void shsha_2fa_secret_bin(unsigned char *secret, size_t secret_len);



/* alg - shacrypt */

char *shcrypt(const char *passwd, const char *salt);

char *shcrypt_sha256(const char *key, const char *salt);

char *shcrypt_sha512(const char *key, const char *salt);

void shcrypt_b64_encode(char *ret_str, unsigned char *data, size_t data_len);
void shcrypt_b64_decode(char *str, unsigned char *data, size_t *data_len_p);



/* alg - ecdsa */

typedef struct shec_t
{
  int alg;
  char priv[648];
  char pub[648];
  char sig[648];
} shec_t;

shkey_t *shecdsa_key(char *hex_str);

shkey_t *shecdsa_key_priv(char *hex_seed);

shkey_t *shecdsa_key_pub(shkey_t *priv_key);

const char *shecdsa_pub(const char *hex_str);

int shecdsa_sign(shkey_t *priv_key, char *sig_r, char *sig_s, unsigned char *data, size_t data_len);

int shecdsa_verify(shkey_t *pub_key, char *str_r, char *str_s, unsigned char *data, size_t data_len);


/**
 * Generate a private key from the given seed context. 
 * @param seed_hex A seed for the private key in hexadecimal format.
 * @returns A private key (32 bytes) in hexadecimal string.
 */
char *shecdsa_hd_seed(char *seed_hex, char *chain);

/**
 * @param pubkey The parent pubkey (65 bytes) in hexadecimal format.
 * @param chain The parent chain (32 bytes) in hexadecimal format. This value is over-written with the new chain sequence.
 * @param idx The sequence number in the derived set.
 * @returns A hexadecimal public key (65 bytes) in hexadecimal format.
 */
char *shecdsa_hd_pubkey(char *pubkey, char *chain, uint32_t idx);

/**
 * @param pubkey The parent pubkey (65 bytes) in hexadecimal format.
 * @param chain The parent chain (32 bytes) in hexadecimal format. This value is over-written with the new chain sequence.
 * @param seed The parent's secret key (32 bytes) in hexadecimal format.
 * @param idx The sequence number in the derived set.
 * @returns A hexadecimal private key (32 bytes) in hexadecimal format.
 */
char *shecdsa_hd_privkey(char *secret, char *chain, uint32_t idx);

char *shecdsa_hd_par_pub(char *p_secret, char *p_chain, uint32_t idx);

char *shecdsa_hd_recover_pub(char *secret);

int shecdsa_hd_sign(char *privkey_hex, char *sig_r, char *sig_s, char *hash_hex);

int shecdsa_hd_verify(char *pubkey_hex, char *str_r, char *str_s, char *hash_hex);


shec_t *shec_init(int alg);
void shec_free(shec_t **ec_p);
char *shec_priv(shec_t *ec);

char *shec_priv_gen(shec_t *ec, unsigned char *data, size_t data_len);

void shec_priv_set(shec_t *ec, char *hex_priv);

char *shec_priv_rand(shec_t *ec);

char *shec_pub(shec_t *ec);

char *shec_pub_gen(shec_t *ec);

int shec_sign(shec_t *ec, unsigned char *data, size_t data_len);

int shec_signstr(shec_t *ec, char *data);
int shec_signnull(shec_t *ec);
int shec_ver(shec_t *ec, unsigned char *data, size_t data_len);
int shec_verstr(shec_t *ec, char *data);
int shec_vernull(shec_t *ec);


shkey_t *shec_priv_key(shec_t *ec);

int shec_priv_key_set(shec_t *ec, shkey_t *key);

shkey_t *shec_pub_key(shec_t *ec);

int shec_pub_key_set(shec_t *ec, shkey_t *key);

int shec_pub_set(shec_t *ec, char *hex_pub);

int shec_sig_set(shec_t *ec, char *hex_sig);



/* alg - shcr224 */

#define SHCR224_SIZE 96

#define SHCR224_SALT_SIZE 28

#define SHCR224_MIN_ROUNDS 1000
#define SHCR224_DEFAULT_ROUNDS SHCR224_MIN_ROUNDS

typedef unsigned char shcr224_t[SHCR224_SIZE];

int shcr224_verify(char *salt, char *sig, char *data);

int shcr224_bin_verify(unsigned char salt_key[SHCR224_SALT_SIZE], shcr224_t sig, unsigned int rounds, unsigned char *data, size_t data_len);

int shcr224(char *salt, char *data, char *ret_str);

/** Generate a signature, from the salt provided, that can be used in order to authenticate a password. */
int shcr224_bin(unsigned char salt_key[SHCR224_SALT_SIZE], shcr224_t ret_key, unsigned int rounds, unsigned char *data, size_t data_len);

char *shcr224_salt(unsigned int rounds);

/** Generate a random salt. */
int shcr224_salt_bin(unsigned char ret_key[SHCR224_SALT_SIZE]);

char *shcr224_salt_gen(unsigned int rounds, unsigned char *data, size_t data_len);

/* Generate a suitable salt from the variable data provided. */
int shcr224_salt_bin_gen(unsigned char ret_key[SHCR224_SALT_SIZE], unsigned char *data, size_t data_len);



#ifndef DOXYGEN_SHOULD_SKIP_THIS 
/* alg - rsa */

#define SHRSA_PUBLIC      0
#define SHRSA_PRIVATE     1

/** pkcs v15 padding */
#define SHRSA_PKCS_V15    0
/** pkcs v21 padding */
#define SHRSA_PKCS_V21    1

#define SHRSA_SIGN        1
#define SHRSA_CRYPT       2

#define SHRSA_SALT_LEN_ANY    -1


#define SHRSA_ERR_BAD_INPUT_DATA                    -0x4080  /**< Bad input parameters to function. */
#define SHRSA_ERR_INVALID_PADDING                   -0x4100  /**< Input data contains invalid padding and is rejected. */
#define SHRSA_ERR_KEY_GEN_FAILED                    -0x4180  /**< Something failed during generation of a key. */
#define SHRSA_ERR_KEY_CHECK_FAILED                  -0x4200  /**< Key failed to pass the library's validity check. */
#define SHRSA_ERR_PUBLIC_FAILED                     -0x4280  /**< The public key operation failed. */
#define SHRSA_ERR_PRIVATE_FAILED                    -0x4300  /**< The private key operation failed. */
#define SHRSA_ERR_VERIFY_FAILED                     -0x4380  /**< The PKCS#1 verification failed. */
#define SHRSA_ERR_OUTPUT_TOO_LARGE                  -0x4400  /**< The output buffer for decryption is not large enough. */
#define SHRSA_ERR_RNG_FAILED                        -0x4480  /**< The random generator failed to generate non-zeros. */

typedef enum {
  SHRSA_MD_NONE=0,
  SHRSA_MD_MD2,
  SHRSA_MD_MD4,
  SHRSA_MD_MD5,
  SHRSA_MD_SHA1,
  SHRSA_MD_SHA224,
  SHRSA_MD_SHA256,
  SHRSA_MD_SHA384,
  SHRSA_MD_SHA512,
  SHRSA_MD_RIPEMD160,
} shrsa_md_type_t;

/**
 * The RSA context.
 */
typedef struct shrsa_t 
{
  int ver;                    /*!<  always 0          */
  size_t len;                 /*!<  size(N) in chars  */

  shmpi N;                      /*!<  public modulus    */
  shmpi E;                      /*!<  public exponent   */

  shmpi D;                      /*!<  private exponent  */
  shmpi P;                      /*!<  1st prime factor  */
  shmpi Q;                      /*!<  2nd prime factor  */
  shmpi DP;                     /*!<  D % (P - 1)       */
  shmpi DQ;                     /*!<  D % (Q - 1)       */
  shmpi QP;                     /*!<  1 / (Q % P)       */

  shmpi RN;                     /*!<  cached R^2 mod N  */
  shmpi RP;                     /*!<  cached R^2 mod P  */
  shmpi RQ;                     /*!<  cached R^2 mod Q  */

  shmpi Vi;                     /*!<  cached blinding value     */
  shmpi Vf;                     /*!<  cached un-blinding value  */

  int padding;                /*!<  MBEDTLS_RSA_PKCS_V15 for 1.5 padding and MBEDTLS_RSA_PKCS_v21 for OAEP/PSS         */
  int hash_id;                /*!<  Hash identifier of shrsa_md_type_t as specified in the mbedtls_md.h header file for the EME-OAEP and EMSA-PSS encoding                          */
} shrsa_t;



/**
 * \brief          Initialize an RSA context
 *
 *                 Note: Set padding to MBEDTLS_RSA_PKCS_V21 for the RSAES-OAEP
 *                 encryption scheme and the RSASSA-PSS signature scheme.
 *
 * \param ctx      RSA context to be initialized
 * \param padding  MBEDTLS_RSA_PKCS_V15 or MBEDTLS_RSA_PKCS_V21
 * \param hash_id  MBEDTLS_RSA_PKCS_V21 hash identifier
 *
 * \note           The hash_id parameter is actually ignored
 *                 when using MBEDTLS_RSA_PKCS_V15 padding.
 *
 * \note           Choice of padding mode is strictly enforced for private key
 *                 operations, since there might be security concerns in
 *                 mixing padding modes. For public key operations it's merely
 *                 a default value, which can be overriden by calling specific
 *                 rsa_rsaes_xxx or rsa_rsassa_xxx functions.
 *
 * \note           The chosen hash is always used for OEAP encryption.
 *                 For PSS signatures, it's always used for making signatures,
 *                 but can be overriden (and always is, if set to
 *                 MBEDTLS_MD_NONE) for verifying them.
 */
void shrsa_init( shrsa_t *ctx,
               int padding,
               int hash_id);

/**
 * \brief          Set padding for an already initialized RSA context
 *                 See \c shrsa_init() for details.
 *
 * \param ctx      RSA context to be set
 * \param padding  MBEDTLS_RSA_PKCS_V15 or MBEDTLS_RSA_PKCS_V21
 * \param hash_id  MBEDTLS_RSA_PKCS_V21 hash identifier
 */
void shrsa_set_padding( shrsa_t *ctx, int padding, int hash_id);

/**
 * \brief          Generate an RSA keypair
 *
 * \param ctx      RSA context that will hold the key
 * \param f_rng    RNG function
 * \param p_rng    RNG parameter
 * \param nbits    size of the public key in bits
 * \param exponent public exponent (e.g., 65537)
 *
 * \note           shrsa_init() must be called beforehand to setup
 *                 the RSA context.
 *
 * \return         0 if successful, or an MBEDTLS_ERR_RSA_XXX error code
 */
int shrsa_gen_key( shrsa_t *ctx,
                 int (*f_rng)(void *, unsigned char *, size_t),
                 void *p_rng,
                 unsigned int nbits, int exponent );

/**
 * \brief          Check a public RSA key
 *
 * \param ctx      RSA context to be checked
 *
 * \return         0 if successful, or an MBEDTLS_ERR_RSA_XXX error code
 */
int shrsa_check_pubkey( const shrsa_t *ctx );

/**
 * \brief          Check a private RSA key
 *
 * \param ctx      RSA context to be checked
 *
 * \return         0 if successful, or an MBEDTLS_ERR_RSA_XXX error code
 */
int shrsa_check_privkey( const shrsa_t *ctx );

/**
 * \brief          Check a public-private RSA key pair.
 *                 Check each of the contexts, and make sure they match.
 *
 * \param pub      RSA context holding the public key
 * \param prv      RSA context holding the private key
 *
 * \return         0 if successful, or an MBEDTLS_ERR_RSA_XXX error code
 */
int shrsa_check_pub_priv( const shrsa_t *pub, const shrsa_t *prv );

/**
 * \brief          Do an RSA public key operation
 *
 * \param ctx      RSA context
 * \param input    input buffer
 * \param output   output buffer
 *
 * \return         0 if successful, or an MBEDTLS_ERR_RSA_XXX error code
 *
 * \note           This function does NOT take care of message
 *                 padding. Also, be sure to set input[0] = 0 or ensure that
 *                 input is smaller than N.
 *
 * \note           The input and output buffers must be large
 *                 enough (eg. 128 bytes if RSA-1024 is used).
 */
int shrsa_public( shrsa_t *ctx,
                const unsigned char *input,
                unsigned char *output );

/**
 * \brief          Do an RSA private key operation
 *
 * \param ctx      RSA context
 * \param f_rng    RNG function (Needed for blinding)
 * \param p_rng    RNG parameter
 * \param input    input buffer
 * \param output   output buffer
 *
 * \return         0 if successful, or an MBEDTLS_ERR_RSA_XXX error code
 *
 * \note           The input and output buffers must be large
 *                 enough (eg. 128 bytes if RSA-1024 is used).
 */
int shrsa_private( shrsa_t *ctx,
                 int (*f_rng)(void *, unsigned char *, size_t),
                 void *p_rng,
                 const unsigned char *input,
                 unsigned char *output );

/**
 * \brief          Generic wrapper to perform a PKCS#1 encryption using the
 *                 mode from the context. Add the message padding, then do an
 *                 RSA operation.
 *
 * \param ctx      RSA context
 * \param f_rng    RNG function (Needed for padding and PKCS#1 v2.1 encoding
 *                               and MBEDTLS_RSA_PRIVATE)
 * \param p_rng    RNG parameter
 * \param mode     MBEDTLS_RSA_PUBLIC or MBEDTLS_RSA_PRIVATE
 * \param ilen     contains the plaintext length
 * \param input    buffer holding the data to be encrypted
 * \param output   buffer that will hold the ciphertext
 *
 * \return         0 if successful, or an MBEDTLS_ERR_RSA_XXX error code
 *
 * \note           The output buffer must be as large as the size
 *                 of ctx->N (eg. 128 bytes if RSA-1024 is used).
 */
int shrsa_pkcs1_encrypt( shrsa_t *ctx,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng,
                       int mode, size_t ilen,
                       const unsigned char *input,
                       unsigned char *output );

/**
 * \brief          Perform a PKCS#1 v1.5 encryption (RSAES-PKCS1-v1_5-ENCRYPT)
 *
 * \param ctx      RSA context
 * \param f_rng    RNG function (Needed for padding and MBEDTLS_RSA_PRIVATE)
 * \param p_rng    RNG parameter
 * \param mode     MBEDTLS_RSA_PUBLIC or MBEDTLS_RSA_PRIVATE
 * \param ilen     contains the plaintext length
 * \param input    buffer holding the data to be encrypted
 * \param output   buffer that will hold the ciphertext
 *
 * \return         0 if successful, or an MBEDTLS_ERR_RSA_XXX error code
 *
 * \note           The output buffer must be as large as the size
 *                 of ctx->N (eg. 128 bytes if RSA-1024 is used).
 */
int shrsa_rsaes_pkcs1_v15_encrypt( shrsa_t *ctx,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng,
                                 int mode, size_t ilen,
                                 const unsigned char *input,
                                 unsigned char *output );

/**
 * \brief          Perform a PKCS#1 v2.1 OAEP encryption (RSAES-OAEP-ENCRYPT)
 *
 * \param ctx      RSA context
 * \param f_rng    RNG function (Needed for padding and PKCS#1 v2.1 encoding
 *                               and MBEDTLS_RSA_PRIVATE)
 * \param p_rng    RNG parameter
 * \param mode     MBEDTLS_RSA_PUBLIC or MBEDTLS_RSA_PRIVATE
 * \param label    buffer holding the custom label to use
 * \param label_len contains the label length
 * \param ilen     contains the plaintext length
 * \param input    buffer holding the data to be encrypted
 * \param output   buffer that will hold the ciphertext
 *
 * \return         0 if successful, or an MBEDTLS_ERR_RSA_XXX error code
 *
 * \note           The output buffer must be as large as the size
 *                 of ctx->N (eg. 128 bytes if RSA-1024 is used).
 */
int shrsa_rsaes_oaep_encrypt( shrsa_t *ctx,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng,
                            int mode,
                            const unsigned char *label, size_t label_len,
                            size_t ilen,
                            const unsigned char *input,
                            unsigned char *output );

/**
 * \brief          Generic wrapper to perform a PKCS#1 decryption using the
 *                 mode from the context. Do an RSA operation, then remove
 *                 the message padding
 *
 * \param ctx      RSA context
 * \param f_rng    RNG function (Only needed for MBEDTLS_RSA_PRIVATE)
 * \param p_rng    RNG parameter
 * \param mode     MBEDTLS_RSA_PUBLIC or MBEDTLS_RSA_PRIVATE
 * \param olen     will contain the plaintext length
 * \param input    buffer holding the encrypted data
 * \param output   buffer that will hold the plaintext
 * \param output_max_len    maximum length of the output buffer
 *
 * \return         0 if successful, or an MBEDTLS_ERR_RSA_XXX error code
 *
 * \note           The output buffer must be as large as the size
 *                 of ctx->N (eg. 128 bytes if RSA-1024 is used) otherwise
 *                 an error is thrown.
 */
int shrsa_pkcs1_decrypt( shrsa_t *ctx,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng,
                       int mode, size_t *olen,
                       const unsigned char *input,
                       unsigned char *output,
                       size_t output_max_len );

/**
 * \brief          Perform a PKCS#1 v1.5 decryption (RSAES-PKCS1-v1_5-DECRYPT)
 *
 * \param ctx      RSA context
 * \param f_rng    RNG function (Only needed for MBEDTLS_RSA_PRIVATE)
 * \param p_rng    RNG parameter
 * \param mode     MBEDTLS_RSA_PUBLIC or MBEDTLS_RSA_PRIVATE
 * \param olen     will contain the plaintext length
 * \param input    buffer holding the encrypted data
 * \param output   buffer that will hold the plaintext
 * \param output_max_len    maximum length of the output buffer
 *
 * \return         0 if successful, or an MBEDTLS_ERR_RSA_XXX error code
 *
 * \note           The output buffer must be as large as the size
 *                 of ctx->N (eg. 128 bytes if RSA-1024 is used) otherwise
 *                 an error is thrown.
 */
int shrsa_rsaes_pkcs1_v15_decrypt( shrsa_t *ctx,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng,
                                 int mode, size_t *olen,
                                 const unsigned char *input,
                                 unsigned char *output,
                                 size_t output_max_len );

/**
 * \brief          Perform a PKCS#1 v2.1 OAEP decryption (RSAES-OAEP-DECRYPT)
 *
 * \param ctx      RSA context
 * \param f_rng    RNG function (Only needed for MBEDTLS_RSA_PRIVATE)
 * \param p_rng    RNG parameter
 * \param mode     MBEDTLS_RSA_PUBLIC or MBEDTLS_RSA_PRIVATE
 * \param label    buffer holding the custom label to use
 * \param label_len contains the label length
 * \param olen     will contain the plaintext length
 * \param input    buffer holding the encrypted data
 * \param output   buffer that will hold the plaintext
 * \param output_max_len    maximum length of the output buffer
 *
 * \return         0 if successful, or an MBEDTLS_ERR_RSA_XXX error code
 *
 * \note           The output buffer must be as large as the size
 *                 of ctx->N (eg. 128 bytes if RSA-1024 is used) otherwise
 *                 an error is thrown.
 */
int shrsa_rsaes_oaep_decrypt( shrsa_t *ctx,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng,
                            int mode,
                            const unsigned char *label, size_t label_len,
                            size_t *olen,
                            const unsigned char *input,
                            unsigned char *output,
                            size_t output_max_len );

/**
 * \brief          Generic wrapper to perform a PKCS#1 signature using the
 *                 mode from the context. Do a private RSA operation to sign
 *                 a message digest
 *
 * \param ctx      RSA context
 * \param f_rng    RNG function (Needed for PKCS#1 v2.1 encoding and for
 *                               MBEDTLS_RSA_PRIVATE)
 * \param p_rng    RNG parameter
 * \param mode     MBEDTLS_RSA_PUBLIC or MBEDTLS_RSA_PRIVATE
 * \param md_alg   a MBEDTLS_MD_XXX (use MBEDTLS_MD_NONE for signing raw data)
 * \param hashlen  message digest length (for MBEDTLS_MD_NONE only)
 * \param hash     buffer holding the message digest
 * \param sig      buffer that will hold the ciphertext
 *
 * \return         0 if the signing operation was successful,
 *                 or an MBEDTLS_ERR_RSA_XXX error code
 *
 * \note           The "sig" buffer must be as large as the size
 *                 of ctx->N (eg. 128 bytes if RSA-1024 is used).
 *
 * \note           In case of PKCS#1 v2.1 encoding, see comments on
 * \note           \c shrsa_rsassa_pss_sign() for details on md_alg and hash_id.
 */
int shrsa_pkcs1_sign( shrsa_t *ctx,
                    int (*f_rng)(void *, unsigned char *, size_t),
                    void *p_rng,
                    int mode,
                    shrsa_md_type_t md_alg,
                    unsigned int hashlen,
                    const unsigned char *hash,
                    unsigned char *sig );

/**
 * \brief          Perform a PKCS#1 v1.5 signature (RSASSA-PKCS1-v1_5-SIGN)
 *
 * \param ctx      RSA context
 * \param f_rng    RNG function (Only needed for MBEDTLS_RSA_PRIVATE)
 * \param p_rng    RNG parameter
 * \param mode     MBEDTLS_RSA_PUBLIC or MBEDTLS_RSA_PRIVATE
 * \param md_alg   a MBEDTLS_MD_XXX (use MBEDTLS_MD_NONE for signing raw data)
 * \param hashlen  message digest length (for MBEDTLS_MD_NONE only)
 * \param hash     buffer holding the message digest
 * \param sig      buffer that will hold the ciphertext
 *
 * \return         0 if the signing operation was successful,
 *                 or an MBEDTLS_ERR_RSA_XXX error code
 *
 * \note           The "sig" buffer must be as large as the size
 *                 of ctx->N (eg. 128 bytes if RSA-1024 is used).
 */
int shrsa_rsassa_pkcs1_v15_sign( shrsa_t *ctx,
                               int (*f_rng)(void *, unsigned char *, size_t),
                               void *p_rng,
                               int mode,
                               shrsa_md_type_t md_alg,
                               unsigned int hashlen,
                               const unsigned char *hash,
                               unsigned char *sig );

/**
 * \brief          Perform a PKCS#1 v2.1 PSS signature (RSASSA-PSS-SIGN)
 *
 * \param ctx      RSA context
 * \param f_rng    RNG function (Needed for PKCS#1 v2.1 encoding and for
 *                               MBEDTLS_RSA_PRIVATE)
 * \param p_rng    RNG parameter
 * \param mode     MBEDTLS_RSA_PUBLIC or MBEDTLS_RSA_PRIVATE
 * \param md_alg   a MBEDTLS_MD_XXX (use MBEDTLS_MD_NONE for signing raw data)
 * \param hashlen  message digest length (for MBEDTLS_MD_NONE only)
 * \param hash     buffer holding the message digest
 * \param sig      buffer that will hold the ciphertext
 *
 * \return         0 if the signing operation was successful,
 *                 or an MBEDTLS_ERR_RSA_XXX error code
 *
 * \note           The "sig" buffer must be as large as the size
 *                 of ctx->N (eg. 128 bytes if RSA-1024 is used).
 *
 * \note           The hash_id in the RSA context is the one used for the
 *                 encoding. md_alg in the function call is the type of hash
 *                 that is encoded. According to RFC 3447 it is advised to
 *                 keep both hashes the same.
 */
int shrsa_rsassa_pss_sign( shrsa_t *ctx,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng,
                         int mode,
                         shrsa_md_type_t md_alg,
                         unsigned int hashlen,
                         const unsigned char *hash,
                         unsigned char *sig );

/**
 * \brief          Generic wrapper to perform a PKCS#1 verification using the
 *                 mode from the context. Do a public RSA operation and check
 *                 the message digest
 *
 * \param ctx      points to an RSA public key
 * \param f_rng    RNG function (Only needed for MBEDTLS_RSA_PRIVATE)
 * \param p_rng    RNG parameter
 * \param mode     MBEDTLS_RSA_PUBLIC or MBEDTLS_RSA_PRIVATE
 * \param md_alg   a MBEDTLS_MD_XXX (use MBEDTLS_MD_NONE for signing raw data)
 * \param hashlen  message digest length (for MBEDTLS_MD_NONE only)
 * \param hash     buffer holding the message digest
 * \param sig      buffer holding the ciphertext
 *
 * \return         0 if the verify operation was successful,
 *                 or an MBEDTLS_ERR_RSA_XXX error code
 *
 * \note           The "sig" buffer must be as large as the size
 *                 of ctx->N (eg. 128 bytes if RSA-1024 is used).
 *
 * \note           In case of PKCS#1 v2.1 encoding, see comments on
 *                 \c shrsa_rsassa_pss_verify() about md_alg and hash_id.
 */
int shrsa_pkcs1_verify( shrsa_t *ctx,
                      int (*f_rng)(void *, unsigned char *, size_t),
                      void *p_rng,
                      int mode,
                      shrsa_md_type_t md_alg,
                      unsigned int hashlen,
                      const unsigned char *hash,
                      const unsigned char *sig );

/**
 * \brief          Perform a PKCS#1 v1.5 verification (RSASSA-PKCS1-v1_5-VERIFY)
 *
 * \param ctx      points to an RSA public key
 * \param f_rng    RNG function (Only needed for MBEDTLS_RSA_PRIVATE)
 * \param p_rng    RNG parameter
 * \param mode     MBEDTLS_RSA_PUBLIC or MBEDTLS_RSA_PRIVATE
 * \param md_alg   a MBEDTLS_MD_XXX (use MBEDTLS_MD_NONE for signing raw data)
 * \param hashlen  message digest length (for MBEDTLS_MD_NONE only)
 * \param hash     buffer holding the message digest
 * \param sig      buffer holding the ciphertext
 *
 * \return         0 if the verify operation was successful,
 *                 or an MBEDTLS_ERR_RSA_XXX error code
 *
 * \note           The "sig" buffer must be as large as the size
 *                 of ctx->N (eg. 128 bytes if RSA-1024 is used).
 */
int shrsa_rsassa_pkcs1_v15_verify( shrsa_t *ctx,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng,
                                 int mode,
                                 shrsa_md_type_t md_alg,
                                 unsigned int hashlen,
                                 const unsigned char *hash,
                                 const unsigned char *sig );

/**
 * \brief          Perform a PKCS#1 v2.1 PSS verification (RSASSA-PSS-VERIFY)
 *                 (This is the "simple" version.)
 *
 * \param ctx      points to an RSA public key
 * \param f_rng    RNG function (Only needed for MBEDTLS_RSA_PRIVATE)
 * \param p_rng    RNG parameter
 * \param mode     MBEDTLS_RSA_PUBLIC or MBEDTLS_RSA_PRIVATE
 * \param md_alg   a MBEDTLS_MD_XXX (use MBEDTLS_MD_NONE for signing raw data)
 * \param hashlen  message digest length (for MBEDTLS_MD_NONE only)
 * \param hash     buffer holding the message digest
 * \param sig      buffer holding the ciphertext
 *
 * \return         0 if the verify operation was successful,
 *                 or an MBEDTLS_ERR_RSA_XXX error code
 *
 * \note           The "sig" buffer must be as large as the size
 *                 of ctx->N (eg. 128 bytes if RSA-1024 is used).
 *
 * \note           The hash_id in the RSA context is the one used for the
 *                 verification. md_alg in the function call is the type of
 *                 hash that is verified. According to RFC 3447 it is advised to
 *                 keep both hashes the same. If hash_id in the RSA context is
 *                 unset, the md_alg from the function call is used.
 */
int shrsa_rsassa_pss_verify( shrsa_t *ctx,
                           int (*f_rng)(void *, unsigned char *, size_t),
                           void *p_rng,
                           int mode,
                           shrsa_md_type_t md_alg,
                           unsigned int hashlen,
                           const unsigned char *hash,
                           const unsigned char *sig );

/**
 * \brief          Perform a PKCS#1 v2.1 PSS verification (RSASSA-PSS-VERIFY)
 *                 (This is the version with "full" options.)
 *
 * \param ctx      points to an RSA public key
 * \param f_rng    RNG function (Only needed for MBEDTLS_RSA_PRIVATE)
 * \param p_rng    RNG parameter
 * \param mode     MBEDTLS_RSA_PUBLIC or MBEDTLS_RSA_PRIVATE
 * \param md_alg   a MBEDTLS_MD_XXX (use MBEDTLS_MD_NONE for signing raw data)
 * \param hashlen  message digest length (for MBEDTLS_MD_NONE only)
 * \param hash     buffer holding the message digest
 * \param mgf1_hash_id message digest used for mask generation
 * \param expected_salt_len Length of the salt used in padding, use
 *                 MBEDTLS_RSA_SALT_LEN_ANY to accept any salt length
 * \param sig      buffer holding the ciphertext
 *
 * \return         0 if the verify operation was successful,
 *                 or an MBEDTLS_ERR_RSA_XXX error code
 *
 * \note           The "sig" buffer must be as large as the size
 *                 of ctx->N (eg. 128 bytes if RSA-1024 is used).
 *
 * \note           The hash_id in the RSA context is ignored.
 */
int shrsa_rsassa_pss_verify_ext( shrsa_t *ctx,
                               int (*f_rng)(void *, unsigned char *, size_t),
                               void *p_rng,
                               int mode,
                               shrsa_md_type_t md_alg,
                               unsigned int hashlen,
                               const unsigned char *hash,
                               shrsa_md_type_t mgf1_hash_id,
                               int expected_salt_len,
                               const unsigned char *sig );

/**
 * \brief          Copy the components of an RSA context
 *
 * \param dst      Destination context
 * \param src      Source context
 *
 * \return         0 on success,
 *                 MBEDTLS_ERR_MPI_ALLOC_FAILED on memory allocation failure
 */
int shrsa_copy( shrsa_t *dst, const shrsa_t *src );

/**
 * \brief          Free the components of an RSA key
 *
 * \param ctx      RSA Context to free
 */
void shrsa_free( shrsa_t *ctx );

#endif /* ndef DOXYGEN_SHOULD_SKIP_THIS */ 


/* alg - csum */

uint32_t shcsum_crc32(uint32_t crc, unsigned char *buf, size_t len);

uint32_t shcsum_crc32_combine(uint32_t crc1, uint32_t crc2, size_t len2);

uint32_t shcsum_adler32(uint32_t adler, unsigned char *buf, size_t len);

uint32_t shcsum_adler32_combine(uint32_t adler1, uint32_t adler2, size_t len2);

/**
 * @}
 */






/**
 * The libshare memory buffer pool allocation utilities.
 * @ingroup libshare_mem
 * @defgroup libshare_mempool Memory Buffer Pools
 * @{
 */

/**
 * A memory pool.
 */
typedef struct shpool_t shpool_t;

/**
 * A memory pool.
 */
struct shpool_t {
  shbuf_t **pool;
  int max;
};

/**
 * Initializes a new memory pool instance.
 * @returns A @ref shpool_t memory pool of @ref shbuf_t memory buffers.
 */
shpool_t *shpool_init(void);

/**
 * Calculates the number of avaiable @ref shbuf_t memory buffer contained 
 * in the @ref shpool_t memory pool.
 * @see shpool_get_index()
 */
size_t shpool_size(shpool_t *pool);

/**
 * Increases the size of the memory pool.
 * @bug smaller incremental reallocs have been known to fail in glibc
 */
void shpool_grow(shpool_t *pool);

/**
 * Get's the next available memory buffer from a pool.
 * @param idx_p A reference that is filled with the retained pool index of the buffer.
 */
shbuf_t *shpool_get(shpool_t *pool, unsigned int *idx_p);


/**
 * Get's a specific @ref shbuf_t memory buffer by index number.
 * @param index The index number of the memory buffer.
 * @returns The @ref shbuf_t memory buffer associated with the index or NULL if none exist.
 */
shbuf_t *shpool_get_index(shpool_t *pool, int index);

/**
 * Put's a memory buffer into a pool.
 */
void shpool_put(shpool_t *pool, shbuf_t *buff);

/**
 * Free's the resources associated with a memory pool.
 * @param pool_p A reference to an allocated @ref pool_t memory pool.
 */
void shpool_free(shpool_t **pool_p);

/**
 * @}
 */






/**
 * Provides the ability to manage object-related information by a key token.
 * @ingroup libshare_mem
 * @defgroup libshare_memmap Meta Definition Hashmap
 * @{
 */

/**
 * The initial number of hashmap indexes to create.
 */
#define INITIAL_MAX 15 /* tunable == 2^n - 1 */

/**
 * Specifies that a machine has a big endian architecture.
 * @see SHMETA_VALUE_ENDIAN
 */
#define SHMETA_BIG_ENDIAN 0

/**
 * Specifies that a machine has a small endian architecture.
 * @see SHMETA_VALUE_ENDIAN
 */
#define SHMETA_SMALL_ENDIAN 1

/**
 * Determines whether the meta value originated from a big or small endian architecture.
 * @returns SHMETA_BIG_ENDIAN or SHMETA_SMALL_ENDIAN based on the meta value.
 */
#define SHMETA_VALUE_ENDIAN(_val) \
  (_val->magic == SHMEM_ENDIAN_MAGIC ? \
   SHMETA_BIG_ENDIAN : SHMETA_SMALL_ENDIAN)



/**
 * Indicates the underlying map value has been allocated.
 */
#define SHMAP_ALLOC (1 << 0)

/**
 * A null-terminated string value.
 */
#define SHMAP_STRING (1 << 10)

/**
 * A numeric value with decimal precision.
 */
#define SHMAP_NUMBER (1 << 11)

/**
 * A non-specific binary memory segment.
 */
#define SHMAP_BINARY (1 << 13)

/**
 * A hashmap table.
 */
typedef struct shmap_t shmap_t;

/**
 * A hashmap index.
 */
typedef struct shmap_index_t shmap_index_t;

/**
 * Callback functions for calculating hash values.
 * @param key The key.
 * @param klen The length of the key.
 */
typedef unsigned int (*shmapfunc_t)(const char *key, ssize_t *klen);

/**
 * A hashmap entry.
 */
typedef struct shmap_entry_t shmap_entry_t;
struct shmap_entry_t {
    shmap_entry_t *next;
    unsigned int      hash;
    const void       *key;
//    ssize_t       klen;
    const void *val;
    ssize_t sz;
    int flag;
};

/**
 * Data structure for iterating through a hash table.
 *
 * We keep a pointer to the next hash entry here to allow the current
 * hash entry to be freed or otherwise mangled between calls to
 * shmap_next().
 */
struct shmap_index_t {
    shmap_t         *ht;
    shmap_entry_t   *tthis, *next;
    unsigned int        index;
};

/**
 * A meta definition is part of a @c shmap_t hashmap.
 *
 * The share library meta definitions can be used to hash header information from a socket stream, retaining access to the meta information by a token, and allowing for efficient redelivery or caching.
 *
 * @note A @c shfs_tree sharefs file system associates meta definition information with every @c shfs_node inode entry.
 * @note The size of the array is always a power of two. We use the maximum index rather than the size so that we can use bitwise-AND for modular arithmetic. The count of hash entries may be greater depending on the chosen collision rate.
 * @note The table is an array indexed by the hash of the key; collisions are resolved by hanging a linked list of hash entries off each element of the array. Although this is a really simple design it isn't too bad given that pools have a low allocation overhead.
 */
struct shmap_t {
    shmap_entry_t   **array;
    shmap_index_t     iterator;  /* For shmap_first(...) */
    unsigned int         count, max;
    shmapfunc_t       hash_func;
    shmap_entry_t    *free;  /* List of recycled entries */
};

/**
 * The base of a version 1 shmap hashmap entry value.
 */
struct shmap_value_t 
{

  /**
   * The hard-coded value @c SHMETA_VALUE_MAGIC set to ensure validity.
   * @note Used for recycling pools of objects and to ensure network integrity.
   */ 
  uint32_t magic;

  /**
   * An adler32 checksum of this @c shmap_value_t hashmap value header and the data segment following.
   */
  uint32_t crc;

  /**
   * A unix-time timestamp referencing when this hashmap value was generated.
   */
  uint32_t stamp;


  /**
   * A paramater format which describes the data segment following the @c shmap_value_t header.
   */
  uint32_t pf;  

  /**
   * An adler64 reference to the name of this value.
   */
  shkey_t name;

  /**
   * The total size of data segment not including the @c shmap_value_t header 
   */
  shsize_t sz;  

#if 0
  /**
   * A unique index number directly related to this @c shmap_value_t hashmap value.
   */
  uint32_t gl;

  /**
   * A adler32 reference to a function pertaining to this hashmap value.
   */ 
  uint32_t func;
  /**
   * A sequence number in an order of operations.
   */
  uint32_t seq;
#endif
uint64_t __reserved_0__;
uint64_t __reserved_1__;

  /**
   * blind reference to additional an data segment. 
   * */
  char raw[0];
};

/**
 * Specifies a reference to the current version of a shmap hashmap entry value.
 */
typedef struct shmap_value_t shmap_value_t;

/**
 * Create an instance of a meta definition hashmap.
 * @returns A @c shmap_t meta definition hashmap.
 */
shmap_t *shmap_init(void);

/**
 * Free an instance of a meta definition hashmap.
 * @param meta_p A reference to the meta definition hashmap to be free'd.
 */
void shmap_free(shmap_t **meta_p);

/**
 * Set a key to a particular allocated value in a map.
 * @param ht The meta definition hashmap to retrieve from.
 * @param sh_k The key of the meta definition value.
 * @param val The allocated value.
 * @note Do not free the value passed in.
 */
void shmap_set(shmap_t *ht, shkey_t *key, const void *val);

/**
 * Set a meta definition to a string value.
 * @param h The meta definition hash map.
 * @param name A string name identifying the meta definition.
 * @param value A string value to be assigned.
 * @note An allocated copy of the string value is stored.
 */
void shmap_set_str(shmap_t *h, shkey_t *key, char *value);

/**
 * Set a map key to an allocated copy of a string value.
 */
void shmap_set_astr(shmap_t *h, shkey_t *key, char *value);

/**
 * Unset a string value from a meta definition.
 */
void shmap_unset_str(shmap_t *h, shkey_t *name);

/**
 * Set an object value in a meta definition hash map.
 * @param h The meta definition hash map.
 * @param name The name of the meta definition.
 * @param data The binary data to assign.
 * @param data_len The size of the bindary data.
 */
void shmap_set_void(shmap_t *ht, shkey_t *key, void *data, size_t data_len);

/**
 * Get a string meta from a meta definition.
 * @returns A string reference to the hashmap value.
 */
char *shmap_get_str(shmap_t *h, shkey_t *key);

int64_t shmap_get_num(shmap_t *h, shkey_t *key);

void shmap_set_num(shmap_t *ht, shkey_t *key, int64_t val);

/**
 * Obtain a non-specific binary data segment from a meta definition hash map.
 * @param h The meta definition hash map.
 * @param name The name of the meta definition.
 */
void *shmap_get_void(shmap_t *h, shkey_t *key);

/**
 * Get a meta definition value
 * @param ht The meta definition hashmap to retrieve from.
 * @param sh_k The key of the meta definition value.
 * @returns A @c shmap_value_t containing the hashmap value.
 */
void *shmap_get(shmap_t *ht, shkey_t *key);

/**
 * Prints out a JSON representation of a meta definition hashmap.
 * @note The text buffer must be allocated by @c shbuf_init() first.
 * @param h The meta map to print.
 * @param ret_buff The text buffer to return the JSON string representation.
 */
void shmap_print(shmap_t *h, shbuf_t *ret_buff);

/**
 * Loads data dumped by shmap_print().
 */
void shmap_load(shmap_t *ht, shbuf_t *buff);

unsigned int shmap_count(shmap_t *ht);

void shmap_set_ptr(shmap_t *ht, shkey_t *key, void *ptr);

void *shmap_get_ptr(shmap_t *h, shkey_t *key);

void **shmap_get_ptr_list(shmap_t *h);

void shmap_set_abin(shmap_t *ht, shkey_t *key, void *data, size_t data_len);

void shmap_set_bin(shmap_t *ht, shkey_t *key, void *data, size_t data_len);

void shmap_unset(shmap_t *h, shkey_t *name);

void shmap_self(shmap_index_t *hi, shkey_t **key_p, void **val_p, ssize_t *len_p, int *flag_p); 

int shmap_set_ent(shmap_t *ht, shkey_t *key, int map_flag, void *val, ssize_t val_size);



/** */
void shbuf_append(shbuf_t *from_buff, shbuf_t *to_buff);

/** */
shbuf_t *shbuf_clone(shbuf_t *buff);

/**
 * @returns the number of characters appended to the memory buffer.
 * @note passes arguments through vsnprintf().
 */
int shbuf_sprintf(shbuf_t *buff, char *fmt, ...);
/**
 * @}
 */





/**
 * Provides encryption routines in order to encode or decode a binary segment.
 * @ingroup libshare_crypt
 * @defgroup libshare_memcrypt ShareKey Data Encryption
 * @{
 */





/**
 * Encrypt a data segment without allocating additional memory.
 * @param data - A segment of data.
 * @paramlen - The length of the data segment.
 * @param key - Pointer to a libshare @ref shkey_t token key.
 * @returns A zero on success and negative one (-1) when the string is already encrypted with the same key.
 * @note Fills @c data with encrypted data and @c len with the size of the new data array
 * @note data size must be equal to or larger than ((len + 7) / 8) * 8 + 8 + 4
 * TEA encrypts in 8 byte blocks, so it must include enough space to 
 * hold the entire data to pad out to an 8 byte boundary, plus another
 * 8 bytes at the end to give the length to the decrypt algorithm, plus
 * another 4 bytes to signify that it has been encrypted.
 * @note You must use the same key passed into this function in order to decrypt the segment.
 * @bug The data segment must be allocated 20 bytes larger than data_len. If possible this should return the same data length even if up to 16 bytes of the segment suffix is not encrypted.
 * @bug Both parameters will be modified.
 * @bug Specifying a different key will not prevent the data segment from being re-encrypted. The magic number @ref SHMEM_MAGIC should be used instead. 
 */
int ashencode(char *data, size_t *data_len_p, shkey_t *key);

/**
 * Encrypts byte array data of length len with key key using TEA.
 * @param data - A segment of data.
 * @paramlen - The length of the data segment.
 * @param key - Pointer to a libshare @ref shkey_t token key.
 * @returns A zero on success and negative one (-1) when the string is already encrypted with the same key.
 * @note Fills @c data with encrypted data and @c len with the size of the new data array
 * @note data size must be equal to or larger than ((len + 7) / 8) * 8 + 8 + 4
 * TEA encrypts in 8 byte blocks, so it must include enough space to 
 * hold the entire data to pad out to an 8 byte boundary, plus another
 * 8 bytes at the end to give the length to the decrypt algorithm, plus
 * another 4 bytes to signify that it has been encrypted.
 * @bug The data segment must be allocated 20 bytes larger than data_len. If possible this should return the same data length even if up to 16 bytes of the segment suffix is not encrypted.
 * @bug Both parameters will be modified.
 * @bug Specifying a different key will not prevent the data segment from being re-encrypted. The magic number @ref SHMEM_MAGIC should be used instead. 
 */
int shencode(char *data, size_t data_len, unsigned char **data_p, size_t *data_len_p, shkey_t *key);

/**
 * @see shdecode_str()
 */
shkey_t *shencode_str(char *data);

/**
 * Decrypt a data segment without allocating additional memory.
 * @param data - pointer to 8 bit data array to be decrypted - SEE NOTES
 * @param len - length of array
 * @param key - Pointer to four integer array (16 bytes) holding TEA key
 * @returns A zero on success and negative one (-1) when the string is not encrypted.
 * @note Modifies data and len
 * @note Fills @ref data with decrypted data and @ref len with the size of the new data 
 * @bug Using magic numbers in encrypt and decrypt routines - use #defines instead - Kyle
 * @bug If the 64 bit encoding functions aren't used outside this module, their prototypes should be in the code, not header - Simon
 * @bug Add sanity checking to input - Rob
 * @bug Require that input len is a multiple of 8 bytes - making a requirement we can't enforce or check is a recipe for corruption - Rob
 */
int ashdecode(uint8_t *data, size_t *data_len_p, shkey_t *key);

/**
 * Decrypts byte array data of length len with a @shkey_t key token.
 * @param data pointer to 8 bit data array to be decrypted
 * @param len length of array
 * @param data_p A reference to the decrypted data segment. 
 * @param data_len_p The length of the decrypted data segment.
 * @param key - Pointer to four integer array (16 bytes).
 * @returns A zero on success and negative one (-1) when the string is not encrypted.
 * @note Modifies data and len
 * @bug Using magic numbers in encrypt and decrypt routines - use #defines instead - Kyle
 * @bug If the 64 bit encoding functions aren't used outside this module, their prototypes should be in the code, not header - Simon
 * @bug Add sanity checking to input - Rob
 * @bug Require that input len is a multiple of 8 bytes - making a requirement we can't enforce or check is a recipe for corruption - Rob
 */
int shdecode(uint8_t *data, uint32_t data_len, char **data_p, size_t *data_len_p, shkey_t *key);

/**
 * Decrypt a string into it's original format using an assigned key.
 * @param key The key returned by @ref shencode_str()
 * @returns A zero on success and negative one (-1) when the string is not encrypted.
 */
int shdecode_str(char *data, shkey_t *key);


int shencode_b64(unsigned char *data, size_t data_len, char **out_p, shkey_t *key);

int shdecode_b64(char *in_data, unsigned char **data_p, size_t *data_len_p, shkey_t *key);




typedef struct shenc32_hdr_t
{
  uint32_t magic;
  uint32_t size;
} shenc32_hdr_t;

typedef shesig_t shenc_hdr_t; 


int shencrypt(int alg, shbuf_t *out_buff, unsigned char *data, size_t data_len, unsigned char *key, size_t key_len);

int shdecrypt(shbuf_t *out_buff, unsigned char *data, size_t data_len, unsigned char *key, size_t key_len);

int shdecrypt_verify(unsigned char *data, size_t data_len);

int shencrypt_derive(shesig_t *cert, shalg_t pub, shbuf_t *buff, unsigned char *key_data, size_t key_len);

int shdecrypt_derive_verify(shesig_t *cert, shalg_t pub);

void TEA_decrypt_data(uint8_t *data, uint32_t len, uint32_t *key);

void TEA_encrypt_data(uint8_t *data, uint32_t len, uint32_t *key);


/**
 * @}
 */








/**
 * Provides utility functions to manage mutex thread locks and semaphores.
 * @ingroup libshare_mem
 * @defgroup libshare_memlock Mutex and Semaphore Locks
 * @{
 */


/**
 * A lock used by the share library in order to ensure no two threads perform a system call at the same instance.
 */
#define SHLOCK_SYSTEM -9999


/** A flag which indicates the lock applies to only 'Read' I/O access. */
#define SHLK_READ_ONLY O_RDONLY
/** A flag which indicates the lock applies to only 'Write' I/O access. */
#define SHLK_WRITE_ONLY O_WRONLY
/** A flag which indicates the lock applies to all I/O access. */
#define SHLK_IO O_RDWR
/**
 * In memory this Prevents the mutex from allowing the same thread to access the lock. For a file indicates only the originating process may remove lock.
 *
 * @note Similar to a semaphore as the lock is not based on thread conditions.
 */
#define SHLK_PRIVATE O_EXCL
/** A flag which indicates the previous lock should be over-written. */
#define SHLK_OVERRIDE O_TRUNC
/** A flag which indicates to not wait for a lock to become available. */
#define SHLK_NOWAIT O_NONBLOCK


/**
 * The share library lock structure is used primarily in order to prevent multiple threads from performing system calls at the same instance.
 * The lock includes both re-entrant and private access styles.
 * The functionality can be extended in order to provide custom locks.
 * @see shlock_open() shlock_close()
 */
typedef struct shlock_t shlock_t;


/**
 * The share library lock structure.
 */
struct shlock_t 
{
  /** Time the lock was applied. */
  shtime_t lk_time;
  /** Offset of the locked region */ 
  uint64_t lk_of;
  /** Length of the locked regiion. */
  uint64_t lk_len;
  /** The UID of the account which generated the lock. */
  uint64_t lk_uid;
  /* Permissible lock restrictions. (SHLK_XXX) */
  uint32_t lk_flag;
  /* The process which is responsible for the lock. */
  uint32_t lk_pid;

  /**
   * The number of references being made to this lock.
   */
  uint32_t ref;

  /**
   * The process thread identification number
   * @see gettid()
   */
  uint32_t tid;

#if defined(HAVE_PTHREAD_MUTEX_LOCK) && defined(HAVE_PTHREAD_MUTEX_UNLOCK)
  /**
   * A linux-style mutex reference.
   */
  pthread_mutex_t mutex;
#endif

};


/**
 * Create a new lock on a mutex waiting if needed.
 * @param num A positive number identifying the lock.
 * @param flags A set of modifiers to configure the lock. (SHLK_XXX)
 * @note The libshare uses negative numbers for internal locks.
 * @see SHLOCK_SYSTEM SHLK_PRIVATE
 * @bug flags should be stored in @ref shkey_t instead of a paramter 
 */
shlock_t *shlock_open(shkey_t *key, int flags);

/**
 * Opens a lock based on a number.
 * @see shlock_open()
 */
#define shlock_open_num(_num, _flags) \
  shlock_open(ashkey_num(_num), (_flags))

/**
 * Opens a lock based on a string.
 * @see shlock_open()
 */
#define shlock_open_str(_str, _flags) \
  shlock_open(ashkey_str(_str), (_flags))

/**
 * Create a new lock on a mutex unless one has already been created.
 * @param num A positive number identifying the lock.
 * @param flags A set of modifiers to configure the lock. (SHLK_XXX)
 * @note The libshare uses negative numbers for internal locks.
 * @returns A 0 on success, a 1 when the mutex is already locked, and a -1 on error.
 * @see SHLOCK_SYSTEM SHLK_PRIVATE
 */
int shlock_tryopen(shkey_t *key, int flags, shlock_t **lock_p);

/**
 * Opens a lock based on a number.
 * @see shlock_tryopen()
 */
#define shlock_tryopen_num(_num, _flags, _keyp) \
  shlock_tryopen(ashkey_num(_num), (_flags), (_keyp))

/**
 * Opens a lock based on a string.
 * @see shlock_tryopen()
 */
#define shlock_tryopen_str(_str, _flags, _keyp) \
  shlock_tryopen(ashkey_str(_str), (_flags), (_keyp))

/**
 * Unlock a mutex.
 */ 
int shlock_close(shkey_t *key);

/**
 * Closes a lock based on a number.
 * @see shlock_close()
 */
#define shlock_close_num(_num, _flags) \
  shlock_close(ashkey_num(_num), (_flags))

/**
 * Closes a lock based on a string. 
 * @see shlock_close()
 */
#define shlock_close_str(_str) \
  shlock_close(ashkey_str(_str))

/**
 * @}
 */







/**
 * The Scrypt virtual coin algorithm is an alternative to the common SHA bitcoin protocol.
 * @ingroup libshare_mem
 * @defgroup libshare_memscrypt Scrypt Virtual Coin Algorithm
 * @{
 */

typedef struct scrypt_work 
{
  unsigned char   data[128];
  unsigned char   midstate[32];
  unsigned char   target[32];
  char hash[32];

  char ntime[16];
  struct timeval tv_received;
  uint32_t hash_nonce;
  int restart;

  uint64_t        share_diff;

  int             rolls;
  int             drv_rolllimit; /* How much the driver can roll ntime */

  struct timeval  tv_staged;

  uint32_t nonce;

  //        bool            stratum;
  char            *job_id;
  char xnonce2[16];
  //        bytes_t         nonce2;
  double          sdiff;
  //        char            *nonce1;

  unsigned char   work_restart_id;
  int             id;
  int             device_id;
  //UT_hash_handle hh;

  double          work_difficulty;

  char merkle_root[256]; 

  double pool_diff;

} scrypt_work;

typedef struct scrypt_peer
{
  char nonce1[16];
  size_t n1_len;
  size_t n2_len;
  double diff;

} scrypt_peer;


#ifndef bswap_16
#define bswap_16(value)  \
        ((((value) & 0xff) << 8) | ((value) >> 8))

#define bswap_32(value) \
        (((uint32_t)bswap_16((uint16_t)((value) & 0xffff)) << 16) | \
        (uint32_t)bswap_16((uint16_t)((value) >> 16)))

#define bswap_64(value) \
        (((uint64_t)bswap_32((uint32_t)((value) & 0xffffffff)) \
            << 32) | \
        (uint64_t)bswap_32((uint32_t)((value) >> 32)))
#endif

#define flip32(dest_p, src_p) \
  (swap32yes(dest_p, src_p, 32 / 4))

static inline uint32_t swab32(uint32_t v)
{
        return bswap_32(v);
}
static inline void swap32yes(void*out, const void*in, size_t sz) {
        size_t swapcounter = 0;
        for (swapcounter = 0; swapcounter < sz; ++swapcounter)
                (((uint32_t*)out)[swapcounter]) = swab32(((uint32_t*)in)[swapcounter]);
}

void shscrypt_peer(scrypt_peer *peer, char *nonce1, double diff);
int shscrypt(scrypt_work *work, int step);
int shscrypt_verify(scrypt_work *work);
void shscrypt_peer_gen(scrypt_peer *peer, double diff);
double shscrypt_hash_diff(scrypt_work *work);


void shscrypt_work(scrypt_peer *peer, scrypt_work *work, 
    char **merkle_list, char *prev_hash, 
    char *coinbase1, char *coinbase2, char *nbit, char *ntime);

void shscrypt_swap256(void *dest_p, const void *src_p);

void sh_calc_midstate(struct scrypt_work *work);

/**
 * @}
 */







/**
 * A self-balancing tree data structure. Tree nodes are composed of a data segment, a "left branch", and a "right branch". Nodes that do not branch are called leafs.
 * @ingroup libshare_mem
 * @defgroup libshare_memtree B-Tree Index Map
 * @{
 */

#define SHTREE_ORDER_PRE 1
#define SHTREE_ORDER_IN 2
#define SHTREE_ORDER_POST 3

/** Do not allow nodes to be removed. */
#define SHTREE_PERM (1 << 10)
/** Re-use old intermediate branch nodes that are deleted. */
#define SHTREE_RECYCLE (1 << 11)
/** De-allocate the data segments provided. */
#define SHTREE_DEALLOC (1 << 12)

typedef struct shtree_t
{

  /* The base tree node. */
  struct shtree_t *root;
  /* The node one level up. */
  struct shtree_t *parent;
  /* A "left" node one level down. */
  struct shtree_t *left;
  /* A "right" node one level down. */
  struct shtree_t *right;

  /* The context data. */
  unsigned char *data;

  /** The last time that the node was updated. */
  shtime_t stamp;

  /** The number of node hops from the root. */
  int level;

  /** tree attributes */
  int flags;

} shtree_t;

typedef void (*shtree_f)(shtree_t *);

/** Set a data segment for a tree node. */
void shtree_data_set(shtree_t *node, void *data);

/** Get a data segment from a tree node. */
void *shtree_data_get(shtree_t *node);

shtree_t *shtree_new(shtree_t *tree, void *data);

shtree_t *shtree_init(int flags);

void shtree_free_node(shtree_t *node);

void shtree_remove_branch(shtree_t *node);

shtree_t *shtree_left_new(shtree_t *tree, void *data);

shtree_t *shtree_right_new(shtree_t *tree, void *data);

shtree_t *shtree_right(shtree_t *tree);

shtree_t *shtree_left(shtree_t *tree);

int shtree_leaf(shtree_t *tree);

shtree_t *shtree_root(shtree_t *node);

shtree_t *shtree_parent(shtree_t *node);

int shtree_flags(shtree_t *node);

int shtree_root_flags(shtree_t *node);

void shtree_traverse_pre(shtree_t *node, shtree_f proc);

void shtree_traverse_in(shtree_t *node, shtree_f proc);

void shtree_traverse_post(shtree_t *node, shtree_f proc);

void shtree_traverse(shtree_t *node, int order, shtree_f proc);

void shtree_free(shtree_t **tree_p);

/**
 * @}
 */







/**
 * Provides ability to compress and decompress sets of named data segments (files) for the SHZ compression format.
 * @ingroup libshare_mem
 * @defgroup libshare_memzlib SHZ Compression and Decompression
 * @{
 */


/**
 * Compress data into a data buffer.
 * @param buff The data buffer to store the compressed data.
 * @param data The data segment to compress.
 */
int shzenc(shbuf_t *buff, void *data, size_t data_len);

/**
 * Decompress a data segment into a data buffer.
 * @param buff The data buffer to store the decompressed data.
 * @param data The data segment to decompress.
 */
int shzdec(shbuf_t *buff, unsigned char *data, size_t data_len);


/** The size of each page. */
#define SHZ_PAGE_SIZE 1024
/** The maximum size to allocate at once for the archive. */
#define SHZ_ALLOC_SIZE 65536

/* an empty page */
#define SHZ_PAGE_NONE 0
/* a b-tree index referencing a dictionary mapping. */
#define SHZ_PAGE_ROOT 1001
#define SHZ_PAGE_BRANCH 1002
#define SHZ_PAGE_DATA 1004 
/* indicates raw un-encoded data */
#define SHZ_PAGE_RAW 1006 
/** A block containing hash references to archived data content. */
#define SHZ_PAGE_INDEX 10011
/** A block containing a segment of raw zlib compressed data. */
#define SHZ_PAGE_ZLIB_DATA 10021
#define SHZ_PAGE_ZLIB 10022
/** */
#define SHZ_PAGE_DIR 10102
/** */
#define SHZ_PAGE_FILE 10104
/**
 * A base page which initializes the archive state.
 * @see shz_base_t 
 */
#define SHZ_PAGE_BASE 23123 

#define MAX_SHZ_PAGE_MODES 24000


#define SHZ_DICT_MASK 0xFF /* 1 byte */

#define SHZ_HASH_MASK 0xF0 /* 240 */


#define SHZ_MAX_INDEX_SIZE \
    ((SHZ_PAGE_SIZE - sizeof(shz_index_t)) / sizeof(shz_idx))

#define SHZ_WRITE_F(_f) ((shz_write_f)(_f))
#define SHZ_READ_F(_f) ((shz_read_f)(_f))




/* whether to automatically create a file archive if none exists */
#define SHZ_CREATE (1 << 0)

/** whether to reduce the encode (compress) window in order to increase speed */
#define SHZ_FAST (1 << 1)

/** Flag to denote file attributes should not be applied from archive. */ 
#define SHZ_NOATTR (1 << 2)

/** Truncate the archive upon initialization. */
#define SHZ_TRUNC (1 << 3)

/** Do not encode (compress) the stored data. */
#define SHZ_RAW (1 << 4)

/** Log information about individual archive operations. */
#define SHZ_VERBOSE (1 << 5)

/** Skip data integrity errors. */
#define SHZ_IGNORE (1 << 6)

#define SHZ_QUIET (1 << 7)

#define SHZ_ABSOLUTE (1 << 8)

/** Whether the buffer is internally allocated by the shz functionality */
#define SHZ_ALLOC (1 << 20)

/** Whether to start with an empty archive. */
#define SHZ_FRESH (1 << 21)

/** Flag to denote that a base CRC needs verified. */
#define SHZ_VERIFY (1 << 22)



typedef uint32_t shz_idx;

typedef struct shz_hdr_t
{

  /** The type of hdr. */
  uint16_t type;

  /** An arbitrary number for integrity verification. */
  uint16_t magic;

  /* A checksum of the hdr. */
  uint16_t crc;

  /** The size of the hdr used. */
  uint16_t size;

} shz_hdr_t;


typedef struct shz_base_t
{
  shz_hdr_t hdr; /* 'Z' 'S' <88> */

  uint16_t salt;

  uint16_t __reserved_0__;

  /** the initial index block. */
  uint32_t seq;

  /** thte total size of the compressed archive. */
  uint64_t size;

  /** the total size of the compressed data. */
  uint64_t zsize;

  /** A checksum encapsulating the entire archive. */
  uint64_t crc;

  /** the time of when the archive was created. */
  shtime_t ctime;

  /** the time of when the archive was modified. */
  shtime_t mtime;

  shz_idx dtable;

  shz_idx ftable;

} shz_base_t;

struct shz_map_t
{
  shz_hdr_t hdr;
  shz_idx right;
  shz_idx left;
};
typedef struct shz_map_t shz_map_t;

/**
 * A generic module encoding binary information.
 */
struct shz_mod_t
{

  shz_hdr_t hdr;

  /** An identifying hash token representing the data content. */
  shkey_t id;

  /** The size of the data content. */
  uint32_t size;

  /** A checksum of the data content. */
  uint32_t crc;

  /** The number of indexes referencing this module. */
  uint32_t ref;

  uint32_t __reserved_0__;

  /** The block index of the underlying data content. */
  shz_idx seq;

  /** The block index containing a data reference to the file name. */
  shz_idx name;

  /** Creation time of archive member. */
  shtime_t ctime;

  /** Last modification time of archive member. */
  shtime_t mtime;

};
typedef struct shz_mod_t shz_mod_t;

struct shz_data_t
{

  shz_hdr_t hdr;

  /** The block index of the next data segment. */
  uint32_t seq;

  uint32_t __reserved_0__;

};
typedef struct shz_data_t shz_data_t;

struct shz_t
{

  /** The highest page index */
  uint32_t bseq;

  /** The last page read/written. */
  uint32_t bpos;

  uint32_t flags;

  /** A direct pointer into the current "SHZ_PAGE_BASE" header. */
  shz_base_t *base;

  /** A sharebuf holding the raw archive data. */
  shbuf_t *buff;

  /** A data table tree */
  shtree_t *dtable;

  /** A file table tree */
  shtree_t *ftable;


};
typedef struct shz_t shz_t;

/** a tree node reference to a "map" page block. */
struct shz_tree_t
{

  shz_map_t *page;

  shz_idx seq; 

};
typedef struct shz_tree_t shz_tree_t;



typedef struct shz_data_t shz_index_t;






/** The bulk write function template for a module. */
typedef ssize_t (*shz_write_f)(shz_t *, shz_idx *, unsigned char *, size_t);
/** The bulk read function template for a module. */
typedef int (*shz_read_f)(shz_t *, shz_idx, shbuf_t *);

typedef int (*shz_list_f)(shz_t *, shz_idx, char *f_path, shbuf_t *, void *p);



shz_t *shz_init(shbuf_t *buff, int flags);

void shz_free(shz_t **z_p);

shz_t *shz_fopen(const char *path, int flags);

/**
 * Extract files from the an archive to the current working directory.
 * @param z The SHZ archive.
 * @param fspec NULL to omit filter or a wild-card filename specification.
 * @note Specify a literal filename in the fspec to extract a single file.
 */
int shz_extract(shz_t *z, char *fspec);

/**
 * Iterate through all files, filtering by file-spec, to call a supplied procedure.
 * @param z The SHZ archive.
 * @param rel_path An absolute path to extract file(s) to.
 * @param fspec NULL to omit filter or a wild-card filename specification.
 * @param op The procedure to call for each file listed.
 * @note Specify a literal filename in the fspec to extract a single file.
 */
int shz_list(shz_t *z, char *rel_path, char *fspec, shz_list_f op, void *p);


/**
 * Add (or over-write) a file in the archive based on a relative path.
 */
int shz_file_add(shz_t *z, const char *filename);

/** Add to the contents of a file in the archive. */
int shz_file_append(shz_t *z, const char *filename, shbuf_t *buff);

/** Write the contents of a file to the archive. */
int shz_file_write(shz_t *z, const char *filename, shbuf_t *buff);

/** Read the contents of a file in the archive. */
int shz_file_read(shz_t *z, const char *filename, shbuf_t *buff);

/** Obtain the print label for a SHZ page type. */
const char *shz_type_label(int type);



int shz_arch_init(shz_t *z, shbuf_t *buff, int flags);

int shz_arch_fopen(shz_t *z, const char *path, int flags);

void shz_arch_free(shz_t *z);

/** Allocate a new block page for the archive. */
shz_hdr_t *shz_page_new(shz_t *z, int type, shz_idx *bnum_p);

/** Obtain a block page from the archive. */
shz_hdr_t *shz_page(shz_t *z, int bnum);



/**
 * Extracts all files contained in an archive, relative to <filename>, that match the <fspec> filter.
 * @param z The SHZ archive.
 * @param rel_path An absolute path to extract file(s) to.
 * @param fspec NULL for no filter, or a wildcard filename specification.
 * @note All paths refernce the local file system.
 */
int shz_file_extract(shz_t *z, char *rel_path, char *fspec);

int shz_list_write(shz_t *z, shz_idx f_idx, char *f_path, shbuf_t *buff, void *p);





ssize_t shz_raw_write(shz_t *z, shz_idx *ret_idx_p, unsigned char *data, size_t data_len);

int shz_raw_read(shz_t *z, shz_idx bnum, shbuf_t *buff);

int shz_index_add(shz_t *z, shz_write_f f, shbuf_t *buff, shz_idx *ret_idx_p);

int shz_index_write(shz_t *z, shz_write_f f, shbuf_t *buff, shz_idx *ret_idx_p);

int shz_index_read(shz_t *z, shz_read_f f, shbuf_t *buff, shz_idx bnum);

ssize_t shz_zlib_write(shz_t *z, shz_idx *z_bnum_p, unsigned char *data, size_t data_len);

int shz_zlib_read(shz_t *z, int page_bnum, shbuf_t *dec_buff);


int shz_mod_write(shz_t *z, shz_idx mod_bnum, shbuf_t *buff);

int shz_mod_read(shz_t *z, shz_mod_t *mod, shbuf_t *buff);


time_t shz_mod_ctime(shz_t *z, shz_idx bnum);

time_t shz_mod_mtime(shz_t *z, shz_idx bnum);

const char *shz_mod_label(shz_t *z, shz_idx bnum);


/** The time that the archive was created. */
shtime_t shz_ctime(shz_t *z);

/** The last time the archive was updated. */
shtime_t shz_mtime(shz_t *z);

/** The time the archive was created in unix-time. */
time_t shz_uctime(shz_t *z);

/** The last modification time in unix-time format. */
time_t shz_umtime(shz_t *z);





/**
 * @}
 */





/**
 * Provides the ability to generate patches, or apply them, for text segments.
 * @ingroup libshare_mem
 * @defgroup libshare_memdiff Textual Comparison Patch
 * @{
 */
int shdiff(shbuf_t *buff, char *str_1, char *str_2);
/**
 * @}
 */





/**
 * Provides the ability to generate patches, or apply them, for binary segments.
 * @ingroup libshare_mem
 * @defgroup libshare_memdelta XD3 Diff Comparison
 * @{
 */
int shdelta(shbuf_t *src_buff, shbuf_t *in_buff, shbuf_t *out_buff);

int shpatch(shbuf_t *src_buff, shbuf_t *in_buff, shbuf_t *out_buff);
/**
 * @}
 */




/**
 * Provides various text formats that can be used to reference a binary data segment.
 * @ingroup libshare_mem
 * @defgroup libshare_membase Base-X Numerical Text Format
 * @{
 */

int shbase58_decode(unsigned char *data, size_t *data_len, char *b58);

int shbase58_encode(char *b58, size_t *b58sz, unsigned char *data, size_t data_len);

int shbase58_encode_check(const uint8_t *data, int datalen, char *str, int strsize);

int shbase58_decode_check(const char *str, uint8_t *data, int datalen);

int shbase58_decode_size(char *b58, size_t max_size);



int shbase64_decode(char *enc_data, unsigned char **data_p, size_t *data_len_p);
int shbase64_encode(unsigned char *data, size_t data_len, char **enc_data_p);

int shbase32_adecode(char *in, size_t in_len, unsigned char *out, size_t *out_len_p);
int shbase32_decode(char *in, size_t in_len, unsigned char *out, size_t *out_len_p);
void shbase32_encode (const char *in, size_t inlen, char *out, size_t outlen);
size_t shbase32_encode_alloc (const char *in, size_t inlen, char **out);

/**
 * @}
 */






/**
 * A ShareKey (SHALG_SHKEY) derived method for generating a cryptographic signature referencing a data segment.
 * @ingroup libshare_mem
 * @defgroup libshare_memsig Sharekey Signature Algorithm
 * @{
 */

typedef struct shsig_t
{

  //shkey_t sig_peer;

  shkey_t sig_key;

  shtime_t sig_stamp;

  shtime_t sig_expire;

  union {
    struct shsig_rsa_t {
      char mod[512];
      uint32_t mod_len;
      uint64_t exp;
    } rsa;
    struct shsig_md_t {
      char md[512];
      uint32_t md_len;
    } md;
    struct shsig_sha_t {
      char sha[512];
      uint32_t sha_len;
    } sha;
    struct shsig_ecdsa_t {
      char sig_r[64];
      char sig_s[64];
    } ecdsa;
  } key;

} shsig_t;


/**
 * Generate a public key using random or user-supplied content.
 * @param data The user-supplied content or NULL for random key.
 */
int shsig_shr_gen(shsig_t *pub_sig, unsigned char data, size_t data_len);

/**
 * Generate a private signature from data content and sign it with a public key.
 * @param data The user-supplied message to sign.
 */
int shsig_shr_sign(shsig_t *priv_sig, shsig_t *pub_sig, unsigned char *data, size_t data_len);

/**
 * Verify that a private key is valid based on user-supplied content and a public signature.
 */
int shsig_shr_verify(shsig_t *priv_sig, shsig_t *pub_sig, unsigned char *data, size_t data_len);

/**
 * @}
 */





/**
 * Provides the capability to generate or parse a JSON formatted context.
 * @ingroup libshare_mem
 * @defgroup libshare_memjson JSON Format Encoder
 * @{
 */

#define SHJSON_FALSE 0
#define SHJSON_TRUE 1
#define SHJSON_NULL 2
#define SHJSON_NUMBER 3
#define SHJSON_STRING 4
#define SHJSON_ARRAY 5
#define SHJSON_OBJECT 6
#define SHJSON_REFERENCE 256
#define SHJSON_BOOLEAN 257

#define shjson_False SHJSON_FALSE
#define shjson_True SHJSON_TRUE
#define shjson_NULL SHJSON_NULL
#define shjson_Number SHJSON_NUMBER
#define shjson_String SHJSON_STRING
#define shjson_Array SHJSON_ARRAY
#define shjson_Object SHJSON_OBJECT

typedef struct shjson_t {
  /* next/prev allow you to walk array/object chains. Alternatively, use GetArraySize/GetArrayItem/GetObjectItem */
  struct shjson_t *next,*prev;	
  /* An array or object item will have a child pointer pointing to a chain of the items in the array/object. */
  struct shjson_t *child;
  /* The type of the item, as above. */
  int type;		
  /* The item's string, if type==shjson_String */
  char *valuestring;	
  /* The item's number, if type==shjson_Number */
  int valueint;	
  /* The item's number, if type==shjson_Number */
  double valuedouble;	
  /* The item's name string, if this item is the child of, or is in the list of subitems of an object. */
  char *string;			
} shjson_t;


/**
 * A JSON text-format of the specified hierarchy.
 * @returns An allocated string in JSON format.
 */
char *shjson_print(shjson_t *json);

/**
 * A human-readable JSON text-format of the specified hierarchy.
 * @returns An allocated string in JSON format.
 */
char *shjson_Print(shjson_t *item);

/**
 * Obtain the type of variable for a given element.
 * @param json A json element.
 * @param name The object element names, or NULL to specify <json> itself. 
 * @returns A SHJSON_XXX type define.
 * @note Returns SHJSON_BOOLEAN in the case of SHJSON_TRUE or SHJSON_FALSE.
 */
int shjson_type(shjson_t *json, char *name);

/**
 * Obtain an allocated string value from a JSON object.
 * @param tree The JSON object containing the string value.
 * @param name The name of the string JSON node.
 * @param def_str The default string value if the JSON node does not exist.
 * @returns The string value contained in the JSON node.
 */
char *shjson_str(shjson_t *json, char *name, char *def_str);

/**
 * Obtain an un-allocated string value from a JSON object.
 * @param tree The JSON object containing the string value.
 * @param name The name of the string JSON node.
 * @param def_str The default string value if the JSON node does not exist.
 * @returns The string value contained in the JSON node.
 */
char *shjson_astr(shjson_t *json, char *name, char *def_str);

/**
 * Add a string value to a JSON object or array.
 * @param tree The JSON object containing the string value.
 * @param name The name of the string JSON node.
 * @param val The string value to store in the new JSON node.
 * @returns The new JSON node containing the string value.
 */
shjson_t *shjson_str_add(shjson_t *tree, char *name, char *val);

/**
 * Add a boolean value to a JSON object or array.
 * @param tree The JSON object or array to append to.
 * @param name The name of the boolean JSON node or NULL if tree is an array.
 * @param val Either TRUE or FALSE.
 * @returns The new JSON node containing the string value.
 */
shjson_t *shjson_bool_add(shjson_t *tree, char *name, int val);

/**
 * De-allocates memory associated with a JSON hiearchy.
 * @param tree_p A reference to the JSON hierarchy.
 * @see shjson_init()
 */
void shjson_free(shjson_t **tree_p);

/**
 * Obtain a number value from a JSON object.
 * @param tree The JSON object containing the number value.
 * @param name The name of the number JSON node.
 * @param def_d The default number value if the JSON node does not exist.
 * @returns The number value contained in the JSON node.
 */
double shjson_num(shjson_t *json, char *name, double def_d);

/**
 * Obtain a boolean value from a JSON object.
 * @param tree The JSON object containing the boolean value.
 * @param name The name of the boolean JSON node.
 * @param def_d The default boolean value if the JSON node does not exist.
 * @returns The boolean value contained in the JSON node.
 */
int shjson_bool(shjson_t *json, char *name, int def_d);

/**
 * Add a number value to a JSON object or array.
 * @param tree The JSON object or array to add the number value.
 * @param name The name of the number JSON node or NULL if @c tree is an array.
 * @param idx The number value to store in the new JSON node.
 * @returns The new JSON node containing the number value.
 */
shjson_t *shjson_num_add(shjson_t *tree, char *name, double num);

/**
 * Add a null value to a JSON object or array.
 * @param tree The JSON object or array to add the null value.
 * @param name The name of the number JSON node or NULL if adding to an array.
 * @returns The new JSON node containing the null value.
 */
shjson_t *shjson_null_add(shjson_t *tree, char *name);


/**
 * Create a new JSON tree hierarchy.
 * @param json_str A JSON formatted text string or NULL.
 * @returns A new JSON object if @c json_str is null or a full JSON node hierarchy otherwise.
 * @see shjson_print
 * @see shjson_free
 */
shjson_t *shjson_init(char *json_str);

/**
 * Create a new JSON node at the end of an array.
 * @param json The JSON object containing the array.
 * @param name The name of the array in the JSON object.
 * @returns A new JSON node attachd to the array.
 */
shjson_t *shjson_array_add(shjson_t *tree, char *name);

int shjson_array_count(shjson_t *json, char *name);

/**
 * Create a new object JSON node.
 * @param name The name of the object or NULL if appending to an array.
 */
shjson_t *shjson_obj_add(shjson_t *tree, char *name);

/**
 * Append a JSON object into another object.
 * @param item A JSON object to copy from.
 * @param obj The JSON object to copy to.
 * @note Can also be used on a JSON array.
 */
void shjson_obj_append(shjson_t *item, shjson_t *obj);

/**
 * Obtain an allocated string value from an array.
 * @param json The JSON object containing the array.
 * @param name The name of the array in the JSON object.
 * @param idx The index number of the JSON node in the array.
 * @returns The string value contained in the array's node index.
 * @note The string pointer returned must be de-allocated.
 */
char *shjson_array_str(shjson_t *json, char *name, int idx);

/**
 * Obtain an un-allocated string value from an array.
 * @param json The JSON object containing the array.
 * @param name The name of the array in the JSON object.
 * @param idx The index number of the JSON node in the array.
 * @returns The string value contained in the array's node index.
 * @note Do not free the string pointer returned.
 */
char *shjson_array_astr(shjson_t *json, char *name, int idx);

/**
 * Obtain a number value from an array.
 * @param json The JSON object containing the array.
 * @param name The name of the array in the JSON object.
 * @param idx The index number of the JSON node in the array.
 * @returns The numeric value contained in the array's node index.
 */
double shjson_array_num(shjson_t *json, char *name, int idx);

/**
 * @returns A JSON object contained inside another object.
 */
shjson_t *shjson_obj(shjson_t *json, char *name);

/**
 * @returns The string length of a JSON object node.
 */
size_t shjson_strlen(shjson_t *json, char *name);

uint64_t shjson_crc(shjson_t *json, char *name);

shjson_t *shjson_obj_get(shjson_t *json, char *name);

/**
 * @}
 */







/** 
 * @example shkeystore.c
 * Example of storing, verifying, and retrieiving arbitrary keys.
 */

/**
 * @}
 */


#endif /* ndef __MEM__SHMEM_H__ */

