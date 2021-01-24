
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

#ifndef __MEM__SHMEM_ALG_SHA_H__
#define __MEM__SHMEM_ALG_SHA_H__


/*
 *  These constants are used in the USHA (Unified SHA) functions.
 */
typedef enum SHAversion {
  SHA1 = SHALG_SHA1, 
  SHA224 = SHALG_SHA224,
  SHA256 = SHALG_SHA256,
  SHA384 = SHALG_SHA384,
  SHA512 = SHALG_SHA512
} SHAversion;



#define SHA_Ch(x, y, z)      (((x) & ((y) ^ (z))) ^ (z))
#define SHA_Maj(x, y, z)     (((x) & ((y) | (z))) | ((y) & (z)))
#define SHA_Parity(x, y, z)  ((x) ^ (y) ^ (z))


/* sha1 */

/**  Define the SHA1 circular left shift macro */
#define SHA1_ROTL(bits,word) \
                (((word) << (bits)) | ((word) >> (32-(bits))))

/*
 * Add "length" to the length.
 * Set Corrupted when overflow has occurred.
 */
static uint32_t _sha1_add_temp;
#define SHA1AddLength(context, length)                     \
    (_sha1_add_temp = (context)->Length_Low,                      \
     (context)->Corrupted =                                \
        (((context)->Length_Low += (length)) < _sha1_add_temp) && \
        (++(context)->Length_High == 0) ? SHERR_INVAL  \
                                        : (context)->Corrupted )



/* sha256 */
/* Define the SHA shift, rotate left, and rotate right macros */
#define SHA256_SHR(bits,word)      ((word) >> (bits))
#define SHA256_ROTL(bits,word)                         \
  (((word) << (bits)) | ((word) >> (32-(bits))))
#define SHA256_ROTR(bits,word)                         \
  (((word) >> (bits)) | ((word) << (32-(bits))))

/* Define the SHA SIGMA and sigma macros */
#define SHA256_SIGMA0(word)   \
  (SHA256_ROTR( 2,word) ^ SHA256_ROTR(13,word) ^ SHA256_ROTR(22,word))
#define SHA256_SIGMA1(word)   \
  (SHA256_ROTR( 6,word) ^ SHA256_ROTR(11,word) ^ SHA256_ROTR(25,word))
#define SHA256_sigma0(word)   \
  (SHA256_ROTR( 7,word) ^ SHA256_ROTR(18,word) ^ SHA256_SHR( 3,word))
#define SHA256_sigma1(word)   \
  (SHA256_ROTR(17,word) ^ SHA256_ROTR(19,word) ^ SHA256_SHR(10,word))

/*
 * Add "length" to the length.
 * Set Corrupted when overflow has occurred.
 */
static uint32_t _sha224_add_temp;
#define SHA224_256AddLength(context, length)               \
  (_sha224_add_temp = (context)->Length_Low, (context)->Corrupted = \
    (((context)->Length_Low += (length)) < _sha224_add_temp) &&     \
    (++(context)->Length_High == 0) ? SHERR_INVAL :    \
                                      (context)->Corrupted )







/* sh512 */

/* Define the SHA shift, rotate left and rotate right macros */
#define SHA512_SHR(bits,word)  (((uint64_t)(word)) >> (bits))
#define SHA512_ROTR(bits,word) ((((uint64_t)(word)) >> (bits)) | \
                                (((uint64_t)(word)) << (64-(bits))))

/*
 * Define the SHA SIGMA and sigma macros
 *
 *  SHA512_ROTR(28,word) ^ SHA512_ROTR(34,word) ^ SHA512_ROTR(39,word)
 */
#define SHA512_SIGMA0(word)   \
 (SHA512_ROTR(28,word) ^ SHA512_ROTR(34,word) ^ SHA512_ROTR(39,word))
#define SHA512_SIGMA1(word)   \
 (SHA512_ROTR(14,word) ^ SHA512_ROTR(18,word) ^ SHA512_ROTR(41,word))
#define SHA512_sigma0(word)   \
 (SHA512_ROTR( 1,word) ^ SHA512_ROTR( 8,word) ^ SHA512_SHR( 7,word))
#define SHA512_sigma1(word)   \
 (SHA512_ROTR(19,word) ^ SHA512_ROTR(61,word) ^ SHA512_SHR( 6,word))

/*
 * Add "length" to the length.
 * Set Corrupted when overflow has occurred.
 */
static uint64_t addTemp;
#define SHA384_512AddLength(context, length)                   \
   (addTemp = context->Length_Low, context->Corrupted =        \
    ((context->Length_Low += length) < addTemp) &&             \
    (++context->Length_High == 0) ? SHERR_INVAL :          \
                                    (context)->Corrupted)


#endif /* ndef __MEM__SHMEM_ALG_SHA_H__ */

