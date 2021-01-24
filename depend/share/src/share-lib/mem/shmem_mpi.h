
/*
 * @copyright
 *
 *  Copyright 2015 Neo Natura 
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


/*
 *  Copyright (C) 2006-2014, ARM Limited, All Rights Reserved
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __MEM__SHMEM_MPI_H__
#define __MEM__SHMEM_MPI_H__

#ifndef DOXYGEN_SHOULD_SKIP_THIS


#if defined(_MSC_VER) && !defined(EFIX64) && !defined(EFI32)
#include <basetsd.h>
#if (_MSC_VER <= 1200)
typedef   signed short  int16_t;
typedef unsigned short uint16_t;
#else
typedef  INT16  int16_t;
typedef UINT16 uint16_t;
#endif
typedef  INT32  int32_t;
typedef  INT64  int64_t;
typedef UINT32 uint32_t;
typedef UINT64 uint64_t;
#else
#include <inttypes.h>
#endif /* _MSC_VER && !EFIX64 && !EFI32 */

#define MPI_CHK(f) do { if( ( ret = f ) != 0 ) goto cleanup; } while( 0 )

/*
 * Maximum size MPIs are allowed to grow to in number of limbs.
 */
#define MPI_MPI_MAX_LIMBS                             10000

#if !defined(MPI_MPI_WINDOW_SIZE)
/*
 * Maximum window size used for modular exponentiation. Default: 6
 * Minimum value: 1. Maximum value: 6.
 *
 * Result is an array of ( 2 << MPI_MPI_WINDOW_SIZE ) MPIs used
 * for the sliding window calculation. (So 64 by default)
 *
 * Reduction in size, reduces speed.
 */
#define MPI_MPI_WINDOW_SIZE                           6        /**< Maximum windows size used. */
#endif /* !MPI_MPI_WINDOW_SIZE */

#if !defined(MPI_MPI_MAX_SIZE)
/*
 * Maximum size of MPIs allowed in bits and bytes for user-MPIs.
 * ( Default: 512 bytes => 4096 bits, Maximum tested: 2048 bytes => 16384 bits )
 *
 * Note: Calculations can results temporarily in larger MPIs. So the number
 * of limbs required (MPI_MPI_MAX_LIMBS) is higher.
 */
#define MPI_MPI_MAX_SIZE                              1024     /**< Maximum number of bytes for usable MPIs. */
#endif /* !MPI_MPI_MAX_SIZE */

#define MPI_MPI_MAX_BITS                              ( 8 * MPI_MPI_MAX_SIZE )    /**< Maximum number of bits for usable MPIs. */

/*
 * When reading from files with shmpi_read_file() and writing to files with
 * shmpi_write_file() the buffer should have space
 * for a (short) label, the MPI (in the provided radix), the newline
 * characters and the '\0'.
 *
 * By default we assume at least a 10 char label, a minimum radix of 10
 * (decimal) and a maximum of 4096 bit numbers (1234 decimal chars).
 * Autosized at coshmpile time for at least a 10 char label, a minimum radix
 * of 10 (decimal) for a number of MPI_MPI_MAX_BITS size.
 *
 * This used to be statically sized to 1250 for a maximum of 4096 bit
 * numbers (1234 decimal chars).
 *
 * Calculate using the formula:
 *  MPI_MPI_RW_BUFFER_SIZE = ceil(MPI_MPI_MAX_BITS / ln(10) * ln(2)) +
 *                                LabelSize + 6
 */
#define MPI_MPI_MAX_BITS_SCALE100          ( 100 * MPI_MPI_MAX_BITS )
#define LN_2_DIV_LN_10_SCALE100                 332
#define MPI_MPI_RW_BUFFER_SIZE             ( ((MPI_MPI_MAX_BITS_SCALE100 + LN_2_DIV_LN_10_SCALE100 - 1) / LN_2_DIV_LN_10_SCALE100) + 10 + 6 )


#ifndef MULADDC_INIT
#define MULADDC_INIT                    \
{                                       \
    t_uint s0, s1, b0, b1;              \
    t_uint r0, r1, rx, ry;              \
    b0 = ( b << biH ) >> biH;           \
    b1 = ( b >> biH );
#endif

#ifndef MULADDC_CORE
#define MULADDC_CORE                    \
    s0 = ( *s << biH ) >> biH;          \
    s1 = ( *s >> biH ); s++;            \
    rx = s0 * b1; r0 = s0 * b0;         \
    ry = s1 * b0; r1 = s1 * b1;         \
    r1 += ( rx >> biH );                \
    r1 += ( ry >> biH );                \
    rx <<= biH; ry <<= biH;             \
    r0 += rx; r1 += (r0 < rx);          \
    r0 += ry; r1 += (r0 < ry);          \
    r0 +=  c; r1 += (r0 <  c);          \
    r0 += *d; r1 += (r0 < *d);          \
    c = r1; *(d++) = r0;
#endif

#ifndef MULADDC_STOP
#define MULADDC_STOP                    \
}
#endif


#endif /* ndef DOXYGEN_SHOULD_SKIP_THIS */

#endif /* ndef __MEM__SHMEM_MPI_H__ */
