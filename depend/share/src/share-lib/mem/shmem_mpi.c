
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
 *  Multi-precision integer library
 *
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
/*
 *  This MPI implementation is based on:
 *
 *  http://www.cacr.math.uwaterloo.ca/hac/about/chap14.pdf
 *  http://www.stillhq.com/extracted/gnupg-api/shmpi/
 *  http://math.libtomcrypt.com/files/tommath.pdf
 */

#include "share.h"

#define debug_printf     printf

/* Implementation that should never be optimized out by the coshmpiler */
static void _zeroize( void *v, size_t n ) {
  memset(v, '\000', n);
}

#define ciL    (sizeof(t_uint))         /* chars in limb  */
#define biL    (ciL << 3)               /* bits  in limb  */
#define biH    (ciL << 2)               /* half limb size */

/*
 * Convert between bits/chars and number of limbs
 */
#define BITS_TO_LIMBS(i)  (((i) + biL - 1) / biL)
#define CHARS_TO_LIMBS(i) (((i) + ciL - 1) / ciL)

/*
 * Initialize one MPI
 */
void shmpi_init( shmpi *X )
{
    if( X == NULL )
        return;

    X->s = 1;
    X->n = 0;
    X->p = NULL;
}

/*
 * Unallocate one MPI
 */
void shmpi_free( shmpi *X )
{
    if( X == NULL )
        return;

    if( X->p != NULL )
    {
        _zeroize( X->p, X->n * ciL );
        free( X->p );
    }

    X->s = 1;
    X->n = 0;
    X->p = NULL;
}

/*
 * Enlarge to the specified number of limbs
 */
int shmpi_grow( shmpi *X, size_t nblimbs )
{
    t_uint *p;

    if( nblimbs > MPI_MPI_MAX_LIMBS )
        return( SHMPI_ERR_MALLOC_FAILED );

    if( X->n < nblimbs )
    {
        if( ( p = malloc( nblimbs * ciL ) ) == NULL )
            return( SHMPI_ERR_MALLOC_FAILED );

        memset( p, 0, nblimbs * ciL );

        if( X->p != NULL )
        {
            memcpy( p, X->p, X->n * ciL );
            _zeroize( X->p, X->n * ciL );
            free( X->p );
        }

        X->n = nblimbs;
        X->p = p;
    }

    return( 0 );
}

/*
 * Resize down as much as possible,
 * while keeping at least the specified number of limbs
 */
int shmpi_shrink( shmpi *X, size_t nblimbs )
{
    t_uint *p;
    size_t i;

    /* Actually resize up in this case */
    if( X->n <= nblimbs )
        return( shmpi_grow( X, nblimbs ) );

    for( i = X->n - 1; i > 0; i-- )
        if( X->p[i] != 0 )
            break;
    i++;

    if( i < nblimbs )
        i = nblimbs;

    if( ( p = malloc( i * ciL ) ) == NULL )
        return( SHMPI_ERR_MALLOC_FAILED );

    memset( p, 0, i * ciL );

    if( X->p != NULL )
    {
        memcpy( p, X->p, i * ciL );
        _zeroize( X->p, X->n * ciL );
        free( X->p );
    }

    X->n = i;
    X->p = p;

    return( 0 );
}

/*
 * Copy the contents of Y into X
 */
int shmpi_copy( shmpi *X, const shmpi *Y )
{
    int ret;
    size_t i;

    if( X == Y )
        return( 0 );

    if( Y->p == NULL )
    {
        shmpi_free( X );
        return( 0 );
    }

    for( i = Y->n - 1; i > 0; i-- )
        if( Y->p[i] != 0 )
            break;
    i++;

    X->s = Y->s;

    MPI_CHK( shmpi_grow( X, i ) );

    memset( X->p, 0, X->n * ciL );
    memcpy( X->p, Y->p, i * ciL );

cleanup:

    return( ret );
}

/*
 * Swap the contents of X and Y
 */
void shmpi_swap( shmpi *X, shmpi *Y )
{
    shmpi T;

    memcpy( &T,  X, sizeof( shmpi ) );
    memcpy(  X,  Y, sizeof( shmpi ) );
    memcpy(  Y, &T, sizeof( shmpi ) );
}

/*
 * Conditionally assign X = Y, without leaking information
 * about whether the assignment was made or not.
 * (Leaking information about the respective sizes of X and Y is ok however.)
 */
int shmpi_safe_cond_assign( shmpi *X, const shmpi *Y, unsigned char assign )
{
    int ret = 0;
    size_t i;

    /* make sure assign is 0 or 1 in a time-constant manner */
    assign = (assign | (unsigned char)-assign) >> 7;

    MPI_CHK( shmpi_grow( X, Y->n ) );

    X->s = X->s * ( 1 - assign ) + Y->s * assign;

    for( i = 0; i < Y->n; i++ )
        X->p[i] = X->p[i] * ( 1 - assign ) + Y->p[i] * assign;

    for( ; i < X->n; i++ )
        X->p[i] *= ( 1 - assign );

cleanup:
    return( ret );
}

/*
 * Conditionally swap X and Y, without leaking information
 * about whether the swap was made or not.
 * Here it is not ok to simply swap the pointers, which whould lead to
 * different memory access patterns when X and Y are used afterwards.
 */
int shmpi_safe_cond_swap( shmpi *X, shmpi *Y, unsigned char swap )
{
    int ret, s;
    size_t i;
    t_uint tmp;

    if( X == Y )
        return( 0 );

    /* make sure swap is 0 or 1 in a time-constant manner */
    swap = (swap | (unsigned char)-swap) >> 7;

    MPI_CHK( shmpi_grow( X, Y->n ) );
    MPI_CHK( shmpi_grow( Y, X->n ) );

    s = X->s;
    X->s = X->s * ( 1 - swap ) + Y->s * swap;
    Y->s = Y->s * ( 1 - swap ) +    s * swap;


    for( i = 0; i < X->n; i++ )
    {
        tmp = X->p[i];
        X->p[i] = X->p[i] * ( 1 - swap ) + Y->p[i] * swap;
        Y->p[i] = Y->p[i] * ( 1 - swap ) +     tmp * swap;
    }

cleanup:
    return( ret );
}

/*
 * Set value from integer
 */
int shmpi_lset( shmpi *X, t_sint z )
{
    int ret;

    MPI_CHK( shmpi_grow( X, 1 ) );
    memset( X->p, 0, X->n * ciL );

    X->p[0] = ( z < 0 ) ? -z : z;
    X->s    = ( z < 0 ) ? -1 : 1;

cleanup:

    return( ret );
}

/*
 * Get a specific bit
 */
int shmpi_get_bit( const shmpi *X, size_t pos )
{
    if( X->n * biL <= pos )
        return( 0 );

    return( ( X->p[pos / biL] >> ( pos % biL ) ) & 0x01 );
}

/*
 * Set a bit to a specific value of 0 or 1
 */
int shmpi_set_bit( shmpi *X, size_t pos, unsigned char val )
{
    int ret = 0;
    size_t off = pos / biL;
    size_t idx = pos % biL;

    if( val != 0 && val != 1 )
        return( SHMPI_ERR_BAD_INPUT_DATA );

    if( X->n * biL <= pos )
    {
        if( val == 0 )
            return( 0 );

        MPI_CHK( shmpi_grow( X, off + 1 ) );
    }

    X->p[off] &= ~( (t_uint) 0x01 << idx );
    X->p[off] |= (t_uint) val << idx;

cleanup:

    return( ret );
}

/*
 * Return the number of least significant bits
 */
size_t shmpi_lsb( const shmpi *X )
{
    size_t i, j, count = 0;

    for( i = 0; i < X->n; i++ )
        for( j = 0; j < biL; j++, count++ )
            if( ( ( X->p[i] >> j ) & 1 ) != 0 )
                return( count );

    return( 0 );
}

/*
 * Return the number of most significant bits
 */
size_t shmpi_msb( const shmpi *X )
{
    size_t i, j;

    if( X->n == 0 )
        return( 0 );

    for( i = X->n - 1; i > 0; i-- )
        if( X->p[i] != 0 )
            break;

    for( j = biL; j > 0; j-- )
        if( ( ( X->p[i] >> ( j - 1 ) ) & 1 ) != 0 )
            break;

    return( ( i * biL ) + j );
}

/*
 * Return the total size in bytes
 */
size_t shmpi_size( const shmpi *X )
{
    return( ( shmpi_msb( X ) + 7 ) >> 3 );
}

/*
 * Convert an ASCII character to digit value
 */
static int shmpi_get_digit( t_uint *d, int radix, char c )
{
    *d = 255;

    if( c >= 0x30 && c <= 0x39 ) *d = c - 0x30;
    if( c >= 0x41 && c <= 0x46 ) *d = c - 0x37;
    if( c >= 0x61 && c <= 0x66 ) *d = c - 0x57;

    if( *d >= (t_uint) radix )
        return( SHMPI_ERR_INVALID_CHARACTER );

    return( 0 );
}

/*
 * Import from an ASCII string
 */
int shmpi_read_string( shmpi *X, int radix, const char *s )
{
    int ret;
    size_t i, j, slen, n;
    t_uint d;
    shmpi T;

    if( radix < 2 || radix > 16 )
        return( SHMPI_ERR_BAD_INPUT_DATA );

    shmpi_init( &T );

    slen = strlen( s );

    if( radix == 16 )
    {
        n = BITS_TO_LIMBS( slen << 2 );

        MPI_CHK( shmpi_grow( X, n ) );
        MPI_CHK( shmpi_lset( X, 0 ) );

        for( i = slen, j = 0; i > 0; i--, j++ )
        {
            if( i == 1 && s[i - 1] == '-' )
            {
                X->s = -1;
                break;
            }

            MPI_CHK( shmpi_get_digit( &d, radix, s[i - 1] ) );
            X->p[j / ( 2 * ciL )] |= d << ( ( j % ( 2 * ciL ) ) << 2 );
        }
    }
    else
    {
        MPI_CHK( shmpi_lset( X, 0 ) );

        for( i = 0; i < slen; i++ )
        {
            if( i == 0 && s[i] == '-' )
            {
                X->s = -1;
                continue;
            }

            MPI_CHK( shmpi_get_digit( &d, radix, s[i] ) );
            MPI_CHK( shmpi_mul_int( &T, X, radix ) );

            if( X->s == 1 )
            {
                MPI_CHK( shmpi_add_int( X, &T, d ) );
            }
            else
            {
                MPI_CHK( shmpi_sub_int( X, &T, d ) );
            }
        }
    }

cleanup:

    shmpi_free( &T );

    return( ret );
}

/*
 * Helper to write the digits high-order first
 */
static int shmpi_write_hlp( shmpi *X, int radix, char **p )
{
    int ret;
    t_uint r;

    if( radix < 2 || radix > 16 )
        return( SHMPI_ERR_BAD_INPUT_DATA );

    MPI_CHK( shmpi_mod_int( &r, X, radix ) );
    MPI_CHK( shmpi_div_int( X, NULL, X, radix ) );

    if( shmpi_cmp_int( X, 0 ) != 0 )
        MPI_CHK( shmpi_write_hlp( X, radix, p ) );

    if( r < 10 )
        *(*p)++ = (char)( r + 0x30 );
    else
        *(*p)++ = (char)( r + 0x37 );

cleanup:

    return( ret );
}

/*
 * Export into an ASCII string
 */
int shmpi_write_string( const shmpi *X, int radix, char *s, size_t *slen )
{
    int ret = 0;
    size_t n;
    char *p;
    shmpi T;

    if( radix < 2 || radix > 16 )
        return( SHMPI_ERR_BAD_INPUT_DATA );

    n = shmpi_msb( X );
    if( radix >=  4 ) n >>= 1;
    if( radix >= 16 ) n >>= 1;
    n += 3;

    if( *slen < n )
    {
        *slen = n;
        return( SHMPI_ERR_BUFFER_TOO_SMALL );
    }

    p = s;
    shmpi_init( &T );

    if( X->s == -1 )
        *p++ = '-';

    if( radix == 16 )
    {
        int c;
        size_t i, j, k;

        for( i = X->n, k = 0; i > 0; i-- )
        {
            for( j = ciL; j > 0; j-- )
            {
                c = ( X->p[i - 1] >> ( ( j - 1 ) << 3) ) & 0xFF;

                if( c == 0 && k == 0 && ( i + j ) != 2 )
                    continue;

                *(p++) = "0123456789ABCDEF" [c / 16];
                *(p++) = "0123456789ABCDEF" [c % 16];
                k = 1;
            }
        }
    }
    else
    {
        MPI_CHK( shmpi_copy( &T, X ) );

        if( T.s == -1 )
            T.s = 1;

        MPI_CHK( shmpi_write_hlp( &T, radix, &p ) );
    }

    *p++ = '\0';
    *slen = p - s;

cleanup:

    shmpi_free( &T );

    return( ret );
}

#if defined(MPI_FS_IO)
/*
 * Read X from an opened file
 */
int shmpi_read_file( shmpi *X, int radix, FILE *fin )
{
    t_uint d;
    size_t slen;
    char *p;
    /*
     * Buffer should have space for (short) label and decimal formatted MPI,
     * newline characters and '\0'
     */
    char s[ MPI_MPI_RW_BUFFER_SIZE ];

    memset( s, 0, sizeof( s ) );
    if( fgets( s, sizeof( s ) - 1, fin ) == NULL )
        return( SHMPI_ERR_FILE_IO_ERROR );

    slen = strlen( s );
    if( slen == sizeof( s ) - 2 )
        return( SHMPI_ERR_BUFFER_TOO_SMALL );

    if( s[slen - 1] == '\n' ) { slen--; s[slen] = '\0'; }
    if( s[slen - 1] == '\r' ) { slen--; s[slen] = '\0'; }

    p = s + slen;
    while( --p >= s )
        if( shmpi_get_digit( &d, radix, *p ) != 0 )
            break;

    return( shmpi_read_string( X, radix, p + 1 ) );
}

/*
 * Write X into an opened file (or stdout if fout == NULL)
 */
int shmpi_write_file( const char *p, const shmpi *X, int radix, FILE *fout )
{
    int ret;
    size_t n, slen, plen;
    /*
     * Buffer should have space for (short) label and decimal formatted MPI,
     * newline characters and '\0'
     */
    char s[ MPI_MPI_RW_BUFFER_SIZE ];

    n = sizeof( s );
    memset( s, 0, n );
    n -= 2;

    MPI_CHK( shmpi_write_string( X, radix, s, (size_t *) &n ) );

    if( p == NULL ) p = "";

    plen = strlen( p );
    slen = strlen( s );
    s[slen++] = '\r';
    s[slen++] = '\n';

    if( fout != NULL )
    {
        if( fwrite( p, 1, plen, fout ) != plen ||
            fwrite( s, 1, slen, fout ) != slen )
            return( SHMPI_ERR_FILE_IO_ERROR );
    }
    else
        debug_printf( "%s%s", p, s );

cleanup:

    return( ret );
}
#endif /* MPI_FS_IO */

/*
 * Import X from unsigned binary data, big endian
 */
int shmpi_read_binary( shmpi *X, const unsigned char *buf, size_t buflen )
{
    int ret;
    size_t i, j, n;

    for( n = 0; n < buflen; n++ )
        if( buf[n] != 0 )
            break;

    MPI_CHK( shmpi_grow( X, CHARS_TO_LIMBS( buflen - n ) ) );
    MPI_CHK( shmpi_lset( X, 0 ) );

    for( i = buflen, j = 0; i > n; i--, j++ )
        X->p[j / ciL] |= ((t_uint) buf[i - 1]) << ((j % ciL) << 3);

cleanup:

    return( ret );
}

/*
 * Export X into unsigned binary data, big endian
 */
int shmpi_write_binary( const shmpi *X, unsigned char *buf, size_t buflen )
{
    size_t i, j, n;

    n = shmpi_size( X );

    if( buflen < n )
        return( SHMPI_ERR_BUFFER_TOO_SMALL );

    memset( buf, 0, buflen );

    for( i = buflen - 1, j = 0; n > 0; i--, j++, n-- )
        buf[i] = (unsigned char)( X->p[j / ciL] >> ((j % ciL) << 3) );

    return( 0 );
}

/*
 * Left-shift: X <<= count
 */
int shmpi_shift_l( shmpi *X, size_t count )
{
    int ret;
    size_t i, v0, t1;
    t_uint r0 = 0, r1;

    v0 = count / (biL    );
    t1 = count & (biL - 1);

    i = shmpi_msb( X ) + count;

    if( X->n * biL < i )
        MPI_CHK( shmpi_grow( X, BITS_TO_LIMBS( i ) ) );

    ret = 0;

    /*
     * shift by count / limb_size
     */
    if( v0 > 0 )
    {
        for( i = X->n; i > v0; i-- )
            X->p[i - 1] = X->p[i - v0 - 1];

        for( ; i > 0; i-- )
            X->p[i - 1] = 0;
    }

    /*
     * shift by count % limb_size
     */
    if( t1 > 0 )
    {
        for( i = v0; i < X->n; i++ )
        {
            r1 = X->p[i] >> (biL - t1);
            X->p[i] <<= t1;
            X->p[i] |= r0;
            r0 = r1;
        }
    }

cleanup:

    return( ret );
}

/*
 * Right-shift: X >>= count
 */
int shmpi_shift_r( shmpi *X, size_t count )
{
    size_t i, v0, v1;
    t_uint r0 = 0, r1;

    v0 = count /  biL;
    v1 = count & (biL - 1);

    if( v0 > X->n || ( v0 == X->n && v1 > 0 ) )
        return shmpi_lset( X, 0 );

    /*
     * shift by count / limb_size
     */
    if( v0 > 0 )
    {
        for( i = 0; i < X->n - v0; i++ )
            X->p[i] = X->p[i + v0];

        for( ; i < X->n; i++ )
            X->p[i] = 0;
    }

    /*
     * shift by count % limb_size
     */
    if( v1 > 0 )
    {
        for( i = X->n; i > 0; i-- )
        {
            r1 = X->p[i - 1] << (biL - v1);
            X->p[i - 1] >>= v1;
            X->p[i - 1] |= r0;
            r0 = r1;
        }
    }

    return( 0 );
}

/*
 * Compare unsigned values
 */
int shmpi_cmp_abs( const shmpi *X, const shmpi *Y )
{
    size_t i, j;

    for( i = X->n; i > 0; i-- )
        if( X->p[i - 1] != 0 )
            break;

    for( j = Y->n; j > 0; j-- )
        if( Y->p[j - 1] != 0 )
            break;

    if( i == 0 && j == 0 )
        return( 0 );

    if( i > j ) return(  1 );
    if( j > i ) return( -1 );

    for( ; i > 0; i-- )
    {
        if( X->p[i - 1] > Y->p[i - 1] ) return(  1 );
        if( X->p[i - 1] < Y->p[i - 1] ) return( -1 );
    }

    return( 0 );
}

/*
 * Compare signed values
 */
int shmpi_cmp_mpi( const shmpi *X, const shmpi *Y )
{
    size_t i, j;

    for( i = X->n; i > 0; i-- )
        if( X->p[i - 1] != 0 )
            break;

    for( j = Y->n; j > 0; j-- )
        if( Y->p[j - 1] != 0 )
            break;

    if( i == 0 && j == 0 )
        return( 0 );

    if( i > j ) return(  X->s );
    if( j > i ) return( -Y->s );

    if( X->s > 0 && Y->s < 0 ) return(  1 );
    if( Y->s > 0 && X->s < 0 ) return( -1 );

    for( ; i > 0; i-- )
    {
        if( X->p[i - 1] > Y->p[i - 1] ) return(  X->s );
        if( X->p[i - 1] < Y->p[i - 1] ) return( -X->s );
    }

    return( 0 );
}

/*
 * Compare signed values
 */
int shmpi_cmp_int( const shmpi *X, t_sint z )
{
    shmpi Y;
    t_uint p[1];

    *p  = ( z < 0 ) ? -z : z;
    Y.s = ( z < 0 ) ? -1 : 1;
    Y.n = 1;
    Y.p = p;

    return( shmpi_cmp_mpi( X, &Y ) );
}

/*
 * Unsigned addition: X = |A| + |B|  (HAC 14.7)
 */
int shmpi_add_abs( shmpi *X, const shmpi *A, const shmpi *B )
{
    int ret;
    size_t i, j;
    t_uint *o, *p, c;

    if( X == B )
    {
        const shmpi *T = A; A = X; B = T;
    }

    if( X != A )
        MPI_CHK( shmpi_copy( X, A ) );

    /*
     * X should always be positive as a result of unsigned additions.
     */
    X->s = 1;

    for( j = B->n; j > 0; j-- )
        if( B->p[j - 1] != 0 )
            break;

    MPI_CHK( shmpi_grow( X, j ) );

    o = B->p; p = X->p; c = 0;

    for( i = 0; i < j; i++, o++, p++ )
    {
        *p +=  c; c  = ( *p <  c );
        *p += *o; c += ( *p < *o );
    }

    while( c != 0 )
    {
        if( i >= X->n )
        {
            MPI_CHK( shmpi_grow( X, i + 1 ) );
            p = X->p + i;
        }

        *p += c; c = ( *p < c ); i++; p++;
    }

cleanup:

    return( ret );
}

/*
 * Helper for shmpi subtraction
 */
static void shmpi_sub_hlp( size_t n, t_uint *s, t_uint *d )
{
    size_t i;
    t_uint c, z;

    for( i = c = 0; i < n; i++, s++, d++ )
    {
        z = ( *d <  c );     *d -=  c;
        c = ( *d < *s ) + z; *d -= *s;
    }

    while( c != 0 )
    {
        z = ( *d < c ); *d -= c;
        c = z; i++; d++;
    }
}

/*
 * Unsigned subtraction: X = |A| - |B|  (HAC 14.9)
 */
int shmpi_sub_abs( shmpi *X, const shmpi *A, const shmpi *B )
{
    shmpi TB;
    int ret;
    size_t n;

    if( shmpi_cmp_abs( A, B ) < 0 )
        return( SHMPI_ERR_NEGATIVE_VALUE );

    shmpi_init( &TB );

    if( X == B )
    {
        MPI_CHK( shmpi_copy( &TB, B ) );
        B = &TB;
    }

    if( X != A )
        MPI_CHK( shmpi_copy( X, A ) );

    /*
     * X should always be positive as a result of unsigned subtractions.
     */
    X->s = 1;

    ret = 0;

    for( n = B->n; n > 0; n-- )
        if( B->p[n - 1] != 0 )
            break;

    shmpi_sub_hlp( n, B->p, X->p );

cleanup:

    shmpi_free( &TB );

    return( ret );
}

/*
 * Signed addition: X = A + B
 */
int shmpi_add_mpi( shmpi *X, const shmpi *A, const shmpi *B )
{
    int ret, s = A->s;

    if( A->s * B->s < 0 )
    {
        if( shmpi_cmp_abs( A, B ) >= 0 )
        {
            MPI_CHK( shmpi_sub_abs( X, A, B ) );
            X->s =  s;
        }
        else
        {
            MPI_CHK( shmpi_sub_abs( X, B, A ) );
            X->s = -s;
        }
    }
    else
    {
        MPI_CHK( shmpi_add_abs( X, A, B ) );
        X->s = s;
    }

cleanup:

    return( ret );
}

/*
 * Signed subtraction: X = A - B
 */
int shmpi_sub_mpi( shmpi *X, const shmpi *A, const shmpi *B )
{
    int ret, s = A->s;

    if( A->s * B->s > 0 )
    {
        if( shmpi_cmp_abs( A, B ) >= 0 )
        {
            MPI_CHK( shmpi_sub_abs( X, A, B ) );
            X->s =  s;
        }
        else
        {
            MPI_CHK( shmpi_sub_abs( X, B, A ) );
            X->s = -s;
        }
    }
    else
    {
        MPI_CHK( shmpi_add_abs( X, A, B ) );
        X->s = s;
    }

cleanup:

    return( ret );
}

/*
 * Signed addition: X = A + b
 */
int shmpi_add_int( shmpi *X, const shmpi *A, t_sint b )
{
    shmpi _mpi;
    t_uint p[1];

    p[0] = ( b < 0 ) ? -b : b;
    _mpi.s = ( b < 0 ) ? -1 : 1;
    _mpi.n = 1;
    _mpi.p = p;

    return( shmpi_add_mpi( X, A, &_mpi ) );
}

/*
 * Signed subtraction: X = A - b
 */
int shmpi_sub_int( shmpi *X, const shmpi *A, t_sint b )
{
    shmpi _mpi;
    t_uint p[1];

    p[0] = ( b < 0 ) ? -b : b;
    _mpi.s = ( b < 0 ) ? -1 : 1;
    _mpi.n = 1;
    _mpi.p = p;

    return( shmpi_sub_mpi( X, A, &_mpi ) );
}

/*
 * Helper for shmpi multiplication
 */
static
#if defined(__APPLE__) && defined(__arm__)
/*
 * Apple LLVM version 4.2 (clang-425.0.24) (based on LLVM 3.2svn)
 * appears to need this to prevent bad ARM code generation at -O3.
 */
__attribute__ ((noinline))
#endif
void shmpi_mul_hlp( size_t i, t_uint *s, t_uint *d, t_uint b )
{
    t_uint c = 0, t = 0;

#if defined(MULADDC_HUIT)
    for( ; i >= 8; i -= 8 )
    {
        MULADDC_INIT
        MULADDC_HUIT
        MULADDC_STOP
    }

    for( ; i > 0; i-- )
    {
        MULADDC_INIT
        MULADDC_CORE
        MULADDC_STOP
    }
#else /* MULADDC_HUIT */
    for( ; i >= 16; i -= 16 )
    {
        MULADDC_INIT
        MULADDC_CORE   MULADDC_CORE
        MULADDC_CORE   MULADDC_CORE
        MULADDC_CORE   MULADDC_CORE
        MULADDC_CORE   MULADDC_CORE

        MULADDC_CORE   MULADDC_CORE
        MULADDC_CORE   MULADDC_CORE
        MULADDC_CORE   MULADDC_CORE
        MULADDC_CORE   MULADDC_CORE
        MULADDC_STOP
    }

    for( ; i >= 8; i -= 8 )
    {
        MULADDC_INIT
        MULADDC_CORE   MULADDC_CORE
        MULADDC_CORE   MULADDC_CORE

        MULADDC_CORE   MULADDC_CORE
        MULADDC_CORE   MULADDC_CORE
        MULADDC_STOP
    }

    for( ; i > 0; i-- )
    {
        MULADDC_INIT
        MULADDC_CORE
        MULADDC_STOP
    }
#endif /* MULADDC_HUIT */

    t++;

    do {
        *d += c; c = ( *d < c ); d++;
    }
    while( c != 0 );
}

/*
 * Baseline multiplication: X = A * B  (HAC 14.12)
 */
int shmpi_mul_mpi( shmpi *X, const shmpi *A, const shmpi *B )
{
    int ret;
    size_t i, j;
    shmpi TA, TB;

    shmpi_init( &TA ); shmpi_init( &TB );

    if( X == A ) { MPI_CHK( shmpi_copy( &TA, A ) ); A = &TA; }
    if( X == B ) { MPI_CHK( shmpi_copy( &TB, B ) ); B = &TB; }

    for( i = A->n; i > 0; i-- )
        if( A->p[i - 1] != 0 )
            break;

    for( j = B->n; j > 0; j-- )
        if( B->p[j - 1] != 0 )
            break;

    MPI_CHK( shmpi_grow( X, i + j ) );
    MPI_CHK( shmpi_lset( X, 0 ) );

    for( i++; j > 0; j-- )
        shmpi_mul_hlp( i - 1, A->p, X->p + j - 1, B->p[j - 1] );

    X->s = A->s * B->s;

cleanup:

    shmpi_free( &TB ); shmpi_free( &TA );

    return( ret );
}

/*
 * Baseline multiplication: X = A * b
 */
int shmpi_mul_int( shmpi *X, const shmpi *A, t_sint b )
{
    shmpi _mpi;
    t_uint p[1];

    _mpi.s = 1;
    _mpi.n = 1;
    _mpi.p = p;
    p[0] = b;

    return( shmpi_mul_mpi( X, A, &_mpi ) );
}

/*
 * Division by shmpi: A = Q * B + R  (HAC 14.20)
 */
int shmpi_div_mpi( shmpi *Q, shmpi *R, const shmpi *A, const shmpi *B )
{
    int ret;
    size_t i, n, t, k;
    shmpi X, Y, Z, T1, T2;

    if( shmpi_cmp_int( B, 0 ) == 0 )
        return( SHMPI_ERR_DIVISION_BY_ZERO );

    shmpi_init( &X ); shmpi_init( &Y ); shmpi_init( &Z );
    shmpi_init( &T1 ); shmpi_init( &T2 );

    if( shmpi_cmp_abs( A, B ) < 0 )
    {
        if( Q != NULL ) MPI_CHK( shmpi_lset( Q, 0 ) );
        if( R != NULL ) MPI_CHK( shmpi_copy( R, A ) );
        return( 0 );
    }

    MPI_CHK( shmpi_copy( &X, A ) );
    MPI_CHK( shmpi_copy( &Y, B ) );
    X.s = Y.s = 1;

    MPI_CHK( shmpi_grow( &Z, A->n + 2 ) );
    MPI_CHK( shmpi_lset( &Z,  0 ) );
    MPI_CHK( shmpi_grow( &T1, 2 ) );
    MPI_CHK( shmpi_grow( &T2, 3 ) );

    k = shmpi_msb( &Y ) % biL;
    if( k < biL - 1 )
    {
        k = biL - 1 - k;
        MPI_CHK( shmpi_shift_l( &X, k ) );
        MPI_CHK( shmpi_shift_l( &Y, k ) );
    }
    else k = 0;

    n = X.n - 1;
    t = Y.n - 1;
    MPI_CHK( shmpi_shift_l( &Y, biL * ( n - t ) ) );

    while( shmpi_cmp_mpi( &X, &Y ) >= 0 )
    {
        Z.p[n - t]++;
        MPI_CHK( shmpi_sub_mpi( &X, &X, &Y ) );
    }
    MPI_CHK( shmpi_shift_r( &Y, biL * ( n - t ) ) );

    for( i = n; i > t ; i-- )
    {
        if( X.p[i] >= Y.p[t] )
            Z.p[i - t - 1] = ~0;
        else
        {
#if defined(MPI_HAVE_UDBL)
            t_udbl r;

            r  = (t_udbl) X.p[i] << biL;
            r |= (t_udbl) X.p[i - 1];
            r /= Y.p[t];
            if( r > ( (t_udbl) 1 << biL ) - 1 )
                r = ( (t_udbl) 1 << biL ) - 1;

            Z.p[i - t - 1] = (t_uint) r;
#else
            /*
             * __udiv_qrnnd_c, from gmp/longlong.h
             */
            t_uint q0, q1, r0, r1;
            t_uint d0, d1, d, m;

            d  = Y.p[t];
            d0 = ( d << biH ) >> biH;
            d1 = ( d >> biH );

            q1 = X.p[i] / d1;
            r1 = X.p[i] - d1 * q1;
            r1 <<= biH;
            r1 |= ( X.p[i - 1] >> biH );

            m = q1 * d0;
            if( r1 < m )
            {
                q1--, r1 += d;
                while( r1 >= d && r1 < m )
                    q1--, r1 += d;
            }
            r1 -= m;

            q0 = r1 / d1;
            r0 = r1 - d1 * q0;
            r0 <<= biH;
            r0 |= ( X.p[i - 1] << biH ) >> biH;

            m = q0 * d0;
            if( r0 < m )
            {
                q0--, r0 += d;
                while( r0 >= d && r0 < m )
                    q0--, r0 += d;
            }
            r0 -= m;

            Z.p[i - t - 1] = ( q1 << biH ) | q0;
#endif /* MPI_HAVE_UDBL && !64-bit Apple with Clang 5.0 */
        }

        Z.p[i - t - 1]++;
        do
        {
            Z.p[i - t - 1]--;

            MPI_CHK( shmpi_lset( &T1, 0 ) );
            T1.p[0] = ( t < 1 ) ? 0 : Y.p[t - 1];
            T1.p[1] = Y.p[t];
            MPI_CHK( shmpi_mul_int( &T1, &T1, Z.p[i - t - 1] ) );

            MPI_CHK( shmpi_lset( &T2, 0 ) );
            T2.p[0] = ( i < 2 ) ? 0 : X.p[i - 2];
            T2.p[1] = ( i < 1 ) ? 0 : X.p[i - 1];
            T2.p[2] = X.p[i];
        }
        while( shmpi_cmp_mpi( &T1, &T2 ) > 0 );

        MPI_CHK( shmpi_mul_int( &T1, &Y, Z.p[i - t - 1] ) );
        MPI_CHK( shmpi_shift_l( &T1,  biL * ( i - t - 1 ) ) );
        MPI_CHK( shmpi_sub_mpi( &X, &X, &T1 ) );

        if( shmpi_cmp_int( &X, 0 ) < 0 )
        {
            MPI_CHK( shmpi_copy( &T1, &Y ) );
            MPI_CHK( shmpi_shift_l( &T1, biL * ( i - t - 1 ) ) );
            MPI_CHK( shmpi_add_mpi( &X, &X, &T1 ) );
            Z.p[i - t - 1]--;
        }
    }

    if( Q != NULL )
    {
        MPI_CHK( shmpi_copy( Q, &Z ) );
        Q->s = A->s * B->s;
    }

    if( R != NULL )
    {
        MPI_CHK( shmpi_shift_r( &X, k ) );
        X.s = A->s;
        MPI_CHK( shmpi_copy( R, &X ) );

        if( shmpi_cmp_int( R, 0 ) == 0 )
            R->s = 1;
    }

cleanup:

    shmpi_free( &X ); shmpi_free( &Y ); shmpi_free( &Z );
    shmpi_free( &T1 ); shmpi_free( &T2 );

    return( ret );
}

/*
 * Division by int: A = Q * b + R
 */
int shmpi_div_int( shmpi *Q, shmpi *R, const shmpi *A, t_sint b )
{
    shmpi _mpi;
    t_uint p[1];

    p[0] = ( b < 0 ) ? -b : b;
    _mpi.s = ( b < 0 ) ? -1 : 1;
    _mpi.n = 1;
    _mpi.p = p;

    return( shmpi_div_mpi( Q, R, A, &_mpi ) );
}

/*
 * Modulo: R = A mod B
 */
int shmpi_mod_mpi( shmpi *R, const shmpi *A, const shmpi *B )
{
    int ret;

    if( shmpi_cmp_int( B, 0 ) < 0 )
        return( SHMPI_ERR_NEGATIVE_VALUE );

    MPI_CHK( shmpi_div_mpi( NULL, R, A, B ) );

    while( shmpi_cmp_int( R, 0 ) < 0 )
      MPI_CHK( shmpi_add_mpi( R, R, B ) );

    while( shmpi_cmp_mpi( R, B ) >= 0 )
      MPI_CHK( shmpi_sub_mpi( R, R, B ) );

cleanup:

    return( ret );
}

/*
 * Modulo: r = A mod b
 */
int shmpi_mod_int( t_uint *r, const shmpi *A, t_sint b )
{
    size_t i;
    t_uint x, y, z;

    if( b == 0 )
        return( SHMPI_ERR_DIVISION_BY_ZERO );

    if( b < 0 )
        return( SHMPI_ERR_NEGATIVE_VALUE );

    /*
     * handle trivial cases
     */
    if( b == 1 )
    {
        *r = 0;
        return( 0 );
    }

    if( b == 2 )
    {
        *r = A->p[0] & 1;
        return( 0 );
    }

    /*
     * general case
     */
    for( i = A->n, y = 0; i > 0; i-- )
    {
        x  = A->p[i - 1];
        y  = ( y << biH ) | ( x >> biH );
        z  = y / b;
        y -= z * b;

        x <<= biH;
        y  = ( y << biH ) | ( x >> biH );
        z  = y / b;
        y -= z * b;
    }

    /*
     * If A is negative, then the current y represents a negative value.
     * Flipping it to the positive side.
     */
    if( A->s < 0 && y != 0 )
        y = b - y;

    *r = y;

    return( 0 );
}

/*
 * Fast Montgomery initialization (thanks to Tom St Denis)
 */
static void shmpi_montg_init( t_uint *mm, const shmpi *N )
{
    t_uint x, m0 = N->p[0];
    unsigned int i;

    x  = m0;
    x += ( ( m0 + 2 ) & 4 ) << 1;

    for( i = biL; i >= 8; i /= 2 )
        x *= ( 2 - ( m0 * x ) );

    *mm = ~x + 1;
}

/*
 * Montgomery multiplication: A = A * B * R^-1 mod N  (HAC 14.36)
 */
static void shmpi_montmul( shmpi *A, const shmpi *B, const shmpi *N, t_uint mm,
                         const shmpi *T )
{
    size_t i, n, m;
    t_uint u0, u1, *d;

    memset( T->p, 0, T->n * ciL );

    d = T->p;
    n = N->n;
    m = ( B->n < n ) ? B->n : n;

    for( i = 0; i < n; i++ )
    {
        /*
         * T = (T + u0*B + u1*N) / 2^biL
         */
        u0 = A->p[i];
        u1 = ( d[0] + u0 * B->p[0] ) * mm;

        shmpi_mul_hlp( m, B->p, d, u0 );
        shmpi_mul_hlp( n, N->p, d, u1 );

        *d++ = u0; d[n + 1] = 0;
    }

    memcpy( A->p, d, ( n + 1 ) * ciL );

    if( shmpi_cmp_abs( A, N ) >= 0 )
        shmpi_sub_hlp( n, N->p, A->p );
    else
        /* prevent timing attacks */
        shmpi_sub_hlp( n, A->p, T->p );
}

/*
 * Montgomery reduction: A = A * R^-1 mod N
 */
static void shmpi_montred( shmpi *A, const shmpi *N, t_uint mm, const shmpi *T )
{
    t_uint z = 1;
    shmpi U;

    U.n = U.s = (int) z;
    U.p = &z;

    shmpi_montmul( A, &U, N, mm, T );
}

/*
 * Sliding-window exponentiation: X = A^E mod N  (HAC 14.85)
 */
int shmpi_exp_mod( shmpi *X, const shmpi *A, const shmpi *E, const shmpi *N, shmpi *_RR )
{
    int ret;
    size_t wbits, wsize, one = 1;
    size_t i, j, nblimbs;
    size_t bufsize, nbits;
    t_uint ei, mm, state;
    shmpi RR, T, W[ 2 << MPI_MPI_WINDOW_SIZE ], Apos;
    int neg;

    if( shmpi_cmp_int( N, 0 ) < 0 || ( N->p[0] & 1 ) == 0 )
        return( SHMPI_ERR_BAD_INPUT_DATA );

    if( shmpi_cmp_int( E, 0 ) < 0 )
        return( SHMPI_ERR_BAD_INPUT_DATA );

    /*
     * Init temps and window size
     */
    shmpi_montg_init( &mm, N );
    shmpi_init( &RR ); shmpi_init( &T );
    shmpi_init( &Apos );
    memset( W, 0, sizeof( W ) );

    i = shmpi_msb( E );

    wsize = ( i > 671 ) ? 6 : ( i > 239 ) ? 5 :
            ( i >  79 ) ? 4 : ( i >  23 ) ? 3 : 1;

    if( wsize > MPI_MPI_WINDOW_SIZE )
        wsize = MPI_MPI_WINDOW_SIZE;

    j = N->n + 1;
    MPI_CHK( shmpi_grow( X, j ) );
    MPI_CHK( shmpi_grow( &W[1],  j ) );
    MPI_CHK( shmpi_grow( &T, j * 2 ) );

    /*
     * Compensate for negative A (and correct at the end)
     */
    neg = ( A->s == -1 );
    if( neg )
    {
        MPI_CHK( shmpi_copy( &Apos, A ) );
        Apos.s = 1;
        A = &Apos;
    }

    /*
     * If 1st call, pre-compute R^2 mod N
     */
    if( _RR == NULL || _RR->p == NULL )
    {
        MPI_CHK( shmpi_lset( &RR, 1 ) );
        MPI_CHK( shmpi_shift_l( &RR, N->n * 2 * biL ) );
        MPI_CHK( shmpi_mod_mpi( &RR, &RR, N ) );

        if( _RR != NULL )
            memcpy( _RR, &RR, sizeof( shmpi ) );
    }
    else
        memcpy( &RR, _RR, sizeof( shmpi ) );

    /*
     * W[1] = A * R^2 * R^-1 mod N = A * R mod N
     */
    if( shmpi_cmp_mpi( A, N ) >= 0 )
        MPI_CHK( shmpi_mod_mpi( &W[1], A, N ) );
    else
        MPI_CHK( shmpi_copy( &W[1], A ) );

    shmpi_montmul( &W[1], &RR, N, mm, &T );

    /*
     * X = R^2 * R^-1 mod N = R mod N
     */
    MPI_CHK( shmpi_copy( X, &RR ) );
    shmpi_montred( X, N, mm, &T );

    if( wsize > 1 )
    {
        /*
         * W[1 << (wsize - 1)] = W[1] ^ (wsize - 1)
         */
        j =  one << ( wsize - 1 );

        MPI_CHK( shmpi_grow( &W[j], N->n + 1 ) );
        MPI_CHK( shmpi_copy( &W[j], &W[1]    ) );

        for( i = 0; i < wsize - 1; i++ )
            shmpi_montmul( &W[j], &W[j], N, mm, &T );

        /*
         * W[i] = W[i - 1] * W[1]
         */
        for( i = j + 1; i < ( one << wsize ); i++ )
        {
            MPI_CHK( shmpi_grow( &W[i], N->n + 1 ) );
            MPI_CHK( shmpi_copy( &W[i], &W[i - 1] ) );

            shmpi_montmul( &W[i], &W[1], N, mm, &T );
        }
    }

    nblimbs = E->n;
    bufsize = 0;
    nbits   = 0;
    wbits   = 0;
    state   = 0;

    while( 1 )
    {
        if( bufsize == 0 )
        {
            if( nblimbs == 0 )
                break;

            nblimbs--;

            bufsize = sizeof( t_uint ) << 3;
        }

        bufsize--;

        ei = (E->p[nblimbs] >> bufsize) & 1;

        /*
         * skip leading 0s
         */
        if( ei == 0 && state == 0 )
            continue;

        if( ei == 0 && state == 1 )
        {
            /*
             * out of window, square X
             */
            shmpi_montmul( X, X, N, mm, &T );
            continue;
        }

        /*
         * add ei to current window
         */
        state = 2;

        nbits++;
        wbits |= ( ei << ( wsize - nbits ) );

        if( nbits == wsize )
        {
            /*
             * X = X^wsize R^-1 mod N
             */
            for( i = 0; i < wsize; i++ )
                shmpi_montmul( X, X, N, mm, &T );

            /*
             * X = X * W[wbits] R^-1 mod N
             */
            shmpi_montmul( X, &W[wbits], N, mm, &T );

            state--;
            nbits = 0;
            wbits = 0;
        }
    }

    /*
     * process the remaining bits
     */
    for( i = 0; i < nbits; i++ )
    {
        shmpi_montmul( X, X, N, mm, &T );

        wbits <<= 1;

        if( ( wbits & ( one << wsize ) ) != 0 )
            shmpi_montmul( X, &W[1], N, mm, &T );
    }

    /*
     * X = A^E * R * R^-1 mod N = A^E mod N
     */
    shmpi_montred( X, N, mm, &T );

    if( neg )
    {
        X->s = -1;
        MPI_CHK( shmpi_add_mpi( X, N, X ) );
    }

cleanup:

    for( i = ( one << ( wsize - 1 ) ); i < ( one << wsize ); i++ )
        shmpi_free( &W[i] );

    shmpi_free( &W[1] ); shmpi_free( &T ); shmpi_free( &Apos );

    if( _RR == NULL || _RR->p == NULL )
        shmpi_free( &RR );

    return( ret );
}

/*
 * Greatest common divisor: G = gcd(A, B)  (HAC 14.54)
 */
int shmpi_gcd( shmpi *G, const shmpi *A, const shmpi *B )
{
    int ret;
    size_t lz, lzt;
    shmpi TG, TA, TB;

    shmpi_init( &TG ); shmpi_init( &TA ); shmpi_init( &TB );

    MPI_CHK( shmpi_copy( &TA, A ) );
    MPI_CHK( shmpi_copy( &TB, B ) );

    lz = shmpi_lsb( &TA );
    lzt = shmpi_lsb( &TB );

    if( lzt < lz )
        lz = lzt;

    MPI_CHK( shmpi_shift_r( &TA, lz ) );
    MPI_CHK( shmpi_shift_r( &TB, lz ) );

    TA.s = TB.s = 1;

    while( shmpi_cmp_int( &TA, 0 ) != 0 )
    {
        MPI_CHK( shmpi_shift_r( &TA, shmpi_lsb( &TA ) ) );
        MPI_CHK( shmpi_shift_r( &TB, shmpi_lsb( &TB ) ) );

        if( shmpi_cmp_mpi( &TA, &TB ) >= 0 )
        {
            MPI_CHK( shmpi_sub_abs( &TA, &TA, &TB ) );
            MPI_CHK( shmpi_shift_r( &TA, 1 ) );
        }
        else
        {
            MPI_CHK( shmpi_sub_abs( &TB, &TB, &TA ) );
            MPI_CHK( shmpi_shift_r( &TB, 1 ) );
        }
    }

    MPI_CHK( shmpi_shift_l( &TB, lz ) );
    MPI_CHK( shmpi_copy( G, &TB ) );

cleanup:

    shmpi_free( &TG ); shmpi_free( &TA ); shmpi_free( &TB );

    return( ret );
}

/*
 * Fill X with size bytes of random.
 *
 * Use a temporary bytes representation to make sure the result is the same
 * regardless of the platform endianness (useful when f_rng is actually
 * deterministic, eg for tests).
 */
int shmpi_fill_random( shmpi *X, size_t size,
                     int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng )
{
    int ret;
    unsigned char buf[MPI_MPI_MAX_SIZE];

    if( size > MPI_MPI_MAX_SIZE )
        return( SHMPI_ERR_BAD_INPUT_DATA );

    MPI_CHK( f_rng( p_rng, buf, size ) );
    MPI_CHK( shmpi_read_binary( X, buf, size ) );

cleanup:
    return( ret );
}

/*
 * Modular inverse: X = A^-1 mod N  (HAC 14.61 / 14.64)
 */
int shmpi_inv_mod( shmpi *X, const shmpi *A, const shmpi *N )
{
    int ret;
    shmpi G, TA, TU, U1, U2, TB, TV, V1, V2;

    if( shmpi_cmp_int( N, 0 ) <= 0 )
        return( SHMPI_ERR_BAD_INPUT_DATA );

    shmpi_init( &TA ); shmpi_init( &TU ); shmpi_init( &U1 ); shmpi_init( &U2 );
    shmpi_init( &G ); shmpi_init( &TB ); shmpi_init( &TV );
    shmpi_init( &V1 ); shmpi_init( &V2 );

    MPI_CHK( shmpi_gcd( &G, A, N ) );

    if( shmpi_cmp_int( &G, 1 ) != 0 )
    {
        ret = SHMPI_ERR_NOT_ACCEPTABLE;
        goto cleanup;
    }

    MPI_CHK( shmpi_mod_mpi( &TA, A, N ) );
    MPI_CHK( shmpi_copy( &TU, &TA ) );
    MPI_CHK( shmpi_copy( &TB, N ) );
    MPI_CHK( shmpi_copy( &TV, N ) );

    MPI_CHK( shmpi_lset( &U1, 1 ) );
    MPI_CHK( shmpi_lset( &U2, 0 ) );
    MPI_CHK( shmpi_lset( &V1, 0 ) );
    MPI_CHK( shmpi_lset( &V2, 1 ) );

    do
    {
        while( ( TU.p[0] & 1 ) == 0 )
        {
            MPI_CHK( shmpi_shift_r( &TU, 1 ) );

            if( ( U1.p[0] & 1 ) != 0 || ( U2.p[0] & 1 ) != 0 )
            {
                MPI_CHK( shmpi_add_mpi( &U1, &U1, &TB ) );
                MPI_CHK( shmpi_sub_mpi( &U2, &U2, &TA ) );
            }

            MPI_CHK( shmpi_shift_r( &U1, 1 ) );
            MPI_CHK( shmpi_shift_r( &U2, 1 ) );
        }

        while( ( TV.p[0] & 1 ) == 0 )
        {
            MPI_CHK( shmpi_shift_r( &TV, 1 ) );

            if( ( V1.p[0] & 1 ) != 0 || ( V2.p[0] & 1 ) != 0 )
            {
                MPI_CHK( shmpi_add_mpi( &V1, &V1, &TB ) );
                MPI_CHK( shmpi_sub_mpi( &V2, &V2, &TA ) );
            }

            MPI_CHK( shmpi_shift_r( &V1, 1 ) );
            MPI_CHK( shmpi_shift_r( &V2, 1 ) );
        }

        if( shmpi_cmp_mpi( &TU, &TV ) >= 0 )
        {
            MPI_CHK( shmpi_sub_mpi( &TU, &TU, &TV ) );
            MPI_CHK( shmpi_sub_mpi( &U1, &U1, &V1 ) );
            MPI_CHK( shmpi_sub_mpi( &U2, &U2, &V2 ) );
        }
        else
        {
            MPI_CHK( shmpi_sub_mpi( &TV, &TV, &TU ) );
            MPI_CHK( shmpi_sub_mpi( &V1, &V1, &U1 ) );
            MPI_CHK( shmpi_sub_mpi( &V2, &V2, &U2 ) );
        }
    }
    while( shmpi_cmp_int( &TU, 0 ) != 0 );

    while( shmpi_cmp_int( &V1, 0 ) < 0 )
        MPI_CHK( shmpi_add_mpi( &V1, &V1, N ) );

    while( shmpi_cmp_mpi( &V1, N ) >= 0 )
        MPI_CHK( shmpi_sub_mpi( &V1, &V1, N ) );

    MPI_CHK( shmpi_copy( X, &V1 ) );

cleanup:

    shmpi_free( &TA ); shmpi_free( &TU ); shmpi_free( &U1 ); shmpi_free( &U2 );
    shmpi_free( &G ); shmpi_free( &TB ); shmpi_free( &TV );
    shmpi_free( &V1 ); shmpi_free( &V2 );

    return( ret );
}

/* gen prime */
static const int small_prime[] =
{
        3,    5,    7,   11,   13,   17,   19,   23,
       29,   31,   37,   41,   43,   47,   53,   59,
       61,   67,   71,   73,   79,   83,   89,   97,
      101,  103,  107,  109,  113,  127,  131,  137,
      139,  149,  151,  157,  163,  167,  173,  179,
      181,  191,  193,  197,  199,  211,  223,  227,
      229,  233,  239,  241,  251,  257,  263,  269,
      271,  277,  281,  283,  293,  307,  311,  313,
      317,  331,  337,  347,  349,  353,  359,  367,
      373,  379,  383,  389,  397,  401,  409,  419,
      421,  431,  433,  439,  443,  449,  457,  461,
      463,  467,  479,  487,  491,  499,  503,  509,
      521,  523,  541,  547,  557,  563,  569,  571,
      577,  587,  593,  599,  601,  607,  613,  617,
      619,  631,  641,  643,  647,  653,  659,  661,
      673,  677,  683,  691,  701,  709,  719,  727,
      733,  739,  743,  751,  757,  761,  769,  773,
      787,  797,  809,  811,  821,  823,  827,  829,
      839,  853,  857,  859,  863,  877,  881,  883,
      887,  907,  911,  919,  929,  937,  941,  947,
      953,  967,  971,  977,  983,  991,  997, -103
};

/*
 * Small divisors test (X must be positive)
 *
 * Return values:
 * 0: no small factor (possible prime, more tests needed)
 * 1: certain prime
 * SHMPI_ERR_NOT_ACCEPTABLE: certain non-prime
 * other negative: error
 */
static int shmpi_check_small_factors( const shmpi *X )
{
    int ret = 0;
    size_t i;
    t_uint r;

    if( ( X->p[0] & 1 ) == 0 )
        return( SHMPI_ERR_NOT_ACCEPTABLE );

    for( i = 0; small_prime[i] > 0; i++ )
    {
        if( shmpi_cmp_int( X, small_prime[i] ) <= 0 )
            return( 1 );

        MPI_CHK( shmpi_mod_int( &r, X, small_prime[i] ) );

        if( r == 0 )
            return( SHMPI_ERR_NOT_ACCEPTABLE );
    }

cleanup:
    return( ret );
}

/*
 * Miller-Rabin pseudo-primality test  (HAC 4.24)
 */
static int shmpi_miller_rabin( const shmpi *X,
                             int (*f_rng)(void *, unsigned char *, size_t),
                             void *p_rng )
{
    int ret, count;
    size_t i, j, k, n, s;
    shmpi W, R, T, A, RR;

    shmpi_init( &W ); shmpi_init( &R ); shmpi_init( &T ); shmpi_init( &A );
    shmpi_init( &RR );

    /*
     * W = |X| - 1
     * R = W >> lsb( W )
     */
    MPI_CHK( shmpi_sub_int( &W, X, 1 ) );
    s = shmpi_lsb( &W );
    MPI_CHK( shmpi_copy( &R, &W ) );
    MPI_CHK( shmpi_shift_r( &R, s ) );

    i = shmpi_msb( X );
    /*
     * HAC, table 4.4
     */
    n = ( ( i >= 1300 ) ?  2 : ( i >=  850 ) ?  3 :
          ( i >=  650 ) ?  4 : ( i >=  350 ) ?  8 :
          ( i >=  250 ) ? 12 : ( i >=  150 ) ? 18 : 27 );

    for( i = 0; i < n; i++ )
    {
        /*
         * pick a random A, 1 < A < |X| - 1
         */

        count = 0;
        do {
            MPI_CHK( shmpi_fill_random( &A, X->n * ciL, f_rng, p_rng ) );

            j = shmpi_msb( &A );
            k = shmpi_msb( &W );
            if (j > k) {
                MPI_CHK( shmpi_shift_r( &A, j - k ) );
            }

            if (count++ > 30) {
                return SHMPI_ERR_NOT_ACCEPTABLE;
            }

        } while ( (shmpi_cmp_mpi( &A, &W ) >= 0) ||
                  (shmpi_cmp_int( &A, 1 )  <= 0)    );

        /*
         * A = A^R mod |X|
         */
        MPI_CHK( shmpi_exp_mod( &A, &A, &R, X, &RR ) );

        if( shmpi_cmp_mpi( &A, &W ) == 0 ||
            shmpi_cmp_int( &A,  1 ) == 0 )
            continue;

        j = 1;
        while( j < s && shmpi_cmp_mpi( &A, &W ) != 0 )
        {
            /*
             * A = A * A mod |X|
             */
            MPI_CHK( shmpi_mul_mpi( &T, &A, &A ) );
            MPI_CHK( shmpi_mod_mpi( &A, &T, X  ) );

            if( shmpi_cmp_int( &A, 1 ) == 0 )
                break;

            j++;
        }

        /*
         * not prime if A != |X| - 1 or A == 1
         */
        if( shmpi_cmp_mpi( &A, &W ) != 0 ||
            shmpi_cmp_int( &A,  1 ) == 0 )
        {
            ret = SHMPI_ERR_NOT_ACCEPTABLE;
            break;
        }
    }

cleanup:
    shmpi_free( &W ); shmpi_free( &R ); shmpi_free( &T ); shmpi_free( &A );
    shmpi_free( &RR );

    return( ret );
}

/*
 * Pseudo-primality test: small factors, then Miller-Rabin
 */
int shmpi_is_prime( shmpi *X,
                  int (*f_rng)(void *, unsigned char *, size_t),
                  void *p_rng )
{
    int ret;
    shmpi XX;

    XX.s = 1;
    XX.n = X->n;
    XX.p = X->p;

    if( shmpi_cmp_int( &XX, 0 ) == 0 ||
        shmpi_cmp_int( &XX, 1 ) == 0 )
        return( SHMPI_ERR_NOT_ACCEPTABLE );

    if( shmpi_cmp_int( &XX, 2 ) == 0 )
        return( 0 );

    if( ( ret = shmpi_check_small_factors( &XX ) ) != 0 )
    {
        if( ret == 1 )
            return( 0 );

        return( ret );
    }

    return( shmpi_miller_rabin( &XX, f_rng, p_rng ) );
}

/*
 * Prime number generation
 */
int shmpi_gen_prime( shmpi *X, size_t nbits, int dh_flag,
                   int (*f_rng)(void *, unsigned char *, size_t),
                   void *p_rng )
{
    int ret;
    size_t k, n;
    t_uint r;
    shmpi Y;

    if( nbits < 3 || nbits > MPI_MPI_MAX_BITS )
        return( SHMPI_ERR_BAD_INPUT_DATA );

    shmpi_init( &Y );

    n = BITS_TO_LIMBS( nbits );

    MPI_CHK( shmpi_fill_random( X, n * ciL, f_rng, p_rng ) );

    k = shmpi_msb( X );
    if( k > nbits ) MPI_CHK( shmpi_shift_r( X, k - nbits + 1 ) );

    shmpi_set_bit( X, nbits-1, 1 );

    X->p[0] |= 1;

    if( dh_flag == 0 )
    {
        while( ( ret = shmpi_is_prime( X, f_rng, p_rng ) ) != 0 )
        {
            if( ret != SHMPI_ERR_NOT_ACCEPTABLE )
                goto cleanup;

            MPI_CHK( shmpi_add_int( X, X, 2 ) );
        }
    }
    else
    {
        /*
         * An necessary condition for Y and X = 2Y + 1 to be prime
         * is X = 2 mod 3 (which is equivalent to Y = 2 mod 3).
         * Make sure it is satisfied, while keeping X = 3 mod 4
         */

        X->p[0] |= 2;

        MPI_CHK( shmpi_mod_int( &r, X, 3 ) );
        if( r == 0 )
            MPI_CHK( shmpi_add_int( X, X, 8 ) );
        else if( r == 1 )
            MPI_CHK( shmpi_add_int( X, X, 4 ) );

        /* Set Y = (X-1) / 2, which is X / 2 because X is odd */
        MPI_CHK( shmpi_copy( &Y, X ) );
        MPI_CHK( shmpi_shift_r( &Y, 1 ) );

        while( 1 )
        {
            /*
             * First, check small factors for X and Y
             * before doing Miller-Rabin on any of them
             */
            if( ( ret = shmpi_check_small_factors(  X         ) ) == 0 &&
                ( ret = shmpi_check_small_factors( &Y         ) ) == 0 &&
                ( ret = shmpi_miller_rabin(  X, f_rng, p_rng  ) ) == 0 &&
                ( ret = shmpi_miller_rabin( &Y, f_rng, p_rng  ) ) == 0 )
            {
                break;
            }

            if( ret != SHMPI_ERR_NOT_ACCEPTABLE )
                goto cleanup;

            /*
             * Next candidates. We want to preserve Y = (X-1) / 2 and
             * Y = 1 mod 2 and Y = 2 mod 3 (eq X = 3 mod 4 and X = 2 mod 3)
             * so up Y by 6 and X by 12.
             */
            MPI_CHK( shmpi_add_int(  X,  X, 12 ) );
            MPI_CHK( shmpi_add_int( &Y, &Y, 6  ) );
        }
    }

cleanup:

    shmpi_free( &Y );

    return( ret );
}

/* Count leading zero bits in a given integer */
static size_t _clz(const t_uint x)
{
  size_t j;
  t_uint mask = (t_uint) 1 << (biL - 1);

  for( j = 0; j < biL; j++ )
  {
    if( x & mask ) break;

    mask >>= 1;
  }

  return j;
}

/**
 * @returns The the number of bits.
 */
size_t shmpi_bitlen( const shmpi *X )
{
  size_t i, j;

  if( X->n == 0 )
    return( 0 );

  for( i = X->n - 1; i > 0; i-- )
    if( X->p[i] != 0 )
      break;

  j = biL - _clz( X->p[i] );

  return( ( i * biL ) + j );
}








#define GCD_PAIR_COUNT  3
static const int gcd_pairs[GCD_PAIR_COUNT][3] =
{
    { 693, 609, 21 },
    { 1764, 868, 28 },
    { 768454923, 542167814, 1 }
};
_TEST(shmpi)
{
  int ret, i;
  shmpi A, E, N, X, Y, U, V;

  shmpi_init( &A ); shmpi_init( &E ); shmpi_init( &N ); shmpi_init( &X );
  shmpi_init( &Y ); shmpi_init( &U ); shmpi_init( &V );

  _TRUE(0 == shmpi_read_string( &A, 16, "EFE021C2645FD1DC586E69184AF4A31E" "D5F53E93B5F123FA41680867BA110131" "944FE7952E2517337780CB0DB80E61AA" "E7C8DDC6C5C6AADEB34EB38A2F40D5E6" ) );

  _TRUE(0 == shmpi_read_string( &E, 16, "B2E7EFD37075B9F03FF989C7C5051C20" "34D2A323810251127E7BF8625A4F49A5" "F3E27F4DA8BD59C47D6DAABA4C8127BD" "5B5C25763222FEFCCFC38B832366C29E" ) );

  _TRUE(0 == shmpi_read_string( &N, 16, "0066A198186C18C10B2F5ED9B522752A" "9830B69916E535C8F047518A889A43A5" "94B6BED27A168D31D4A52F88925AA8F5" ) );

  _TRUE(0 == shmpi_mul_mpi( &X, &A, &N ) );

  _TRUE(0 == shmpi_read_string( &U, 16, "602AB7ECA597A3D6B56FF9829A5E8B85" "9E857EA95A03512E2BAE7391688D264A" "A5663B0341DB9CCFD2C4C5F421FEC814" "8001B72E848A38CAE1C65F78E56ABDEF" "E12D3C039B8A02D6BE593F0BBBDA56F1" "ECF677152EF804370C1A305CAF3B5BF1" "30879B56C61DE584A0F53A2447A51E" ) );

  _TRUE(0 == shmpi_cmp_mpi( &X, &U ));

  _TRUE(0 == shmpi_div_mpi( &X, &Y, &A, &N ) );

  _TRUE(0 == shmpi_read_string( &U, 16,
        "256567336059E52CAE22925474705F39A94" ) );

  _TRUE(0 == shmpi_read_string( &V, 16, "6613F26162223DF488E9CD48CC132C7A" "0AC93C701B001B092E4E5B9F73BCD27B" "9EE50D0657C77F374E903CDFA4C642" ) );

  _TRUE(0 == shmpi_cmp_mpi( &X, &U ));
  _TRUE(0 == shmpi_cmp_mpi( &Y, &V ));

  _TRUE(0 == shmpi_exp_mod( &X, &A, &E, &N, NULL ));

  _TRUE(0 == shmpi_read_string( &U, 16, "36E139AEA55215609D2816998ED020BB" "BD96C37890F65171D948E9BC7CBAA4D9" "325D24D6A3C12710F10A09FA08AB87" ));

  _TRUE(0 == shmpi_cmp_mpi( &X, &U ));

  _TRUE(0 == shmpi_inv_mod( &X, &A, &N ));

  _TRUE(0 == shmpi_read_string( &U, 16, "003A0AAEDD7E784FC07D8F9EC6E3BFD5" "C3DBA76456363A10869622EAC2DD84EC" "C5B8A74DAC4D09E03B5E0BE779F2DF61" ));

  _TRUE(0 == shmpi_cmp_mpi( &X, &U ));

  for( i = 0; i < GCD_PAIR_COUNT; i++ ) {
    _TRUE(0 == shmpi_lset( &X, gcd_pairs[i][0] ));
    _TRUE(0 == shmpi_lset( &Y, gcd_pairs[i][1] ));

    _TRUE(0 == shmpi_gcd( &A, &X, &Y ) );

    _TRUE(0 == shmpi_cmp_int( &A, gcd_pairs[i][2] ));
  }
}


