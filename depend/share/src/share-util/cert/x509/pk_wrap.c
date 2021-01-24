/*
 *  Public Key abstraction layer: wrapper functions
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

#if !defined(POLARSSL_CONFIG_FILE)
#include "polarssl/config.h"
#else
#include POLARSSL_CONFIG_FILE
#endif

#include "platform.h"
#include <stdlib.h>
#include <string.h>
#define polarssl_malloc     malloc
#define polarssl_free       free

#include "pk_wrap.h"

#if defined(POLARSSL_ECP_C)
#include "ecp.h"
#endif

#if defined(POLARSSL_ECDSA_C)
#include "ecdsa.h"
#endif


/* Implementation that should never be optimized out by the compiler */
static void polarssl_zeroize( void *v, size_t n ) {
    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
}

#if defined(POLARSSL_RSA_C)
static int shrsa_can_do( pk_type_t type )
{
    return( type == POLARSSL_PK_RSA ||
            type == POLARSSL_PK_RSASSA_PSS );
}

static size_t shrsa_get_size( const void *ctx )
{
    return( 8 * ((const shrsa_t *) ctx)->len );
}

static int shrsa_verify_wrap( void *ctx, shrsa_md_type_t md_alg,
                   const unsigned char *hash, size_t hash_len,
                   const unsigned char *sig, size_t sig_len )
{
    int ret;

    if( sig_len < ((shrsa_t *) ctx)->len )
        return( SHRSA_ERR_VERIFY_FAILED );

    if( ( ret = shrsa_pkcs1_verify( (shrsa_t *) ctx, NULL, NULL,
                                  SHRSA_PUBLIC, md_alg,
                                  (unsigned int) hash_len, hash, sig ) ) != 0 )
        return( ret );

    if( sig_len > ((shrsa_t *) ctx)->len )
        return( POLARSSL_ERR_PK_SIG_LEN_MISMATCH );

    return( 0 );
}

static int shrsa_sign_wrap( void *ctx, shrsa_md_type_t md_alg,
                   const unsigned char *hash, size_t hash_len,
                   unsigned char *sig, size_t *sig_len,
                   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    *sig_len = ((shrsa_t *) ctx)->len;

    return( shrsa_pkcs1_sign( (shrsa_t *) ctx, f_rng, p_rng, SHRSA_PRIVATE,
                md_alg, (unsigned int) hash_len, hash, sig ) );
}

static int shrsa_decrypt_wrap( void *ctx,
                    const unsigned char *input, size_t ilen,
                    unsigned char *output, size_t *olen, size_t osize,
                    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    if( ilen != ((shrsa_t *) ctx)->len )
        return( SHRSA_ERR_BAD_INPUT_DATA );

    return( shrsa_pkcs1_decrypt( (shrsa_t *) ctx, f_rng, p_rng,
                SHRSA_PRIVATE, olen, input, output, osize ) );
}

static int shrsa_encrypt_wrap( void *ctx,
                    const unsigned char *input, size_t ilen,
                    unsigned char *output, size_t *olen, size_t osize,
                    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    *olen = ((shrsa_t *) ctx)->len;

    if( *olen > osize )
        return( SHRSA_ERR_OUTPUT_TOO_LARGE );

    return( shrsa_pkcs1_encrypt( (shrsa_t *) ctx,
                f_rng, p_rng, SHRSA_PUBLIC, ilen, input, output ) );
}

static int shrsa_check_pair_wrap( const void *pub, const void *prv )
{
    return( shrsa_check_pub_priv( (const shrsa_t *) pub,
                                (const shrsa_t *) prv ) );
}

static void *shrsa_alloc_wrap( void )
{
    void *ctx = polarssl_malloc( sizeof( shrsa_t ) );

    if( ctx != NULL )
        shrsa_init( (shrsa_t *) ctx, 0, 0 );

    return( ctx );
}

static void shrsa_free_wrap( void *ctx )
{
    shrsa_free( (shrsa_t *) ctx );
    polarssl_free( ctx );
}

static void shrsa_debug( const void *ctx, pk_debug_item *items )
{
    items->type = POLARSSL_PK_DEBUG_MPI;
    items->name = "shrsa.N";
    items->value = &( ((shrsa_t *) ctx)->N );

    items++;

    items->type = POLARSSL_PK_DEBUG_MPI;
    items->name = "shrsa.E";
    items->value = &( ((shrsa_t *) ctx)->E );
}

const pk_info_t shrsa_info = {
    POLARSSL_PK_RSA,
    "RSA",
    shrsa_get_size,
    shrsa_can_do,
    shrsa_verify_wrap,
    shrsa_sign_wrap,
    shrsa_decrypt_wrap,
    shrsa_encrypt_wrap,
    shrsa_check_pair_wrap,
    shrsa_alloc_wrap,
    shrsa_free_wrap,
    shrsa_debug,
};
#endif /* POLARSSL_RSA_C */

#if defined(POLARSSL_ECP_C)
/*
 * Generic EC key
 */
static int eckey_can_do( pk_type_t type )
{
    return( type == POLARSSL_PK_ECKEY ||
            type == POLARSSL_PK_ECKEY_DH ||
            type == POLARSSL_PK_ECDSA );
}

static size_t eckey_get_size( const void *ctx )
{
    return( ((ecp_keypair *) ctx)->grp.pbits );
}

#if defined(POLARSSL_ECDSA_C)
/* Forward declarations */
static int ecdsa_verify_wrap( void *ctx, shrsa_md_type_t md_alg,
                       const unsigned char *hash, size_t hash_len,
                       const unsigned char *sig, size_t sig_len );

static int ecdsa_sign_wrap( void *ctx, shrsa_md_type_t md_alg,
                   const unsigned char *hash, size_t hash_len,
                   unsigned char *sig, size_t *sig_len,
                   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

static int eckey_verify_wrap( void *ctx, shrsa_md_type_t md_alg,
                       const unsigned char *hash, size_t hash_len,
                       const unsigned char *sig, size_t sig_len )
{
    int ret;
    ecdsa_context ecdsa;

    ecdsa_init( &ecdsa );

    if( ( ret = ecdsa_from_keypair( &ecdsa, ctx ) ) == 0 )
        ret = ecdsa_verify_wrap( &ecdsa, md_alg, hash, hash_len, sig, sig_len );

    ecdsa_free( &ecdsa );

    return( ret );
}

static int eckey_sign_wrap( void *ctx, shrsa_md_type_t md_alg,
                   const unsigned char *hash, size_t hash_len,
                   unsigned char *sig, size_t *sig_len,
                   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    int ret;
    ecdsa_context ecdsa;

    ecdsa_init( &ecdsa );

    if( ( ret = ecdsa_from_keypair( &ecdsa, ctx ) ) == 0 )
        ret = ecdsa_sign_wrap( &ecdsa, md_alg, hash, hash_len, sig, sig_len,
                               f_rng, p_rng );

    ecdsa_free( &ecdsa );

    return( ret );
}

#endif /* POLARSSL_ECDSA_C */

static int eckey_check_pair( const void *pub, const void *prv )
{
    return( ecp_check_pub_priv( (const ecp_keypair *) pub,
                                (const ecp_keypair *) prv ) );
}

static void *eckey_alloc_wrap( void )
{
    void *ctx = polarssl_malloc( sizeof( ecp_keypair ) );

    if( ctx != NULL )
        ecp_keypair_init( ctx );

    return( ctx );
}

static void eckey_free_wrap( void *ctx )
{
    ecp_keypair_free( (ecp_keypair *) ctx );
    polarssl_free( ctx );
}

static void eckey_debug( const void *ctx, pk_debug_item *items )
{
    items->type = POLARSSL_PK_DEBUG_ECP;
    items->name = "eckey.Q";
    items->value = &( ((ecp_keypair *) ctx)->Q );
}

const pk_info_t eckey_info = {
    POLARSSL_PK_ECKEY,
    "EC",
    eckey_get_size,
    eckey_can_do,
#if defined(POLARSSL_ECDSA_C)
    eckey_verify_wrap,
    eckey_sign_wrap,
#else
    NULL,
    NULL,
#endif
    NULL,
    NULL,
    eckey_check_pair,
    eckey_alloc_wrap,
    eckey_free_wrap,
    eckey_debug,
};

/*
 * EC key restricted to ECDH
 */
static int eckeydh_can_do( pk_type_t type )
{
    return( type == POLARSSL_PK_ECKEY ||
            type == POLARSSL_PK_ECKEY_DH );
}

const pk_info_t eckeydh_info = {
    POLARSSL_PK_ECKEY_DH,
    "EC_DH",
    eckey_get_size,         /* Same underlying key structure */
    eckeydh_can_do,
    NULL,
    NULL,
    NULL,
    NULL,
    eckey_check_pair,
    eckey_alloc_wrap,       /* Same underlying key structure */
    eckey_free_wrap,        /* Same underlying key structure */
    eckey_debug,            /* Same underlying key structure */
};
#endif /* POLARSSL_ECP_C */

#if defined(POLARSSL_ECDSA_C)
static int ecdsa_can_do( pk_type_t type )
{
    return( type == POLARSSL_PK_ECDSA );
}

static int ecdsa_verify_wrap( void *ctx, shrsa_md_type_t md_alg,
                       const unsigned char *hash, size_t hash_len,
                       const unsigned char *sig, size_t sig_len )
{
    int ret;
    ((void) md_alg);

    ret = ecdsa_read_signature( (ecdsa_context *) ctx,
                                hash, hash_len, sig, sig_len );

    if( ret == POLARSSL_ERR_ECP_SIG_LEN_MISMATCH )
        return( POLARSSL_ERR_PK_SIG_LEN_MISMATCH );

    return( ret );
}

static int ecdsa_sign_wrap( void *ctx, shrsa_md_type_t md_alg,
                   const unsigned char *hash, size_t hash_len,
                   unsigned char *sig, size_t *sig_len,
                   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    /* Use deterministic ECDSA by default if available */
#if defined(POLARSSL_ECDSA_DETERMINISTIC)
    ((void) f_rng);
    ((void) p_rng);

    return( ecdsa_write_signature_det( (ecdsa_context *) ctx,
                hash, hash_len, sig, sig_len, md_alg ) );
#else
    ((void) md_alg);

    return( ecdsa_write_signature( (ecdsa_context *) ctx,
                hash, hash_len, sig, sig_len, f_rng, p_rng ) );
#endif /* POLARSSL_ECDSA_DETERMINISTIC */
}

static void *ecdsa_alloc_wrap( void )
{
    void *ctx = polarssl_malloc( sizeof( ecdsa_context ) );

    if( ctx != NULL )
        ecdsa_init( (ecdsa_context *) ctx );

    return( ctx );
}

static void ecdsa_free_wrap( void *ctx )
{
    ecdsa_free( (ecdsa_context *) ctx );
    polarssl_free( ctx );
}

const pk_info_t ecdsa_info = {
    POLARSSL_PK_ECDSA,
    "ECDSA",
    eckey_get_size,     /* Compatible key structures */
    ecdsa_can_do,
    ecdsa_verify_wrap,
    ecdsa_sign_wrap,
    NULL,
    NULL,
    eckey_check_pair,   /* Compatible key structures */
    ecdsa_alloc_wrap,
    ecdsa_free_wrap,
    eckey_debug,        /* Compatible key structures */
};
#endif /* POLARSSL_ECDSA_C */

/*
 * Support for alternative RSA-private implementations
 */

static int shrsa_alt_can_do( pk_type_t type )
{
    return( type == POLARSSL_PK_RSA );
}

static size_t shrsa_alt_get_size( const void *ctx )
{
    const shrsa_alt_context *shrsa_alt = (const shrsa_alt_context *) ctx;

    return( 8 * shrsa_alt->key_len_func( shrsa_alt->key ) );
}

static int shrsa_alt_sign_wrap( void *ctx, shrsa_md_type_t md_alg,
                   const unsigned char *hash, size_t hash_len,
                   unsigned char *sig, size_t *sig_len,
                   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    shrsa_alt_context *shrsa_alt = (shrsa_alt_context *) ctx;

    *sig_len = shrsa_alt->key_len_func( shrsa_alt->key );

    return( shrsa_alt->sign_func( shrsa_alt->key, f_rng, p_rng, SHRSA_PRIVATE,
                md_alg, (unsigned int) hash_len, hash, sig ) );
}

static int shrsa_alt_decrypt_wrap( void *ctx,
                    const unsigned char *input, size_t ilen,
                    unsigned char *output, size_t *olen, size_t osize,
                    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    shrsa_alt_context *shrsa_alt = (shrsa_alt_context *) ctx;

    ((void) f_rng);
    ((void) p_rng);

    if( ilen != shrsa_alt->key_len_func( shrsa_alt->key ) )
        return( SHRSA_ERR_BAD_INPUT_DATA );

    return( shrsa_alt->decrypt_func( shrsa_alt->key,
                SHRSA_PRIVATE, olen, input, output, osize ) );
}

#if defined(POLARSSL_RSA_C)
static int shrsa_alt_check_pair( const void *pub, const void *prv )
{
    unsigned char sig[MPI_MPI_MAX_SIZE];
    unsigned char hash[32];
    size_t sig_len = 0;
    int ret;

    if( shrsa_alt_get_size( prv ) != shrsa_get_size( pub ) )
        return( SHRSA_ERR_KEY_CHECK_FAILED );

    memset( hash, 0x2a, sizeof( hash ) );

    if( ( ret = shrsa_alt_sign_wrap( (void *) prv, SHRSA_MD_NONE,
                                   hash, sizeof( hash ),
                                   sig, &sig_len, NULL, NULL ) ) != 0 )
    {
        return( ret );
    }

    if( shrsa_verify_wrap( (void *) pub, SHRSA_MD_NONE,
                         hash, sizeof( hash ), sig, sig_len ) != 0 )
    {
        return( SHRSA_ERR_KEY_CHECK_FAILED );
    }

    return( 0 );
}
#endif /* POLARSSL_RSA_C */

static void *shrsa_alt_alloc_wrap( void )
{
    void *ctx = polarssl_malloc( sizeof( shrsa_alt_context ) );

    if( ctx != NULL )
        memset( ctx, 0, sizeof( shrsa_alt_context ) );

    return( ctx );
}

static void shrsa_alt_free_wrap( void *ctx )
{
    polarssl_zeroize( ctx, sizeof( shrsa_alt_context ) );
    polarssl_free( ctx );
}

const pk_info_t shrsa_alt_info = {
    POLARSSL_PK_RSA_ALT,
    "RSA-alt",
    shrsa_alt_get_size,
    shrsa_alt_can_do,
    NULL,
    shrsa_alt_sign_wrap,
    shrsa_alt_decrypt_wrap,
    NULL,
#if defined(POLARSSL_RSA_C)
    shrsa_alt_check_pair,
#else
    NULL,
#endif
    shrsa_alt_alloc_wrap,
    shrsa_alt_free_wrap,
    NULL,
};

