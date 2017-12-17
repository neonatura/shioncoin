
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

#ifndef __SERVER__DERKEY_H__
#define __SERVER__DERKEY_H__

/* libsecp256k1 */
#include "secp256k1.h"
#include "secp256k1_recovery.h"

#ifdef __cplusplus
extern "C" {
#endif

void INIT_SECP256K1(void);

secp256k1_context *SECP256K1_VERIFY_CONTEXT(void);

secp256k1_context *SECP256K1_SIGN_CONTEXT(void);

void TERM_SECP256K1(void);


#ifdef __cplusplus
};
#endif


#endif /* ndef __SERVER__DERKEY_H__ */
