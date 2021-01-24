
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
 *  @file signature.h
 */

#ifndef __BITS__SIGNATURE_H__
#define __BITS__SIGNATURE_H__









/**
 * Sign a network transaction in reference to external data.
 * @param tx_sig Filled with the resulting signature.
 */
void tx_sign(tx_t *tx, shkey_t *tx_sig, shkey_t *context);

void tx_sign_context(tx_t *tx, shkey_t *tx_sig, void *data, size_t data_len);

/**
 * Confirm a network transaction signature in reference to external data.
 * @param tx_sig The signature to validate against.
 */
int tx_sign_confirm(tx_t *tx, shkey_t *tx_sig, shkey_t *context);

void tx_sign_confirm_context(tx_t *tx, shkey_t *tx_sig, void *data, size_t data_len);



#endif /* ndef __BITS__SIGNATURE_H__ */
