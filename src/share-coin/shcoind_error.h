
/*
 * @copyright
 *
 *  Copyright 2018 Neo Natura
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

#ifndef __SHCOIND_ERROR_H__
#define __SHCOIND_ERROR_H__

#ifdef __cplusplus
extern "C" {
#endif


/* reserved */
#define ERR_UNKNOWN -1

/* custom (non posix) errors */
#define ERR_MASK -1000
#define CUSTOM_ERROR(_code) \
	(ERR_MASK - (_code))

#define ERR_EXPIRE     CUSTOM_ERROR(1)
#define ERR_ENCODE     CUSTOM_ERROR(2)
#define ERR_FEE        CUSTOM_ERROR(3)
#define ERR_COMMIT     CUSTOM_ERROR(4)
#define ERR_NOCLASS    CUSTOM_ERROR(5)
#define ERR_NOMETHOD   CUSTOM_ERROR(6)

/* redundant (convienence) */
#define ERR_STALE ERR_EXPIRE

/**
 * A table mapping localized error codes to error messages.
 * @note All localized error codes are negative.
 */
typedef struct err_code_t
{
	int code;
	const char *label;
} err_code_t;


/* retrieve a string message for a local error code */
const char *error_str(int code);

/* convert a posix system error (errno) into a local error code */
int error_code(int err_no);


#ifdef __cplusplus
}
#endif

#endif /* ndef __SHCOIND_ERROR_H__ */


