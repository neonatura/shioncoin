
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
 *  @file sexe.h
 *  @brief Utilities to compile and run SEXE bytecode.
 *  @date 2014
 *
 */


#ifndef __SEXE__SYS__SYS_H__
#define __SEXE__SYS__SYS_H__

/**
 * @ingroup sexe
 * @defgroup sexe_sys Standard SEXE Libraries
 * @{
 */

#ifdef __cplusplus
extern "C" {
#endif


/** The sexe standard string library. */
LUAMOD_API int luaopen_string(sexe_t *L);

/** The sexe standard math library. */
LUAMOD_API int luaopen_math(sexe_t *L); 

/** The sexe standard time library. */
LUAMOD_API int luaopen_time(sexe_t *L);

/** The sexe standard crypt library. */
LUAMOD_API int luaopen_crypt(sexe_t *L); 

/** The sexe standard event library. */
LUAMOD_API int luaopen_event(sexe_t *L); 

void set_sexe_stdin(FILE *in);
void set_sexe_stdout(FILE *out);
void set_sexe_stderr(FILE *err);

FILE *get_sexe_stdin(void);
FILE *get_sexe_stdout(void);
FILE *get_sexe_stderr(void);


int lfunc_trigger_event(sexe_t *L);

/**
 * The "floor" mathematical operative rounds a number down to the nearest integer.
 * @note The first argument contains the number to round down. The second optional integral argument specifies a decimal point precision (power of ten) to round down to. For example, "round(3.3333, 2)" would return "3.33".
 */
int lfunc_sexe_math_floor(sexe_t *L); 


#ifdef __cplusplus
}
#endif

/**
 * @}
 */


#endif /* ndef __SEXE__SYS__SYS_H__ */

