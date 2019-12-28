
/*
 * @copyright
 *
 *  Copyright 2016 Brian Burrell
 *
 *  This file is part of Shioncoin.
 *  (https://github.com/neonatura/shioncoin)
 *        
 *  ShionCoin is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version. 
 *
 *  ShionCoin is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with ShionCoin.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  @endcopyright
 */  

#include "shcoind.h"

#ifdef linux
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#endif


void bc_mutex_init(bc_t *bc)
{
	if (!bc) return;
#ifdef USE_LIBPTHREAD
	pthread_mutexattr_t attr;

	/* initialize mutex attributes */
	memset(&attr, 0, sizeof(attr));
	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);

	/* initialize mutex */
	pthread_mutex_init(&bc->lk, &attr);
	pthread_mutexattr_destroy(&attr);
#endif
}

void bc_mutex_term(bc_t *bc)
{
	if (!bc) return;
#ifdef USE_LIBPTHREAD
	pthread_mutex_destroy(&bc->lk);
#endif
}

int bc_lock(bc_t *bc)
{

	if (!bc)
		return (TRUE); /* nothing to lock */

#ifdef USE_LIBPTHREAD
	if (0 != pthread_mutex_lock(&bc->lk))
		return (FALSE);
#endif

	return (TRUE);
}

int bc_trylock(bc_t *bc)
{

	if (!bc)
		return (TRUE); /* nothing to lock */

#ifdef USE_LIBPTHREAD
	if (0 != pthread_mutex_trylock(&bc->lk))
		return (FALSE);
#endif

	return (TRUE);
}

void bc_unlock(bc_t *bc)
{

	if (!bc)
		return;

#ifdef USE_LIBPTHREAD
	pthread_mutex_unlock(&bc->lk);
#endif
}

