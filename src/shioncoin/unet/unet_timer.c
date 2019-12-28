
/*
 * @copyright
 *
 *  Copyright 2015 Brian Burrell
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



/**
 * Add a new work procedure.
 * @note Called once per second.
 */
int unet_timer_set(int mode, unet_op timer_f)
{
  unet_bind_t *bind;

  bind = unet_bind_table(mode);
  if (!bind)
    return (SHERR_INVAL);

  if (bind->peer_db) {
    bc_idle(bind->peer_db);
  }

  bind->timer_stamp = shtime();
  bind->op_timer = timer_f;

  return(0);
}

void unet_timer_unset(int mode)
{
  unet_bind_t *bind;

  bind = unet_bind_table(mode);
  if (!bind)
    return;

  bind->timer_stamp = 0;
  bind->op_timer = NULL;

}

void unet_timer_cycle_mode(unet_bind_t *bind)
{
  shtime_t min_t;
  shtime_t now;
  shtime_t ts;

	if (!bind)
		return;

	if (!bind->op_timer)
		return;

	/* call work procedure */
	bind->timer_stamp = now;
	(*bind->op_timer)();
}

/**
 * Call any timer procedures that have not already this second.
 */
void unet_timer_cycle(void)
{
  unet_bind_t *bind;
  int idx;

  for (idx = 0; idx < MAX_UNET_MODES; idx++) {
		bind = unet_bind_table(idx);
		unet_timer_cycle_mode(bind);
	}

}


