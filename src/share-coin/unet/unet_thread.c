
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

#include "shcoind.h"
#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif

/** A flag indicating that thread sub-system is currently running. */ 
#define UTHREAD_IDLE (1 << 0)

/** A flag indicating that the timer thread is currently running. */ 
#define UTHREAD_TIMER (1 << 1)

/** The maximum time permitted for a thread to sleep is 334ms (1/3 second). */
#define UTHREAD_MAX_TIME 0.334

void *unet_thread_timer(unet_bind_t *bind)
{
	static const double ONE_SEC = 1000000;
	shtime_t start_t;
	double wait_t;
	double idle_t;

	usleep(1000); /* 1ms */

	start_t = shtime();
	idle_t = UTHREAD_MAX_TIME;
	while (bind->fl_timer & UTHREAD_TIMER) {
		/* sleep based on activity load (>activity = <sleep) */
		wait_t = shtimef(shtime()) - shtimef(start_t);
		if (wait_t <= idle_t) {
			/* increase wait if activity takes less time */
			idle_t += 0.001;
		} else {
			/* decrease wait if activity takes longer time */
			idle_t /= 2;
		}
		idle_t = MAX(0.01, MIN(UTHREAD_MAX_TIME, idle_t));
		usleep((unsigned int)(idle_t * ONE_SEC));

		/* reset timer */
		start_t = shtime();

		/* call timer function for timer mode */
		unet_timer_cycle_mode(bind);
	}

	return (NULL);
}

/** Initialize the timer thread. */
void unet_thread_init(int mode)
{
#ifdef USE_LIBPTHREAD
	pthread_attr_t attr;
	unet_bind_t *bind;
	char buf[256];

	bind = unet_bind_table(mode);
	if (!bind)
		return;

	if ((bind->fl_timer & UTHREAD_IDLE))
		return; /* thread is already running */

	bind->fl_timer |= UTHREAD_IDLE;
	bind->fl_timer |= UTHREAD_TIMER;

	memset(&attr, 0, sizeof(attr));
	pthread_attr_init(&attr);
	(void)pthread_create(&bind->th_timer, &attr,
			UTHREAD(unet_thread_timer), bind);
	pthread_attr_destroy(&attr);

	/* debug: */
	sprintf(buf, "unet_thread_init: initialized thread #%x (port %d).", (unsigned int)pthread_self(), bind->port);
	unet_log(mode, buf);
#endif
}

/** Terminate the timer thread. */
void unet_thread_free(int mode)
{
#ifdef USE_LIBPTHREAD
	unet_bind_t *bind;
	void *ret_code;
	char buf[256];

	bind = unet_bind_table(mode);
	if (!bind)
		return;

	if (!(bind->fl_timer & UTHREAD_IDLE))
		return; /* thread is not running */

	/* disable all modes from running. */
	bind->fl_timer = 0;

	/* wait for thread to terminate */
	(void)pthread_join(bind->th_timer, &ret_code);

	/* debug: */
	sprintf(buf, "unet_thread_init: terminated thread #%x (port %d).", (unsigned int)pthread_self(), bind->port);
	unet_log(mode, buf);
#endif USE_LIBPTHREAD
}

