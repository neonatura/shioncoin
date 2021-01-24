
/*
 * @copyright
 *
 *  Copyright 2013 Neo Natura 
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

#ifndef __SHTIME_H__
#define __SHTIME_H__

#include <time.h>


/**
 * Time operations are performed in order to store and compare time metrics.
 * 
 * This library utilizes a 64-bit number in order to provide milli-second precision. The "shtime_t" value is stored in big-endian byte order, and can be copied directly to other (64-bit) computer platforms.
 * 
 * The "Epoch" for this time value starts at 01/01/2000 UTC. Use the shtimef() function in order to manage the time as a floating point value, or shutime() to convert to a standard unix-timevalue . You must use the underlying functions, such as shtimems() or shtime_diff(), to access the "shtime_t" value.
 * 
 * @ingroup libshare
 * @defgroup libshare_time System Time Routines
 * @{
 */

/* one hour in seconds */
#ifndef ONE_HOUR
#define ONE_HOUR 3600
#endif

/* indicates no time has been established */
#define SHTIME_UNDEFINED 0 /* htonl(0) */

/* 01/01/2000 UTC */
#define SHTIME_EPOCH (uint64_t)946684800 

/**
 * The libshare representation of a particular time.
 * @note Content is stored in network byte order.
 */
typedef uint64_t shtime_t;

/**
 * Generate A float-point precision representation of the specified time.
 * @returns An double representing the seconds since Year 2000 UTC.
 */
double shtimef(shtime_t stamp);

/**
 * Generate a 64bit representation integral of the current time with millisecond precision.
 * @returns An unsigned long representing the milliseconds since 200 UTC.
 * @note 32bit friendly.
 */
shtime_t shtime(void);

/**
 * Generate a 64bit 'libshare time-stamp' given a unix epoch value.
 */
shtime_t shtimeu(time_t unix_t);

/**
 * Obtain the milliseconds portion of the time specified.
 */
int shtimems(shtime_t t);

/**
 * Display full ISO 8601 format of date and time.
 */
char *shctime(shtime_t t);

/**
 * Convert a share library timestamp into a unix timestamp.
 */
time_t shutime(shtime_t t);

/**
 * Convert a libshare time-stamp into a string format.
 * @param fmt If NULL then "%x %X" will be used.
 * @note This function utilizes the same time tokens as strftime().
 */
char *shstrtime(shtime_t t, char *fmt);

/**
 * Adjust a libshare time-stamp by a degree of seconds.
 */
shtime_t shtime_adj(shtime_t stamp, double secs);

/**
 * convert a timeval into a libshare time-stamp
 */
shtime_t shgettime(struct timeval *tv);

/**
 * test whether a time is more recent than another time.
 */
int shtime_after(shtime_t stamp, shtime_t cmp_stamp);

/**
 * test whether a time is previous than another time.
 */
int shtime_before(shtime_t stamp, shtime_t cmp_stamp);

/**
 * convert a tm into a libshare time-stamp.
 */
shtime_t shmktime(struct tm *tm);

/**
 * Calculate the difference between two timestamps in seconds.
 */
double shtime_diff(shtime_t stamp, shtime_t cmp_stamp);

/**
 * @}
 */


#endif /* ndef __SHTIME_H__ */


