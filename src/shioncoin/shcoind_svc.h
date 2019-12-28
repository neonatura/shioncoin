
/*
 * @copyright
 *
 *  Copyright 2017 Brian Burrell
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

#ifndef __SHCOIND_SVC_H__	
#define __SHCOIND_SVC_H__

/*
 * SRV_NAME --
 *
 *	Specifies the internal name for your service.  This should contain
 *	no spaces or special characters.
 *
 */

#define SRV_NAME		"shcoind"

/*
 * SRV_DISPLAY_NAME --
 *
 *	This is the display name for your service - the human-readable form
 *	of SRV_NAME.
 */

#define SRV_DISPLAY_NAME	"ShionCoin"

/*
 * SRV_START_TYPE --
 *
 *	For the Windows NT Service Control Manager, you can specify whether
 *	your service should be automatically started when the system boots,
 *	or if it should simply be registered in the list of services available
 *	to be manually started by the user.  To start at boot time, set this to
 *  SERVICE_AUTO_START.  To make it NOT start at boot time, and thus must be
 *  manually started each time, set this to SERVICE_DEMAND_START.
 *
 *  This program doesn't depend on any others, so we can start automatically
 */
#define SRV_START_TYPE		SERVICE_AUTO_START

/*
 * SRV_STOP_SIGNAL --
 *
 *	Define this as the name of a valid signal which will be sent to your
 *	service when it is requested to shut down.  If your service already
 *	uses a specific signal to handle a shutdown request, use that here.
 *	If this definition conflicts with a signal you are already using,
 *	you can change this to any signal that does not conflict with one
 *	you are using.  If your service doesn't require any cleanup, you can
 *	just leave this alone.  A default handler will be provided which
 *	will cause your service to shut down properly.
 */
#define SRV_STOP_SIGNAL		SIGTERM

/*
 * SRV_MAX_STOP_TIME --
 *
 *	This specifies the maximum time (in seconds) that the service control
 *	manager will wait for your service to shut down gracefully before
 *	it gets shut down forcefully.  Change this as needed.
 */
#define SRV_MAX_STOP_TIME	15

/*******************
 * OPTIONAL MACROS
 * The following are macros that can be defined/modified, but for the most
 * part will probably not really be needed.
 *******************/


/*
 * SRV_USAGE_FUNCTION --
 *
 *	Define this to provide a usage/help function that can be called from
 *	the service's default usage function.  The prototype for the usage
 *	function is:
 *
 *		void SRV_USAGE_FUNCTION(void);
 *
 *	If your usage function is 'usage()', you would make this definition
 *
 *		#define SRV_USAGE_FUNCTION	usage
 *
 *	This macro is optional.
 *
 *  CADNT:  for cad programs that have a usage() function, define this to be
 *  that function.
 */
#define SRV_USAGE_FUNCTION usage_help

/*
 * SRV_CLEANUP_FUNCTION --
 *
 *	Define this to provide a cleanup function to be called when the
 *	service gets shut down.  This isn't needed if you have your own
 *	signal handler for the signal defined in SRV_STOP_SIGNAL, or if your
 *	service has no cleanup tasks to perform.  The prototype for this
 *	function is:
 *
 *		void SRV_CLEANUP_FUNCTION(void);
 *
 *	If your cleanup function is 'cleanup()', you would make this definition
 *
 *		#define SRV_CLEANUP_FUNCTION	cleanup
 *
 *	This macro is optional.
 *
 *  CADNT:  As long as we trap SRV_STOP_SIGNAL within the regular program, 
 *  this variable is unneeded.
 */

/*
#define SRV_CLEANUP_FUNCTION
*/

/*******************
 * UNTOUCHABLE MACROS
 * These macros are pre-defined and should not be modified under most
 * circumstances.
 *******************/

/*
 * SRV_MAIN_FUNCTION --
 *
 *	Define this as the name of the main() function for your service.
 *	This will be called after service initialization is complete.  The
 *	prototype for the main function is:
 *
 *		int SRV_MAIN_FUNCTION(int argc, char **argv, char **envp);
 *
 *	If your main function is 'user_main()', you would make this definition
 *
 *		#define SRV_MAIN_FUNCTION	user_main
 *
 *	This macro must be defined.
 *  CADNT:  This is arbitrarily defined to be cad_prog_main.  No real reason
 *  to change this.
 */
#define SRV_MAIN_FUNCTION	shcoind_main

/*
 * SRV_DEPENDENCIES --
 *
 *	This is the list of services which must start before yours on
 *	Windows NT.  There is little science to this.  If your service
 *	depends on networking, you probably want to add 'tcpip\0' to the
 *	start of this list.
 *
 */
#define SRV_DEPENDENCIES	"tcpip\0\0"

#endif /* __SHCOIND_SVC_H__ */	
