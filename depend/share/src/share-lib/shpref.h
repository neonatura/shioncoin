
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
 *
 *  @file shpref.h
 */

#ifndef __PREF__SHPREF_H__
#define __PREF__SHPREF_H__

/**
 * Handles management of user-specific configuration options for the Share Library.
 * @note See the shpref_sess_set() function for information on overwriting an option values for the current process session.
 * @brief Specify user specific configuration items.
 * @addtogroup libshare
 * @{
 */


/**
 * Indicates a positive boolean value.
 */
#define SHPREF_TRUE "true"

/**
 * Indicates a negative boolean value.
 */
#define SHPREF_FALSE "false"

/**
 * Specifies the preferred location of where the sharefs filesystem is stored on the local file system.
 * @note The default location is '$HOME/.share'.
 * @note Use @c shpref_sess_set() to temporarily overwrite this value.
 */
#define SHPREF_BASE_DIR "base-dir"
/**
 * Specifies whether to track sharefs filesystem revisions.
 * @note Use @c shpref_sess_set() to temporarily overwrite this value.
 */ 
#define SHPREF_TRACK "track"
/**
 * Specifies whether the sharefs file system references files on the local filesystem.
 * @note Use @c shpref_sess_set() to temporarily overwrite this value.
 */ 
#define SHPREF_OVERLAY "overlay"

/** The account name is typically comprised of an email address optionally followed by a real name in 'LAST/FIRST' format. */
#define SHPREF_ACC_NAME SHMETA_USER_EMAIL
/** A key reference to the user's account password. */
#define SHPREF_ACC_PASS SHMETA_USER_PASS
/** The salt used to perturb the account password key. */
#define SHPREF_ACC_SALT SHMETA_USER_SALT

#define SHPREF_ACC_GEO SHMETA_USER_GEO

/**
 * Specifies the number of preferences available.
 */
#define SHPREF_MAX 6

/**
 * Specified the maximum size of a share library global preference name.
 */
#define SHPREF_NAME_MAX 4096

/**
 * Specified the maximum size of a share library global preference value.
 */
#define SHPREF_VALUE_MAX 4096

/**
 * Specifies the preferred location of where the sharefs filesystem is stored on the local file system.
 * @returns The path to a directory on the local file-system.
 */
char *shpref_base_dir(void);

/**
 * Specifies whether to track sharefs filesystem revisions.
 * @returns A zero (0) when disabled and a non-zero value when enabled.
 */
#define shpref_track() \
  (0 == strcmp(shpref_get(SHPREF_TRACK), "true") ? TRUE : FALSE) 

/**
 * Permanently sets the @c SHPREF_TRACK option.
 * @param opt A zero to disable the option and a non-zero to enable.
 */
#define shpref_set_track(opt) \
  (opt ? shpref_set(SHPREF_TRACK, "true") : shpref_set(SHPREF_TRACK, "false"))

/**
 * Specifies whether to overlay the sharefs filesystem ontop of the work directory on the local filesystem.
 * @note Disable this option to prevent libshare from writing outside of the base directory.
 * @returns A zero (0) when disabled and a non-zero value when enabled.
 */
#define shpref_overlay() \
  (0 == strcmp(shpref_get(SHPREF_OVERLAY), "true") ? TRUE : FALSE) 

/**
 * Permanently sets the @c SHPREF_OVERLAY option.
 * @param opt A zero to disable the option and a non-zero to enable.
 */
#define shpref_set_overlay(opt) \
  (opt ? shpref_set(SHPREF_OVERLAY, "true") : shpref_set(SHPREF_OVERLAY, "false"))

/**
 * The local filesystem path for storing configuration options.
 * @returns The path to the location on the local file-system that contains user-specific libshare configuration options.
 */
char *shpref_path(int uid);

/**
 * Initialize an instance of configuration options in memory.
 * @note This function does not need to be called in order to retrieve or set configuration options.
 * @returns A zero (0) on success and a negative one (-1) on failure.
 */
int shpref_init(void);

/**
 * Free the configuration options loaded into memory.
 * @note This will remove all temporar configuration settings that have been made this process session.
 */
void shpref_free(void);

/**
 * Retrieve a configuration option value.
 * @param pref The name of the preference.
 * @param default_value The default string value to return if the preference is not set.
 * @returns The configuration option value.
 * @note This function is not thread-safe. 
 */
const char *shpref_get(char *pref, char *default_value);

/**
 * Set a persistent value for a particular libshare user-specific configuration option.
 *
 * Specify user specific configuration items:
 *  - SHPREF_BASE_DIR The base directory to store sharefs file data.
 *  - SHPREF_TRACK    Whether to automatically track file revisions. 
 *  - SHPREF_OVERLAY  Whether to write outside of the base directory.
 * @brief Set a configuration option value.
 * @param pref The name of the preference.
 * @param value The configuration option value.
 * @returns The configuration option value.
 */
int shpref_set(char *pref, char *value);

/**
 * Persistently unset a libshare configuration option.
 */
#define shpref_unset(pref) \
  shpref_set(pref, NULL)

/**
 * Overwrite a preference for the current session.
 */
#define shpref_sess_set(pref, value) \
  shmap_set_astr(_pref, ashkey_str(pref), value)

/**
 * Temporarily unset a libshare configuration option.
 */
#define shpref_sess_unset(pref) \
  shmap_unset(_pref, ashkey_str(pref))

/**
 * @}
 */

#endif /* ndef __PREF__SHPREF_H__ */

