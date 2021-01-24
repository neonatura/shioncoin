
/*
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
 */  


#ifndef __SHARE_UTIL__SHARETOOL_REV_H__
#define __SHARE_UTIL__SHARETOOL_REV_H__

#define REV_NONE 0
#define REV_LOG 1
#define REV_CHECKOUT 2
#define REV_ADD 3
#define REV_DIFF 4
#define REV_COMMIT 5
#define REV_TAG 6
#define REV_BRANCH 7
#define REV_REVERT 8
#define REV_STATUS 9
#define REV_SWITCH 10
#define REV_CAT 11

struct revop_t
{
  /* the revision operation being performed. */
  int cmd;
  /* the revision's sharefs filesystem partition. */
  shfs_t *rev_fs;
  /* SHINODE_FILE record of repository */
  shfs_ino_t *rev_base;
  /* SHINODE_REVISION record of current revision. */
  shfs_ino_t *rev_cur;
  /* key name of current revision */
  shkey_t rev_kcur;
  /* hash string of current revision */
  char rev_hcur[MAX_SHARE_HASH_LENGTH];
};
typedef struct revop_t revop_t;



revop_t *rev_init(void);
void rev_command_setstr(revop_t *rev, char *cmd_str);

#endif /* ndef __SHARE_UTIL__SHARETOOL_REV_H__ */


