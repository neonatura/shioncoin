
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
*/  

#include "share.h"

int main(int argc, char **argv)
{
  char mode[4096];
  int err;

  memset(mode, 0, sizeof(mode));
  if (argc > 1)
    strncpy(mode, argv[1], sizeof(mode) - 1);
  err = shfs_proc_lock(argv[0], mode); 
  if (err) {
    fprintf(stderr, "%s [mode: %s]\n", sherrstr(err), mode);
    return (1);
  }

  sleep (5);

  return (0);
}



