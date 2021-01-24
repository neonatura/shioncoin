
/*
 * @copyright
 *
 *  Copyright 2015 Neo Natura 
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

package net.sharelib.mem;

import net.sharelib.*;

public class SHKey
{

  protected SWIGTYPE_p_shkey_t key;

  public SHKey(SWIGTYPE_p_shkey_t key)
  {
    this.key = key;
  }

  public SWIGTYPE_p_shkey_t getKey()
  {
    return (key);
  }

  /**
   * Print the buffer being represented in a standard format.
   */
  public String toString()
  {
    return (share_java.shkey_print(key));
  }

  public void finalize() throws Throwable /* Object */ 
  {
//    share_java.shkey_dealloc(key);
    super.finalize();
  }


}


