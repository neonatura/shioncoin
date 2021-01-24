
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

package net.sharelib.fs;

import net.sharelib.*;
import net.sharelib.mem.*;

public class SHInode
{

  public SHInode(SWIGTYPE_p_shfs_ino_t inode)
  {
    this.inode = inode;

    this.parent = share_java.shfs_inode_parent(inode);
    this.name = share_java.shfs_filename(inode);
    this.type = share_java.shfs_type(inode);
  }
  public SHInode(SHInode parent, String name, int type)
  {
    this.parent = parent.getInode();
    this.name = name;
    this.type = type;

    this.inode = share_java.shfs_inode(this.parent, name, type);
  }

  public SHInode load(SHInode parent, SHKey key)
  {
    return (new SHInode(share_java.shfs_inode_load(parent.getInode(), key.getKey())));
  }

  public SWIGTYPE_p_shfs_ino_t getInode()
  {
    return (inode);
  }

  /**
   * Print the inode being represented in a standard format.
   */
  public String toString()
  {
    return (super.toString());
  }

  public void finalize() throws Throwable /* Object */ 
  {
    super.finalize();
  }

  protected String name;
  protected int type;
  protected SWIGTYPE_p_shfs_ino_t parent;
  protected SWIGTYPE_p_shfs_ino_t inode;
}


