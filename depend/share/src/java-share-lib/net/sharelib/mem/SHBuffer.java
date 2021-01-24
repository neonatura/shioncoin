
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

public class SHBuffer
{

  protected SWIGTYPE_p_shbuf_t buffer;
  protected byte[] _data;
  private byte[] _single = new byte[1];

  public SHBuffer()
  {
    buffer = share_java.shbuf_init(); 
  }

  public SHBuffer(SWIGTYPE_p_shbuf_t buffer)
  {
    this.buffer = buffer;
  }

  public int size()
  {
    return ((int)share_java.shbuf_size(buffer));
  }

  /**
   * Print the buffer being represented in a plain text format. 
   */
  public String getText()
  {
    return (new String(getBytes()));
  }

  /**
   * Print the buffer being represented in a binary format.
   */
  public byte[] getBytes()
  {

    if (_data == null) {
      _data = new byte[size()]; 
      share_java.shbuf_memcpy(buffer, _data);
    }

    return (_data);
  }

  public void append(String text)
  {
    _data = null;
    share_java.shbuf_catstr(buffer, text); 
  }

  public void append(byte[] data)
  {
    _data = null;
    share_java.shbuf_cat(buffer, data);
  }

  public void append(byte val)
  {
    _single[0] = val;
    append(_single);
  }

  public void append(char val)
  {
    _single[0] = (byte)val;
    append(_single);
  }

  /**
   * Clear the contents of the buffer.
   */
  public void clear()
  {
    _data = null;
    share_java.shbuf_clear(buffer);
  }

  /**
   * Remove a segment from the end of the buffer.
   */
  public void truncate(long len)
  {
    _data = null;
    share_java.shbuf_truncate(buffer, len);
  }

  /**
   * Remove a segment from the beginning of the buffer.
   */
  public void trim(long len)
  {
    _data = null;
    share_java.shbuf_trim(buffer, len);
  }

  /**
   * Obtain a byte from the given offset of the buffer.
   */
  public byte read(long off)
  {
    byte[] data = getBytes();

    if (off < 0 || off >= data.length) {
      throw new IndexOutOfBoundsException("index out of range");
    }

    return (data[(int)off]);
  }

  /**
   * Print the buffer being represented in a standard format.
   */
  public String toString()
  {
    return (getText());
  }

  public void finalize() throws Throwable /* Object */ 
  {
    share_java.shbuf_dealloc(buffer); 
    super.finalize();
  }

  protected Object clone()
  {
    SWIGTYPE_p_shbuf_t clone_obj = share_java.shbuf_clone(buffer);
    return (new SHBuffer(clone_obj)); 
  }

}


