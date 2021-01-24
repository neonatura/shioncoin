
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

package net.sharelib;

import java.util.zip.Checksum;
import java.math.BigInteger;

public class SHCRC64 extends Number implements Checksum
{

  protected BigInteger value;

  public SHCRC64()
  {
    reset();
  }

  /** Returns the current checksum crc. */
  public long getValue()
  {
    return (longValue());
  }

  /** Resets the checksum to its initial crc. */
  @Override public void reset() /* Checksum */
  {
    byte data[] = new byte[0];
    value = share_java.shcrc(data);
  }

  /** Updates the current checksum with the specified array of bytes. */
  public void update(byte[] b, int off, int len) /* Checksum */
  {
    byte[] data;
    int i;

    if (off+len < 0)
      throw new IndexOutOfBoundsException("index is not valid");

    data = new byte[len-off];
    for (i = 0; i < len; i++)
      data[i] = b[off+i];

    /* add new content to existing value. */
    value.add(share_java.shcrc(data));
  }

  /** Updates the current checksum with the specified array of bytes. */
  public void update(int b) /* Checksum */
  {
    _single[0] = (byte)b;
    /* add new content to existing value. */
    value.add(share_java.shcrc(_single));
  }

  public void set(long num)
  {
    value = BigInteger.valueOf(num);
  }

  public void set(String text)
  {
    value = share_java.shcrcgen(text);
  }

  @Override public String toString() /* Object */
  {
    return (share_java.shcrcstr(value));
  }

  /** Returns the value of the checksum as a double. */
  @Override public double doubleValue() /* Number */
  {
    return (value.doubleValue());
  }

  /** Returns the value of the checksum as a float. */
  @Override public float floatValue() /* Number */
  {
    return (value.floatValue());
  }

  /** Returns the value of the checksum as an int. */
  @Override public int intValue() /* Number */
  {
    return (value.intValue());
  }

  /** Returns the value of the checksum as a long. */
  @Override public long longValue() /* Number */
  {
    return (value.longValue());
  }

  static private byte[] _single = new byte[1];

}

