
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

/**
 * Provides a channel to read bytes segments from a sharebuffer.
 */
public class SHBufferInputStream extends java.io.InputStream
{

  protected SHBuffer buff;
  protected long offset;
  protected long mark;

  public SHBufferInputStream(SHBuffer buff)
  {
    this.buff = buff;
  }

  /**
   * Returns an estimate of the number of bytes that can be read (or skipped over) from this input stream without blocking by the next invocation of a method for this input stream.
   */
  @Override public int available() /* InputStream */
  {
    return ((int)(buff.size() - offset));
  }

  /**
   * Reads the next byte of data from the input stream.
   */
  @Override public int read()
  {
    int ret_ch = (int)buff.read(offset);
    offset++;
    return (ret_ch);
  }

  @Override public long skip(long n)
  {
    long max = Math.max(offset + n, buff.size() - offset);
    offset += max;
    return (max);
  }

  /** Repositions this stream to the position at the time the mark method was last called on this input stream. */
  @Override public void reset() throws java.io.IOException
  {
    if (mark == -1)
      throw new java.io.IOException("stream has not been marked");
    if (mark >= buff.size())
      throw new java.io.IOException("mark is no longer valid");
    offset = mark;
  }

  /** Marks the current position in this input stream. */
  @Override public void mark(int readlimit)
  {
    mark = offset;
  }

  /** Tests if this input stream supports the mark and reset methods. */
  @Override public boolean markSupported()
  {
    return (true);
  }

  public SHBuffer getBuffer()
  {
    return (buff);
  }

}
