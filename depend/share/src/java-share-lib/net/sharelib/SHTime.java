
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

import java.math.BigInteger;

public class SHTime
{

  protected BigInteger time;

  public SHTime()
  {
    time = share_java.shtime();
  }
  public SHTime(long sys_ms)
  {
    set(sys_ms);
  }

  public void add(double seconds)
  {
    time = share_java.shtime_adj(time, seconds);
  }

  public void sub(double seconds)
  {
    time = share_java.shtime_adj(time, -seconds);
  }

  public BigInteger getTime()
  {
    return (time);
  }

  /**
   * Convert a SHTime into an epoch unix-style timestamp.
   */
  public long unixTime()
  {
    return (share_java.shutime(this.time));
  }

  public long sysTime()
  {
    long t = share_java.shutime(this.time); /* unix time */
    t = (t * 1000) + share_java.shtimems(this.time); /* add ms */
    return (t);
  }

  /**
   * Set the share time-stamp to a java system time-stamp. 
   */
  public void set(long sys_ms)
  {
    long t = sys_ms / 1000;
    /* establish time from unix epoch stamp */
    time = share_java.shtimeu(t);
    /* add milliseconds */
    time = share_java.shtime_adj(time, (double)(sys_ms % 1000) / 1000);
  }

  public void set(BigInteger t)
  {
    time = t;
  }

  /**
   * Provides a string representation of the time given a unix-style time format specification.
   * @note Example format is "%m/%d/%y %Y-%m-%d" for date and time.
   * @see strftime()
   */
  public String format(String fmt)
  {
    return (share_java.shstrtime(time, fmt));
  }

  /**
   * Print the time being represented in a standard format.
   */
  public String toString()
  {
    return (share_java.shctime(this.time));
  }

  static public SHTime valueOf(long sys_ms)
  {
    return (new SHTime(sys_ms));
  }

}
