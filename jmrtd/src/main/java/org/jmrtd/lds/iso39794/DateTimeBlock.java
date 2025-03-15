/*
 * JMRTD - A Java API for accessing machine readable travel documents.
 *
 * Copyright (C) 2006 - 2025  The JMRTD team
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * $Id$
 *
 * Based on ISO-IEC-39794-1-ed-1-v1. Disclaimer:
 * THE SCHEMA ON WHICH THIS SOFTWARE IS BASED IS PROVIDED BY THE COPYRIGHT
 * HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THE CODE COMPONENTS, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.jmrtd.lds.iso39794;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import org.bouncycastle.asn1.ASN1Encodable;
import org.jmrtd.ASN1Util;

public class DateTimeBlock extends Block {

  private static final long serialVersionUID = 2053705457048769663L;

  private int year;
  private int month;
  private int day;
  private int hour;
  private int minute;
  private int second;
  private int millisecond;

  public DateTimeBlock(int year, int month, int day, int hour, int minute, int second, int millisecond) {
    this.year = year;
    this.month = month;
    this.day = day;
    this.hour = hour;
    this.minute = minute;
    this.second = second;
    this.millisecond = millisecond;
  }

  //  DateTimeBlock ::= SEQUENCE {
  //    year          [0] Year,
  //    month         [1] Month          OPTIONAL,
  //    day           [2] Day            OPTIONAL,
  //    hour          [3] Hour           OPTIONAL,
  //    minute        [4] Minute         OPTIONAL,
  //    second        [5] Second         OPTIONAL,
  //    millisecond   [6] Millisecond    OPTIONAL
  //  }

  //  Year ::= INTEGER (0..9999)
  //
  //  Month ::= INTEGER (1..12)
  //
  //  Day ::= INTEGER (1..31)
  //
  //  Hour ::= INTEGER (0..23)
  //
  //  Minute ::= INTEGER (0..59)
  //
  //  Second ::= INTEGER (0..59)
  //
  //  Millisecond ::= INTEGER (0..999)

  DateTimeBlock(ASN1Encodable asn1Encodable) {
    Map<Integer, ASN1Encodable> taggedObjects = ASN1Util.decodeTaggedObjects(asn1Encodable);
    year = ASN1Util.decodeInt(taggedObjects.get(0));
    month = taggedObjects.containsKey(1) ? ASN1Util.decodeInt(taggedObjects.get(1)) : -1;
    day = taggedObjects.containsKey(2) ? ASN1Util.decodeInt(taggedObjects.get(2)) : -1;
    hour = taggedObjects.containsKey(3) ? ASN1Util.decodeInt(taggedObjects.get(3)) : -1;
    minute = taggedObjects.containsKey(4) ? ASN1Util.decodeInt(taggedObjects.get(4)) : -1;
    second = taggedObjects.containsKey(5) ? ASN1Util.decodeInt(taggedObjects.get(5)) : -1;
    millisecond = taggedObjects.containsKey(6) ? ASN1Util.decodeInt(taggedObjects.get(6)) : -1;
  }

  public int getYear() {
    return year;
  }

  public int getMonth() {
    return month;
  }

  public int getDay() {
    return day;
  }

  public int getHour() {
    return hour;
  }

  public int getMinute() {
    return minute;
  }

  public int getSecond() {
    return second;
  }

  public int getMillisecond() {
    return millisecond;
  }

  @Override
  public int hashCode() {
    return Objects.hash(day, hour, millisecond, minute, month, second, year);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null) {
      return false;
    }
    if (getClass() != obj.getClass()) {
      return false;
    }

    DateTimeBlock other = (DateTimeBlock) obj;
    return year == other.year
        && month == other.month
        && day == other.day
        && hour == other.hour
        && minute == other.minute
        && second == other.second
        && millisecond == other.millisecond;
  }

  @Override
  public String toString() {
    return "DateTimeBlock ["
        + "year: " + year
        + ", month: " + month
        + ", day: " + day
        + ", hour: " + hour
        + ", minute: " + minute
        + ", second: " + second
        + ", millisecond: " + millisecond
        + "]";
  }

  /* PACKAGE */

  @Override
  ASN1Encodable getASN1Object() {
    Map<Integer, ASN1Encodable> taggedObjects = new HashMap<Integer, ASN1Encodable>();
    taggedObjects.put(0,ASN1Util.encodeInt(year));
    if (month >= 0) { taggedObjects.put(1, ASN1Util.encodeInt(month)); }
    if (day >= 0) { taggedObjects.put(2, ASN1Util.encodeInt(day)); }
    if (hour >= 0) { taggedObjects.put(3, ASN1Util.encodeInt(hour)); }
    if (minute >= 0) { taggedObjects.put(4, ASN1Util.encodeInt(minute)); }
    if (second >= 0) { taggedObjects.put(5, ASN1Util.encodeInt(second)); }
    if (millisecond >= 0) { taggedObjects.put(6, ASN1Util.encodeInt(millisecond)); }
    return ASN1Util.encodeTaggedObjects(taggedObjects);
  }
}
