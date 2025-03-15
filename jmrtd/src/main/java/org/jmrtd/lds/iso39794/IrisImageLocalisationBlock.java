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
 * Based on ISO-IEC-39794-6-ed-1-v1. Disclaimer:
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

public class IrisImageLocalisationBlock extends Block {

  private static final long serialVersionUID = 3352687403941493410L;

  private int irisCenterXSmallest;
  private int irisCenterXLargest;

  private int irisCenterYSmallest;
  private int irisCenterYLargest;

  private int irisDiameterSmallest;
  private int irisDiameterLargest;


  //  Coordinate ::=  INTEGER (1..65535)
  //  Diameter ::=    INTEGER (1..65535)

  //  LocalisationBlock ::= SEQUENCE {
  //    irisCenterXSmallest [0]                 Coordinate                                      OPTIONAL,
  //    irisCenterXLargest [1]                  Coordinate                                      OPTIONAL,
  //    irisCenterYSmallest [2]                 Coordinate                                      OPTIONAL,
  //    irisCenterYLargest [3]                  Coordinate                                      OPTIONAL,
  //    irisDiameterSmallest [4]                Diameter                                        OPTIONAL,
  //    irisDiameterLargest [5]                 Diameter                                        OPTIONAL
  //  }

  public IrisImageLocalisationBlock(ASN1Encodable asn1Encodable) {
    Map<Integer, ASN1Encodable> taggedObjects = ASN1Util.decodeTaggedObjects(asn1Encodable);
    if (taggedObjects.containsKey(0)) {
      irisCenterXSmallest = ASN1Util.decodeInt(taggedObjects.get(0));
    }
    if (taggedObjects.containsKey(1)) {
      irisCenterXLargest = ASN1Util.decodeInt(taggedObjects.get(1));
    }
    if (taggedObjects.containsKey(2)) {
      irisCenterYSmallest = ASN1Util.decodeInt(taggedObjects.get(2));
    }

    if (taggedObjects.containsKey(3)) {
      irisCenterYLargest = ASN1Util.decodeInt(taggedObjects.get(3));
    }

    if (taggedObjects.containsKey(4)) {
      irisDiameterSmallest = ASN1Util.decodeInt(taggedObjects.get(4));
    }

    if (taggedObjects.containsKey(5)) {
      irisDiameterLargest = ASN1Util.decodeInt(taggedObjects.get(5));
    }
  }

  public int getIrisCenterXSmallest() {
    return irisCenterXSmallest;
  }


  public int getIrisCenterXLargest() {
    return irisCenterXLargest;
  }


  public int getIrisCenterYSmallest() {
    return irisCenterYSmallest;
  }


  public int getIrisCenterYLargest() {
    return irisCenterYLargest;
  }


  public int getIrisDiameterSmallest() {
    return irisDiameterSmallest;
  }


  public int getIrisDiameterLargest() {
    return irisDiameterLargest;
  }

  @Override
  public int hashCode() {
    return Objects.hash(irisCenterXLargest, irisCenterXSmallest, irisCenterYLargest, irisCenterYSmallest,
        irisDiameterLargest, irisDiameterSmallest);
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

    IrisImageLocalisationBlock other = (IrisImageLocalisationBlock) obj;
    return irisCenterXLargest == other.irisCenterXLargest && irisCenterXSmallest == other.irisCenterXSmallest
        && irisCenterYLargest == other.irisCenterYLargest && irisCenterYSmallest == other.irisCenterYSmallest
        && irisDiameterLargest == other.irisDiameterLargest && irisDiameterSmallest == other.irisDiameterSmallest;
  }

  @Override
  public String toString() {
    return "IrisImageLocalisationBlock ["
        + "irisCenterXSmallest: " + irisCenterXSmallest
        + ", irisCenterXLargest: " + irisCenterXLargest
        + ", irisCenterYSmallest: " + irisCenterYSmallest
        + ", irisCenterYLargest: " + irisCenterYLargest
        + ", irisDiameterSmallest: " + irisDiameterSmallest
        + ", irisDiameterLargest: " + irisDiameterLargest
        + "]";
  }

  /* PACKAGE. */

  @Override
  ASN1Encodable getASN1Object() {
    Map<Integer, ASN1Encodable> taggedObjects = new HashMap<Integer, ASN1Encodable>();
    if (irisCenterXSmallest >= 0) {
      taggedObjects.put(0, ASN1Util.encodeInt(irisCenterXSmallest));
    }
    if (irisCenterXLargest >= 0) {
      taggedObjects.put(1, ASN1Util.encodeInt(irisCenterXLargest));
    }
    if (irisCenterYSmallest >= 0) {
      taggedObjects.put(2, ASN1Util.encodeInt(irisCenterYSmallest));
    }
    if (irisCenterYLargest >= 0) {
      taggedObjects.put(3, ASN1Util.encodeInt(irisCenterYLargest));
    }
    if (irisDiameterSmallest >= 0) {
      taggedObjects.put(4, ASN1Util.encodeInt(irisDiameterSmallest));
    }
    if (irisDiameterLargest >= 0) {
      taggedObjects.put(5, ASN1Util.encodeInt(irisDiameterLargest));
    }
    return ASN1Util.encodeTaggedObjects(taggedObjects);
  }
}
