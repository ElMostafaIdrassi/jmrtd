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
 * Based on ISO-IEC-39794-5-ed-1-v1. Disclaimer:
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
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.jmrtd.ASN1Util;

public class FaceImageCaptureDeviceSpectral2DBlock extends Block {

  private static final long serialVersionUID = 1003955292326716335L;

  private Boolean isWhiteLight;
  private Boolean isNearInfrared;
  private Boolean isThermal;

  public FaceImageCaptureDeviceSpectral2DBlock(Boolean isWhiteLight, Boolean isNearInfrared, Boolean isThermal) {
    this.isWhiteLight = isWhiteLight;
    this.isNearInfrared = isNearInfrared;
    this.isThermal = isThermal;
  }

  //  CaptureDeviceSpectral2DBlock ::= SEQUENCE {
  //    whiteLight [0] BOOLEAN OPTIONAL,
  //    nearInfrared [1] BOOLEAN OPTIONAL,
  //    thermal [2] BOOLEAN OPTIONAL,
  //    ...
  //  }

  FaceImageCaptureDeviceSpectral2DBlock(ASN1Encodable asn1Encodable) {
    if (!(asn1Encodable instanceof ASN1Sequence) && !(asn1Encodable instanceof ASN1TaggedObject)) {
      throw new IllegalArgumentException("Cannot decode!");
    }

    Map<Integer, ASN1Encodable> taggedObjects = ASN1Util.decodeTaggedObjects(asn1Encodable);
    if (taggedObjects.containsKey(0)) {
      isWhiteLight = ASN1Util.decodeBoolean(taggedObjects.get(0));
    }
    if (taggedObjects.containsKey(1)) {
      isNearInfrared = ASN1Util.decodeBoolean(taggedObjects.get(1));
    }
    if (taggedObjects.containsKey(2)) {
      isThermal = ASN1Util.decodeBoolean(taggedObjects.get(2));
    }
  }

  public Boolean isWhiteLight() {
    return isWhiteLight;
  }

  public Boolean isNearInfrared() {
    return isNearInfrared;
  }

  public Boolean isThermal() {
    return isThermal;
  }

  @Override
  public int hashCode() {
    return Objects.hash(isNearInfrared, isThermal, isWhiteLight);
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

    FaceImageCaptureDeviceSpectral2DBlock other = (FaceImageCaptureDeviceSpectral2DBlock) obj;
    return isNearInfrared == other.isNearInfrared && isThermal == other.isThermal && isWhiteLight == other.isWhiteLight;
  }

  @Override
  public String toString() {
    return "FaceImageCaptureDeviceSpectral2DBlock ["
        + "isWhiteLight: " + isWhiteLight
        + ", isNearInfrared: " + isNearInfrared
        + ", isThermal: " + isThermal + "]";
  }

  /* PACKAGE */

  @Override
  ASN1Encodable getASN1Object() {
    Map<Integer, ASN1Encodable> taggedObjects = new HashMap<Integer, ASN1Encodable>();
    if (isWhiteLight != null) {
      taggedObjects.put(0, ASN1Util.encodeBoolean(isWhiteLight));
    }
    if (isNearInfrared != null) {
      taggedObjects.put(1, ASN1Util.encodeBoolean(isNearInfrared));
    }
    if (isThermal != null) {
      taggedObjects.put(2, ASN1Util.encodeBoolean(isThermal));
    }
    return ASN1Util.encodeTaggedObjects(taggedObjects);
  }
}
