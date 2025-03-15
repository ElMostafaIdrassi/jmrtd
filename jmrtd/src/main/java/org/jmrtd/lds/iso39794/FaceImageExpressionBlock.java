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
import org.jmrtd.ASN1Util;

public class FaceImageExpressionBlock extends Block {

  private static final long serialVersionUID = -3603621366074466000L;

  private Boolean isNeutral;
  private Boolean isSmile;
  private Boolean isRaisedEyebrows;
  private Boolean isEyesLookingAwayFromTheCamera;
  private Boolean isSquinting;
  private Boolean isFrowning;

  public FaceImageExpressionBlock(Boolean isNeutral, Boolean isSmile, Boolean isRaisedEyebrows,
      Boolean isEyesLookingAwayFromTheCamera, Boolean isSquinting, Boolean isFrowning) {
    this.isNeutral = isNeutral;
    this.isSmile = isSmile;
    this.isRaisedEyebrows = isRaisedEyebrows;
    this.isEyesLookingAwayFromTheCamera = isEyesLookingAwayFromTheCamera;
    this.isSquinting = isSquinting;
    this.isFrowning = isFrowning;
  }

  //  ExpressionBlock ::= SEQUENCE {
  //    neutral [0] BOOLEAN OPTIONAL,
  //    smile [1] BOOLEAN OPTIONAL,
  //    raisedEyebrows [2] BOOLEAN OPTIONAL,
  //    eyesLookingAwayFromTheCamera [3] BOOLEAN OPTIONAL,
  //    squinting [4] BOOLEAN OPTIONAL,
  //    frowning [5] BOOLEAN OPTIONAL,
  //    ...
  //  }

  FaceImageExpressionBlock(ASN1Encodable asn1Encodable) {
    Map<Integer, ASN1Encodable> taggedObjects = ASN1Util.decodeTaggedObjects(asn1Encodable);
    if (taggedObjects.containsKey(0)) {
      isNeutral = ASN1Util.decodeBoolean(taggedObjects.get(0));
    }
    if (taggedObjects.containsKey(1)) {
      isSmile = ASN1Util.decodeBoolean(taggedObjects.get(1));
    }
    if (taggedObjects.containsKey(2)) {
      isRaisedEyebrows = ASN1Util.decodeBoolean(taggedObjects.get(2));
    }
    if (taggedObjects.containsKey(3)) {
      isEyesLookingAwayFromTheCamera = ASN1Util.decodeBoolean(taggedObjects.get(3));
    }
    if (taggedObjects.containsKey(4)) {
      isSquinting = ASN1Util.decodeBoolean(taggedObjects.get(4));
    }
    if (taggedObjects.containsKey(5)) {
      isFrowning = ASN1Util.decodeBoolean(taggedObjects.get(5));
    }
  }

  public Boolean isNeutral() {
    return isNeutral;
  }

  public Boolean isSmile() {
    return isSmile;
  }

  public Boolean isRaisedEyebrows() {
    return isRaisedEyebrows;
  }

  public Boolean isEyesLookingAwayFromTheCamera() {
    return isEyesLookingAwayFromTheCamera;
  }

  public Boolean isSquinting() {
    return isSquinting;
  }

  public Boolean isFrowning() {
    return isFrowning;
  }

  @Override
  public int hashCode() {
    return Objects.hash(isEyesLookingAwayFromTheCamera, isFrowning, isNeutral, isRaisedEyebrows, isSmile, isSquinting);
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

    FaceImageExpressionBlock other = (FaceImageExpressionBlock) obj;
    return Objects.equals(isEyesLookingAwayFromTheCamera, other.isEyesLookingAwayFromTheCamera)
        && Objects.equals(isFrowning, other.isFrowning) && Objects.equals(isNeutral, other.isNeutral)
        && Objects.equals(isRaisedEyebrows, other.isRaisedEyebrows) && Objects.equals(isSmile, other.isSmile)
        && Objects.equals(isSquinting, other.isSquinting);
  }

  @Override
  public String toString() {
    return "FaceImageExpressionBlock ["
        + "isNeutral: " + isNeutral
        + ", isSmile: " + isSmile
        + ", isRaisedEyebrows: " + isRaisedEyebrows
        + ", isEyesLookingAwayFromTheCamera: " + isEyesLookingAwayFromTheCamera
        + ", isSquinting: " + isSquinting
        + ", isFrowning: " + isFrowning
        + "]";
  }

  /* PACKAGE */

  @Override
  ASN1Encodable getASN1Object() {
    Map<Integer, ASN1Encodable> taggedObjects = new HashMap<Integer, ASN1Encodable>();
    if (isNeutral != null) {
      taggedObjects.put(0, ASN1Util.encodeBoolean(isNeutral));
    }
    if (isSmile != null) {
      taggedObjects.put(1, ASN1Util.encodeBoolean(isSmile));
    }
    if (isRaisedEyebrows != null) {
      taggedObjects.put(2, ASN1Util.encodeBoolean(isRaisedEyebrows));
    }
    if (isEyesLookingAwayFromTheCamera != null) {
      taggedObjects.put(3, ASN1Util.encodeBoolean(isEyesLookingAwayFromTheCamera));
    }
    if (isSquinting != null) {
      taggedObjects.put(4, ASN1Util.encodeBoolean(isSquinting));
    }
    if (isFrowning != null) {
      taggedObjects.put(5, ASN1Util.encodeBoolean(isFrowning));
    }
    return ASN1Util.encodeTaggedObjects(taggedObjects);
  }
}
