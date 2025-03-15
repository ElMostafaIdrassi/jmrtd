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

public class FaceImagePostAcquisitionProcessingBlock extends Block {

  private static final long serialVersionUID = -3603621266074466100L;

  private Boolean isRotated;
  private Boolean isCropped;
  private Boolean isDownSampled;
  private Boolean isWhiteBalanceAdjusted;
  private Boolean isMultiplyCompressed;
  private Boolean isInterpolated;
  private Boolean isContrastStretched;
  private Boolean isPoseCorrected;
  private Boolean isMultiViewImage;
  private Boolean isAgeProgressed;
  private Boolean isSuperResolutionProcessed;
  private Boolean isNormalised;

  public FaceImagePostAcquisitionProcessingBlock(Boolean isRotated, Boolean isCropped, Boolean isDownSampled,
      Boolean isWhiteBalanceAdjusted, Boolean isMultiplyCompressed, Boolean isInterpolated, Boolean isContrastStretched,
      Boolean isPoseCorrected, Boolean isMultiViewImage, Boolean isAgeProgressed, Boolean isSuperResolutionProcessed,
      Boolean isNormalised) {
    this.isRotated = isRotated;
    this.isCropped = isCropped;
    this.isDownSampled = isDownSampled;
    this.isWhiteBalanceAdjusted = isWhiteBalanceAdjusted;
    this.isMultiplyCompressed = isMultiplyCompressed;
    this.isInterpolated = isInterpolated;
    this.isContrastStretched = isContrastStretched;
    this.isPoseCorrected = isPoseCorrected;
    this.isMultiViewImage = isMultiViewImage;
    this.isAgeProgressed = isAgeProgressed;
    this.isSuperResolutionProcessed = isSuperResolutionProcessed;
    this.isNormalised = isNormalised;
  }

  public FaceImagePostAcquisitionProcessingBlock(ASN1Encodable asn1Encodable) {
    Map<Integer, ASN1Encodable> taggedObjects = ASN1Util.decodeTaggedObjects(asn1Encodable);
    if (taggedObjects.containsKey(0)) {
      isRotated = ASN1Util.decodeBoolean(taggedObjects.get(0));
    }
    if (taggedObjects.containsKey(1)) {
      isCropped = ASN1Util.decodeBoolean(taggedObjects.get(1));
    }
    if (taggedObjects.containsKey(2)) {
      isDownSampled = ASN1Util.decodeBoolean(taggedObjects.get(2));
    }
    if (taggedObjects.containsKey(3)) {
      isWhiteBalanceAdjusted= ASN1Util.decodeBoolean(taggedObjects.get(3));
    }
    if (taggedObjects.containsKey(4)) {
      isMultiplyCompressed= ASN1Util.decodeBoolean(taggedObjects.get(4));
    }
    if (taggedObjects.containsKey(5)) {
      isInterpolated = ASN1Util.decodeBoolean(taggedObjects.get(5));
    }
    if (taggedObjects.containsKey(6)) {
      isContrastStretched = ASN1Util.decodeBoolean(taggedObjects.get(6));
    }
    if (taggedObjects.containsKey(7)) {
      isPoseCorrected = ASN1Util.decodeBoolean(taggedObjects.get(7));
    }
    if (taggedObjects.containsKey(8)) {
      isMultiViewImage = ASN1Util.decodeBoolean(taggedObjects.get(8));
    }
    if (taggedObjects.containsKey(9)) {
      isAgeProgressed = ASN1Util.decodeBoolean(taggedObjects.get(9));
    }
    if (taggedObjects.containsKey(10)) {
      isSuperResolutionProcessed = ASN1Util.decodeBoolean(taggedObjects.get(10));
    }
    if (taggedObjects.containsKey(11)) {
      isNormalised = ASN1Util.decodeBoolean(taggedObjects.get(11));
    }
  }

  public Boolean isRotated() {
    return isRotated;
  }

  public Boolean isCropped() {
    return isCropped;
  }

  public Boolean isDownSampled() {
    return isDownSampled;
  }

  public Boolean isWhiteBalanceAdjusted() {
    return isWhiteBalanceAdjusted;
  }

  public Boolean isMultiplyCompressed() {
    return isMultiplyCompressed;
  }

  public Boolean isInterpolated() {
    return isInterpolated;
  }

  public Boolean isContrastStretched() {
    return isContrastStretched;
  }

  public Boolean isPoseCorrected() {
    return isPoseCorrected;
  }

  public Boolean isMultiViewImage() {
    return isMultiViewImage;
  }

  public Boolean isAgeProgressed() {
    return isAgeProgressed;
  }

  public Boolean isSuperResolutionProcessed() {
    return isSuperResolutionProcessed;
  }

  public Boolean isNormalised() {
    return isNormalised;
  }

  @Override
  public int hashCode() {
    return Objects.hash(isAgeProgressed, isContrastStretched, isCropped, isDownSampled, isInterpolated,
        isMultiViewImage, isMultiplyCompressed, isNormalised, isPoseCorrected, isRotated, isSuperResolutionProcessed,
        isWhiteBalanceAdjusted);
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

    FaceImagePostAcquisitionProcessingBlock other = (FaceImagePostAcquisitionProcessingBlock) obj;
    return Objects.equals(isAgeProgressed, other.isAgeProgressed)
        && Objects.equals(isContrastStretched, other.isContrastStretched) && Objects.equals(isCropped, other.isCropped)
        && Objects.equals(isDownSampled, other.isDownSampled) && Objects.equals(isInterpolated, other.isInterpolated)
        && Objects.equals(isMultiViewImage, other.isMultiViewImage)
        && Objects.equals(isMultiplyCompressed, other.isMultiplyCompressed)
        && Objects.equals(isNormalised, other.isNormalised) && Objects.equals(isPoseCorrected, other.isPoseCorrected)
        && Objects.equals(isRotated, other.isRotated)
        && Objects.equals(isSuperResolutionProcessed, other.isSuperResolutionProcessed)
        && Objects.equals(isWhiteBalanceAdjusted, other.isWhiteBalanceAdjusted);
  }

  @Override
  public String toString() {
    return "FaceImagePostAcquisitionProcessingBlock ["
        + "isRotated: " + isRotated
        + ", isCropped: " + isCropped
        + ", isDownSampled: " + isDownSampled
        + ", isWhiteBalanceAdjusted: " + isWhiteBalanceAdjusted
        + ", isMultiplyCompressed: " + isMultiplyCompressed
        + ", isInterpolated: " + isInterpolated
        + ", isContrastStretched: " + isContrastStretched
        + ", isPoseCorrected: " + isPoseCorrected
        + ", isMultiViewImage: " + isMultiViewImage
        + ", isAgeProgressed: " + isAgeProgressed
        + ", isSuperResolutionProcessed: " + isSuperResolutionProcessed
        + ", isNormalised: " + isNormalised
        + "]";
  }

  /* PACKAGE */

  @Override
  ASN1Encodable getASN1Object() {
    Map<Integer, ASN1Encodable> taggedObjects = new HashMap<Integer, ASN1Encodable>();
    if (isRotated != null) {
      taggedObjects.put(0, ASN1Util.encodeBoolean(isRotated));
    }
    if (isCropped != null) {
      taggedObjects.put(1, ASN1Util.encodeBoolean(isCropped));
    }
    if (isDownSampled != null) {
      taggedObjects.put(2, ASN1Util.encodeBoolean(isDownSampled));
    }
    if (isWhiteBalanceAdjusted != null) {
      taggedObjects.put(3, ASN1Util.encodeBoolean(isWhiteBalanceAdjusted));
    }
    if (isMultiplyCompressed != null) {
      taggedObjects.put(4, ASN1Util.encodeBoolean(isMultiplyCompressed));
    }
    if (isInterpolated != null) {
      taggedObjects.put(5, ASN1Util.encodeBoolean(isInterpolated));
    }
    if (isContrastStretched != null) {
      taggedObjects.put(6, ASN1Util.encodeBoolean(isContrastStretched));
    }
    if (isPoseCorrected != null) {
      taggedObjects.put(7, ASN1Util.encodeBoolean(isPoseCorrected));
    }
    if (isMultiViewImage != null) {
      taggedObjects.put(8, ASN1Util.encodeBoolean(isMultiViewImage));
    }
    if (isAgeProgressed != null) {
      taggedObjects.put(9, ASN1Util.encodeBoolean(isAgeProgressed));
    }
    if (isSuperResolutionProcessed != null) {
      taggedObjects.put(10, ASN1Util.encodeBoolean(isSuperResolutionProcessed));
    }
    if (isNormalised != null) {
      taggedObjects.put(11, ASN1Util.encodeBoolean(isNormalised));
    }
    return ASN1Util.encodeTaggedObjects(taggedObjects);
  }
}
