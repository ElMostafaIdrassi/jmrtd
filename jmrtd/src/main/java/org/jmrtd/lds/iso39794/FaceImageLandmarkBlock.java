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

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.bouncycastle.asn1.ASN1Encodable;
import org.jmrtd.ASN1Util;

public class FaceImageLandmarkBlock extends Block {

  private static final long serialVersionUID = -8008877005187206392L;

  private FaceImageLandmarkKind landmarkKind;

  private FaceImageLandmarkCoordinates landmarkCoordinates;

  public FaceImageLandmarkBlock(FaceImageLandmarkKind landmarkKind, FaceImageLandmarkCoordinates landmarkCoordinates) {
    this.landmarkKind = landmarkKind;
    this.landmarkCoordinates = landmarkCoordinates;
  }

  //  LandmarkBlock ::= SEQUENCE {
  //    landmarkKind [0] LandmarkKind,
  //    landmarkCoordinates [1] LandmarkCoordinates OPTIONAL,
  //    ...
  //  }

  FaceImageLandmarkBlock(ASN1Encodable asn1Encodable) {
    Map<Integer, ASN1Encodable> taggedObjects = ASN1Util.decodeTaggedObjects(asn1Encodable);
    landmarkKind = FaceImageLandmarkKind.decodeLandmarkKind(taggedObjects.get(0));
    if (taggedObjects.containsKey(1)) {
      landmarkCoordinates = FaceImageLandmarkCoordinates.decodeLandmarkCoordinates(taggedObjects.get(1));
    }
  }

  public FaceImageLandmarkKind getLandmarkKind() {
    return landmarkKind;
  }

  public FaceImageLandmarkCoordinates getLandmarkCoordinates() {
    return landmarkCoordinates;
  }

  @Override
  public int hashCode() {
    return Objects.hash(landmarkCoordinates, landmarkKind);
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

    FaceImageLandmarkBlock other = (FaceImageLandmarkBlock) obj;
    return Objects.equals(landmarkCoordinates, other.landmarkCoordinates)
        && Objects.equals(landmarkKind, other.landmarkKind);
  }

  @Override
  public String toString() {
    return "FaceImageLandmarkBlock ["
        + "landmarkKind: " + landmarkKind
        + ", landmarkCoordinates: " + landmarkCoordinates
        + "]";
  }

  /* PACKAGE */

  @Override
  ASN1Encodable getASN1Object() {
    Map<Integer, ASN1Encodable> taggedObjects = new HashMap<Integer, ASN1Encodable>();
    taggedObjects.put(0, FaceImageLandmarkKind.encodeLandmarkKind(landmarkKind));
    if (landmarkCoordinates != null) { taggedObjects.put(1, FaceImageLandmarkCoordinates.encodeLandmarkCoordinates(landmarkCoordinates)); }
    return ASN1Util.encodeTaggedObjects(taggedObjects);
  }

  static List<FaceImageLandmarkBlock> decodeLandmarkBlocks(ASN1Encodable asn1Encodable) {
    if (ASN1Util.isSequenceOfSequences(asn1Encodable)) {
      List<ASN1Encodable> blockASN1Objects = ASN1Util.list(asn1Encodable);
      List<FaceImageLandmarkBlock> blocks = new ArrayList<FaceImageLandmarkBlock>(blockASN1Objects.size());
      for (ASN1Encodable blockASN1Object: blockASN1Objects) {
        blocks.add(new FaceImageLandmarkBlock(blockASN1Object));
      }
      return blocks;
    } else {
      return Collections.singletonList(new FaceImageLandmarkBlock(asn1Encodable));
    }
  }
}
