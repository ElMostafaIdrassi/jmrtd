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
 * Based on ISO-IEC-39794-4-ed-1-v2. Disclaimer:
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

public class FingerImageSegmentBlock extends Block {

  private static final long serialVersionUID = -374626239054691564L;

  private FingerImagePositionCode positionCode;
  private List<CoordinateCartesian2DUnsignedShortBlock> enclosingCoordinatesBlock; // SIZE(2..MAX)
  private Integer orientation;
  private List<QualityBlock> qualityBlocks;
  private int confidence;

  public FingerImageSegmentBlock(FingerImagePositionCode positionCode,
      List<CoordinateCartesian2DUnsignedShortBlock> enclosingCoordinatesBlock, Integer orientation,
      List<QualityBlock> qualityBlocks, int confidence) {
    this.positionCode = positionCode;
    this.enclosingCoordinatesBlock = enclosingCoordinatesBlock;
    this.orientation = orientation;
    this.qualityBlocks = qualityBlocks;
    this.confidence = confidence;
  }

  //    SegmentBlock ::= SEQUENCE {
  //      position [0] Position,
  //      enclosingCoordinatesBlock [1] CoordinatesBlock,
  //      orientation [2] INTEGER (0..255) OPTIONAL,
  //      qualityBlocks [3] QualityBlocks OPTIONAL,
  //      confidence [4] ScoreOrError OPTIONAL,
  //      ...
  //  }

  FingerImageSegmentBlock(ASN1Encodable asn1Encodable) {
    Map<Integer, ASN1Encodable> taggedObjects = ASN1Util.decodeTaggedObjects(asn1Encodable);
    positionCode = FingerImagePositionCode.fromCode(ISO39794Util.decodeCodeFromChoiceExtensionBlockFallback(taggedObjects.get(0)));
    enclosingCoordinatesBlock = CoordinateCartesian2DUnsignedShortBlock.decodeCoordinateCartesian2DUnsignedShortBlocks(taggedObjects.get(1));
    if (taggedObjects.containsKey(2)) {
      orientation = ASN1Util.decodeInt(taggedObjects.get(2));
    }
    if (taggedObjects.containsKey(3)) {
      qualityBlocks = QualityBlock.decodeQualityBlocks(taggedObjects.get(3));
    }
    if (taggedObjects.containsKey(4)) {
      confidence = ISO39794Util.decodeScoreOrError(taggedObjects.get(4));
    }
  }

  public FingerImagePositionCode getPositionCode() {
    return positionCode;
  }

  public List<CoordinateCartesian2DUnsignedShortBlock> getEnclosingCoordinatesBlock() {
    return enclosingCoordinatesBlock;
  }

  public Integer getOrientation() {
    return orientation;
  }

  public List<QualityBlock> getQualityBlocks() {
    return qualityBlocks;
  }

  public int getConfidence() {
    return confidence;
  }

  @Override
  public int hashCode() {
    return Objects.hash(confidence, enclosingCoordinatesBlock, orientation, positionCode, qualityBlocks);
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

    FingerImageSegmentBlock other = (FingerImageSegmentBlock) obj;
    return confidence == other.confidence && Objects.equals(enclosingCoordinatesBlock, other.enclosingCoordinatesBlock)
        && Objects.equals(orientation, other.orientation) && positionCode == other.positionCode
        && Objects.equals(qualityBlocks, other.qualityBlocks);
  }

  @Override
  public String toString() {
    return "FingerImageSegmentBlock ["
        + "positionCode: " + positionCode
        + ", enclosingCoordinatesBlock: " + enclosingCoordinatesBlock
        + ", orientation: " + orientation
        + ", qualityBlocks: " + qualityBlocks
        + ", confidence: " + confidence
        + "]";
  }

  /* PACAKAGE */

  static List<FingerImageSegmentBlock> decodeFingerImageSegmentBlocks(ASN1Encodable asn1Encodable) {
    if (ASN1Util.isSequenceOfSequences(asn1Encodable)) {
      List<ASN1Encodable> blockASN1Objects = ASN1Util.list(asn1Encodable);
      List<FingerImageSegmentBlock> blocks = new ArrayList<FingerImageSegmentBlock>(blockASN1Objects.size());
      for (ASN1Encodable blockASN1Object: blockASN1Objects) {
        blocks.add(new FingerImageSegmentBlock(blockASN1Object));
      }
      return blocks;
    } else {
      return Collections.singletonList(new FingerImageSegmentBlock(asn1Encodable));
    }
  }

  @Override
  ASN1Encodable getASN1Object() {
    Map<Integer, ASN1Encodable> taggedObjects = new HashMap<Integer, ASN1Encodable>();
    taggedObjects.put(0, ISO39794Util.encodeCodeAsChoiceExtensionBlockFallback(positionCode.getCode()));
    taggedObjects.put(1, ISO39794Util.encodeBlocks(enclosingCoordinatesBlock));
    if (orientation != null) {
      taggedObjects.put(2, ASN1Util.encodeInt(orientation));
    }
    if (qualityBlocks != null) {
      taggedObjects.put(3, ISO39794Util.encodeBlocks(qualityBlocks));
    }
    if (confidence >= 0) {
      taggedObjects.put(4, ISO39794Util.encodeScoreOrError(confidence));
    }
    return ASN1Util.encodeTaggedObjects(taggedObjects);
  }
}