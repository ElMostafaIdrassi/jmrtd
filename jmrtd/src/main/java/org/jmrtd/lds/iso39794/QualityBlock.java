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

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.bouncycastle.asn1.ASN1Encodable;
import org.jmrtd.ASN1Util;

public class QualityBlock extends Block {

  private static final long serialVersionUID = 8529221328304209845L;

  //  QualityBlock ::= SEQUENCE {
  //    algorithmIdBlock                [0] RegistryIdBlock,
  //    scoreOrError                    [1] ScoreOrError,
  //    ...
  //  }

  private RegistryIdBlock algorithmIdBlock;

  private int score;

  public QualityBlock(RegistryIdBlock algorithmIdBlock, int score) {
    this.algorithmIdBlock = algorithmIdBlock;
    this.score = score;
  }

  QualityBlock(ASN1Encodable asn1Encodable) {
    Map<Integer, ASN1Encodable> taggedObjects = ASN1Util.decodeTaggedObjects(asn1Encodable);
    algorithmIdBlock = new RegistryIdBlock(taggedObjects.get(0));
    score = decodeScoreOrError(taggedObjects.get(1));
  }

  //  ScoreOrError ::= CHOICE {
  //    score   [0] Score,
  //    error   [1] ScoringError
  //  }

  private static int decodeScoreOrError(ASN1Encodable asn1Encodable) {
    Map<Integer, ASN1Encodable> taggedObjects = ASN1Util.decodeTaggedObjects(asn1Encodable);
    if (taggedObjects.containsKey(0)) {
      return ASN1Util.decodeInt(taggedObjects.get(0));
    }

    /* NOTE: We could navigate the object under [1], and distinguish between failureToAssess or extension. */
    return -1;
  }

  private static ASN1Encodable encodeScoreOrError(int score) {
    Map<Integer, ASN1Encodable> taggedObjects = new HashMap<Integer, ASN1Encodable>();
    taggedObjects.put(0, ASN1Util.encodeInt(score));
    return ASN1Util.encodeTaggedObjects(taggedObjects);
  }

  public RegistryIdBlock getAlgorithmIdBlock() {
    return algorithmIdBlock;
  }

  public int getScore() {
    return score;
  }

  @Override
  public int hashCode() {
    return Objects.hash(algorithmIdBlock, score);
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

    QualityBlock other = (QualityBlock) obj;
    return Objects.equals(algorithmIdBlock, other.algorithmIdBlock) && score == other.score;
  }

  @Override
  public String toString() {
    return "QualityBlock ["
        + "algorithmIdBlock: " + algorithmIdBlock
        + ", score: " + score
        + "]";
  }

  ASN1Encodable getASN1Object() {
    Map<Integer, ASN1Encodable> taggedObjects = new HashMap<Integer, ASN1Encodable>();
    taggedObjects.put(0, algorithmIdBlock.getASN1Object());
    if (score >= 0) {
      taggedObjects.put(1, encodeScoreOrError(score));
    }
    return ASN1Util.encodeTaggedObjects(taggedObjects);
  }

  //  QualityBlocks ::= SEQUENCE OF QualityBlock

  static List<QualityBlock> decodeQualityBlocks(ASN1Encodable asn1Encodable) {
    if (ASN1Util.isSequenceOfSequences(asn1Encodable)) {
      List<ASN1Encodable> blockASN1Objects = ASN1Util.list(asn1Encodable);
      List<QualityBlock> blocks = new ArrayList<QualityBlock>(blockASN1Objects.size());
      for (ASN1Encodable blockASN1Object: blockASN1Objects) {
        blocks.add(new QualityBlock(blockASN1Object));
      }
      return blocks;
    } else {
      return Collections.singletonList(new QualityBlock(asn1Encodable));
    }
  }
}
