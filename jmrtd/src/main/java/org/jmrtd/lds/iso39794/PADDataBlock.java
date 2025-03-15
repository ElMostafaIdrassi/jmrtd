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
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.jmrtd.ASN1Util;

import net.sf.scuba.util.Hex;

public class PADDataBlock extends Block {

  private static final long serialVersionUID = 1498548397505331884L;

  public enum PADDecisionCode {
    NO_ATTACK(0),
    ATTACK(1),
    FAILURE_TO_ASSESS(2);

    private int code;

    private PADDecisionCode(int code) {
      this.code = code;
    }

    public int getCode() {
      return code;
    }

    public static PADDecisionCode fromCode(int code) {
      if (code < 0) {
        return null;
      }
      for (PADDecisionCode value: values()) {
        if (code == value.code) {
          return value;
        }
      }

      return null;
    }
  }

  public enum PADCaptureContextCode {
    ENROLMENT(0),
    VERIFICATION(1),
    IDENTIFICATION(2);

    private int code;

    private PADCaptureContextCode(int code) {
      this.code = code;
    }

    public int getCode() {
      return code;
    }

    public static PADCaptureContextCode fromCode(int code) {
      if (code < 0) {
        return null;
      }
      for (PADCaptureContextCode value: values()) {
        if (code == value.code) {
          return value;
        }
      }

      return null;
    }
  }

  public enum PADSupervisionLevelCode {
    UNKNOWN(0),
    CONTROLLED(1),
    ASSISTED(2),
    OBSERVED(3),
    UNATTENDED(4);

    private int code;

    private PADSupervisionLevelCode(int code) {
      this.code = code;
    }

    public int getCode() {
      return code;
    }

    public static PADSupervisionLevelCode fromCode(int code) {
      if (code < 0) {
        return null;
      }
      for (PADSupervisionLevelCode value: values()) {
        if (code == value.code) {
          return value;
        }
      }

      return null;
    }
  }

  public enum PADCriteriaCategoryCode {
    UNKNOWN(0),
    INDIVIDUAL(1),
    COMMON(2);

    private int code;

    private PADCriteriaCategoryCode(int code) {
      this.code = code;
    }

    public int getCode() {
      return code;
    }

    public static PADCriteriaCategoryCode fromCode(int code) {
      if (code < 0) {
        return null;
      }
      for (PADCriteriaCategoryCode value: values()) {
        if (code == value.code) {
          return value;
        }
      }

      return null;
    }
  }

  private PADDecisionCode padDecisionCode;

  private List<PADScoreBlock> padScoreBlocks;

  private List<ExtendedDataBlock> padExtendedDataBlocks;

  private PADCaptureContextCode padCaptureContextCode;

  private PADSupervisionLevelCode padSupervisionLevelCode;

  /** INTEGER (0..100). */
  private int riskLevel;

  private PADCriteriaCategoryCode padCriteriaCategoryCode;

  private byte[] parameter;

  private List<byte[]> challenges;

  private DateTimeBlock captureDateTimeBlock;

  public PADDataBlock(PADDecisionCode padDecisionCode, List<PADScoreBlock> padScoreBlocks,
      List<ExtendedDataBlock> padExtendedDataBlocks, PADCaptureContextCode padCaptureContextCode,
      PADSupervisionLevelCode padSupervisionLevelCode, int riskLevel, PADCriteriaCategoryCode padCriteriaCategoryCode,
      byte[] parameter, List<byte[]> challenges, DateTimeBlock captureDateTimeBlock) {
    this.padDecisionCode = padDecisionCode;
    this.padScoreBlocks = padScoreBlocks;
    this.padExtendedDataBlocks = padExtendedDataBlocks;
    this.padCaptureContextCode = padCaptureContextCode;
    this.padSupervisionLevelCode = padSupervisionLevelCode;
    this.riskLevel = riskLevel;
    this.padCriteriaCategoryCode = padCriteriaCategoryCode;
    this.parameter = parameter;
    this.challenges = challenges;
    this.captureDateTimeBlock = captureDateTimeBlock;
  }

  //  PADDataBlock ::= SEQUENCE {
  //    decision              [0] PADDecision            OPTIONAL,
  //    scoreBlocks           [1] PADScoreBlocks         OPTIONAL,
  //    extendedDataBlocks    [2] PADExtendedDataBlocks  OPTIONAL,
  //    captureContext        [3] PADCaptureContext      OPTIONAL,
  //    supervisionLevel      [4] PADSupervisionLevel    OPTIONAL,
  //    riskLevel             [5] PADRiskLevel           OPTIONAL,
  //    criteriaCategory      [6] PADCriteriaCategory    OPTIONAL,
  //    parameter             [7] OCTET STRING           OPTIONAL,
  //    challenges            [8] PADChallenges          OPTIONAL,
  //    captureDateTimeBlock  [9] CaptureDateTimeBlock   OPTIONAL,
  //    ...
  //  }

  PADDataBlock(ASN1Encodable asn1Encodable) {
    Map<Integer, ASN1Encodable> taggedObjects = ASN1Util.decodeTaggedObjects(asn1Encodable);
    if (taggedObjects.containsKey(0)) {
      padDecisionCode = decodePADDecision(taggedObjects.get(0));
    }
    if (taggedObjects.containsKey(1)) {
      padScoreBlocks = PADScoreBlock.decodePADScoreBlocks(taggedObjects.get(1));
    }
    if (taggedObjects.containsKey(2)) {
      padExtendedDataBlocks = ExtendedDataBlock.decodeExtendedDataBlocks(taggedObjects.get(2));
    }
    if (taggedObjects.containsKey(3)) {
      padCaptureContextCode =  decodePADCaptureContext(taggedObjects.get(3));
    }
    if (taggedObjects.containsKey(4)) {
      padSupervisionLevelCode = decodePADSupervisionLevel(taggedObjects.get(4));
    }
    if (taggedObjects.containsKey(5)) {
      riskLevel = ASN1Util.decodeInt(taggedObjects.get(5));
    }
    if (taggedObjects.containsKey(6)) {
      padCriteriaCategoryCode = decodePADCriteriaCategory(taggedObjects.get(6));
    }
    if (taggedObjects.containsKey(7)) {
      parameter = ASN1OctetString.getInstance(taggedObjects.get(7)).getOctets();
    }
    if (taggedObjects.containsKey(8)) {
      challenges = decodePADChallenges(taggedObjects.get(8));
    }
    if (taggedObjects.containsKey(9)) {
      captureDateTimeBlock = new DateTimeBlock(taggedObjects.get(9));
    }
  }

  public PADDecisionCode getPADDecisionCode() {
    return padDecisionCode;
  }

  public List<PADScoreBlock> getPadScoreBlocks() {
    return padScoreBlocks;
  }

  public List<ExtendedDataBlock> getPadExtendedDataBlocks() {
    return padExtendedDataBlocks;
  }

  public PADCaptureContextCode getPADCaptureContextCode() {
    return padCaptureContextCode;
  }

  public PADSupervisionLevelCode getPADSupervisionLevelCode() {
    return padSupervisionLevelCode;
  }

  public int getRiskLevel() {
    return riskLevel;
  }

  public PADCriteriaCategoryCode getPADCriteriaCategoryCode() {
    return padCriteriaCategoryCode;
  }

  public byte[] getParameter() {
    return parameter;
  }

  public List<byte[]> getChallenges() {
    return challenges;
  }

  public DateTimeBlock getCaptureDateTimeBlock() {
    return captureDateTimeBlock;
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + Arrays.hashCode(parameter);
    result = prime * result
        + Objects.hash(captureDateTimeBlock, challenges, padCaptureContextCode, padCriteriaCategoryCode,
            padDecisionCode, padExtendedDataBlocks, padScoreBlocks, padSupervisionLevelCode, riskLevel);
    return result;
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

    PADDataBlock other = (PADDataBlock)obj;
    return Objects.equals(captureDateTimeBlock, other.captureDateTimeBlock)
        && equalBytes(challenges, other.challenges)
        && padCaptureContextCode == other.padCaptureContextCode
        && padCriteriaCategoryCode == other.padCriteriaCategoryCode && padDecisionCode == other.padDecisionCode
        && Objects.equals(padExtendedDataBlocks, other.padExtendedDataBlocks)
        && Objects.equals(padScoreBlocks, other.padScoreBlocks)
        && padSupervisionLevelCode == other.padSupervisionLevelCode && Arrays.equals(parameter, other.parameter)
        && riskLevel == other.riskLevel;
  }

  @Override
  public String toString() {
    return "PADDataBlock [padDecisionCode: " + padDecisionCode
        + ", padScoreBlocks: " + padScoreBlocks
        + ", padExtendedDataBlocks: " + padExtendedDataBlocks
        + ", padCaptureContextCode: " + padCaptureContextCode
        + ", padSupervisionLevelCode: " + padSupervisionLevelCode
        + ", riskLevel: " + riskLevel
        + ", padCriteriaCategoryCode: " + padCriteriaCategoryCode
        + ", parameter: " + Hex.bytesToHexString(parameter)
        + ", challenges: " + toString(challenges)
        + ", captureDateTimeBlock: " + captureDateTimeBlock + "]";
  }

  /* PACKAGE */

  static List<PADDataBlock> decodePADDataBlocks(ASN1Encodable asn1Encodable) {
    if (ASN1Util.isSequenceOfSequences(asn1Encodable)) {
      List<ASN1Encodable> blockASN1Objects = ASN1Util.list(asn1Encodable);
      List<PADDataBlock> blocks = new ArrayList<PADDataBlock>(blockASN1Objects.size());
      for (ASN1Encodable blockASN1Object: blockASN1Objects) {
        blocks.add(new PADDataBlock(blockASN1Object));
      }
      return blocks;
    } else {
      PADDataBlock block = new PADDataBlock(asn1Encodable);
      return Collections.singletonList(block);
    }
  }

  @Override
  ASN1Encodable getASN1Object() {
    Map<Integer, ASN1Encodable> taggedObjects = new HashMap<Integer, ASN1Encodable>();
    if (padDecisionCode != null) {
      taggedObjects.put(0, ISO39794Util.encodeCodeAsChoiceExtensionBlockFallback(padDecisionCode.getCode()));
    }
    if (padScoreBlocks != null) {
      taggedObjects.put(1, ISO39794Util.encodeBlocks(padScoreBlocks));
    }
    if (padExtendedDataBlocks != null) {
      taggedObjects.put(2, ISO39794Util.encodeBlocks(padExtendedDataBlocks));
    }
    if (padExtendedDataBlocks != null) {
      taggedObjects.put(3, ISO39794Util.encodeCodeAsChoiceExtensionBlockFallback(padCaptureContextCode.getCode()));
    }
    if (padSupervisionLevelCode != null) {
      taggedObjects.put(4, ISO39794Util.encodeCodeAsChoiceExtensionBlockFallback(padSupervisionLevelCode.getCode()));
    }
    if (riskLevel >= 0) {
      taggedObjects.put(5, ASN1Util.encodeInt(riskLevel));
    }
    if (padCriteriaCategoryCode != null) {
      taggedObjects.put(6, ISO39794Util.encodeCodeAsChoiceExtensionBlockFallback(padCriteriaCategoryCode.getCode()));
    }
    if (parameter != null) {
      taggedObjects.put(7, new DEROctetString(parameter));
    }
    if (challenges != null) {
      taggedObjects.put(8, encodePADChallenges(challenges));
    }
    if (captureDateTimeBlock != null) {
      taggedObjects.put(9, captureDateTimeBlock.getASN1Object());
    }
    return ASN1Util.encodeTaggedObjects(taggedObjects);
  }

  /* PRIVATE */

  private static PADDecisionCode decodePADDecision(ASN1Encodable asn1Encodable) {
    return PADDecisionCode.fromCode(ISO39794Util.decodeCodeFromChoiceExtensionBlockFallback(asn1Encodable));
  }

  private static PADCaptureContextCode decodePADCaptureContext(ASN1Encodable asn1Encodable) {
    return PADCaptureContextCode.fromCode(ISO39794Util.decodeCodeFromChoiceExtensionBlockFallback(asn1Encodable));
  }

  private static PADSupervisionLevelCode decodePADSupervisionLevel(ASN1Encodable asn1Encodable) {
    return PADSupervisionLevelCode.fromCode(ISO39794Util.decodeCodeFromChoiceExtensionBlockFallback(asn1Encodable));
  }

  private static PADCriteriaCategoryCode decodePADCriteriaCategory(ASN1Encodable asn1Encodable) {
    return PADCriteriaCategoryCode.fromCode(ISO39794Util.decodeCodeFromChoiceExtensionBlockFallback(asn1Encodable));
  }

  private static List<byte[]> decodePADChallenges(ASN1Encodable asn1Encodable) {
    List<ASN1Encodable> challengeASN1Objects = ASN1Util.list(asn1Encodable);
    List<byte[]> padChallenges = new ArrayList<byte[]>(challengeASN1Objects.size());
    for (ASN1Encodable challengeASN1Object: challengeASN1Objects) {
      padChallenges.add(ASN1OctetString.getInstance(challengeASN1Object).getOctets());
    }
    return padChallenges;
  }

  private static ASN1Encodable encodePADChallenges(List<byte[]> padChallenges) {
    ASN1Encodable[] asn1Encodables = new ASN1Encodable[padChallenges.size()];
    int i = 0;
    for (byte[] padChallenge: padChallenges) {
      asn1Encodables[i++] = new DEROctetString(padChallenge);
    }
    return new DERSequence(asn1Encodables);
  }

  private static boolean equalBytes(List<byte[]> challenges1, List<byte[]> challenges2) {
    if (Objects.equals(challenges1, challenges2)) {
      return true;
    }
    if (challenges1 == null && challenges2 != null) {
      return false;
    }
    if (challenges1 != null && challenges2 == null) {
      return false;
    }
    if (challenges1.size() != challenges2.size()) {
      return false;
    }
    int length = challenges1.size();
    for (int i = 0; i < length; i++) {
      if (!(Arrays.equals(challenges1.get(i), challenges2.get(i)))) {
        return false;
      }
    }
    return true;
  }

  private static String toString(List<byte[]> challenges) {
    if (challenges == null) {
      return "null";
    }
    boolean isFirst = true;
    StringBuilder stringBuilder = new StringBuilder().append("[");
    for (byte[] challenge: challenges) {
      if (isFirst) {
        isFirst = false;
      } else {
        stringBuilder.append(", ");
      }
      stringBuilder.append(Hex.bytesToHexString(challenge));
    }
    return stringBuilder.append("]").toString();
  }
}
