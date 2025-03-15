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

public class FingerImageAnnotationBlock extends Block {

  private static final long serialVersionUID = -716107883353729322L;

  public static enum AnnotationReasonCode {
    UNKNOWN(0),
    OTHER(1),
    AMPUTATED(2),
    UNABLE_TO_PRINT(3),
    BANDAGED(4),
    PHYSICALLY_CHALLENGED(5),
    DISEASED(6);

    private int code;

    private AnnotationReasonCode(int code) {
      this.code = code;
    }

    public int getCode() {
      return code;
    }

    public static AnnotationReasonCode fromCode(int code) {
      if (code < 0) {
        return null;
      }
      for (AnnotationReasonCode value: values()) {
        if (code == value.code) {
          return value;
        }
      }

      return null;
    }
  }

  private FingerImagePositionCode positionCode;

  private AnnotationReasonCode reasonCode;

  public FingerImageAnnotationBlock(FingerImagePositionCode positionCode, AnnotationReasonCode reasonCode) {
    this.positionCode = positionCode;
    this.reasonCode = reasonCode;
  }

  //  AnnotationBlock ::= SEQUENCE {
  //    position [0] Position,
  //    reason [1] AnnotationReason,
  //    ...
  //  }

  FingerImageAnnotationBlock(ASN1Encodable asn1Encodable) {
    Map<Integer, ASN1Encodable> taggedObjects = ASN1Util.decodeTaggedObjects(asn1Encodable);
    positionCode = FingerImagePositionCode.fromCode(ISO39794Util.decodeCodeFromChoiceExtensionBlockFallback(taggedObjects.get(0)));
    reasonCode = AnnotationReasonCode.fromCode(ISO39794Util.decodeCodeFromChoiceExtensionBlockFallback(taggedObjects.get(1)));
  }

  public static long getSerialversionuid() {
    return serialVersionUID;
  }

  public FingerImagePositionCode getPositionCode() {
    return positionCode;
  }

  public AnnotationReasonCode getReasonCode() {
    return reasonCode;
  }

  @Override
  public int hashCode() {
    return Objects.hash(positionCode, reasonCode);
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

    FingerImageAnnotationBlock other = (FingerImageAnnotationBlock) obj;
    return positionCode == other.positionCode && reasonCode == other.reasonCode;
  }

  @Override
  public String toString() {
    return "FingerImageAnnotationBlock ["
        + "positionCode: " + positionCode
        + ", reasonCode: " + reasonCode
        + "]";
  }

  /* PACKAGE */

  static List<FingerImageAnnotationBlock> decodeFingerImageAnnotationBlocks(ASN1Encodable asn1Encodable) {
    if (ASN1Util.isSequenceOfSequences(asn1Encodable)) {
      List<ASN1Encodable> blockASN1Objects = ASN1Util.list(asn1Encodable);
      List<FingerImageAnnotationBlock> blocks = new ArrayList<FingerImageAnnotationBlock>(blockASN1Objects.size());
      for (ASN1Encodable blockASN1Object: blockASN1Objects) {
        blocks.add(new FingerImageAnnotationBlock(blockASN1Object));
      }
      return blocks;
    } else {
      return Collections.singletonList(new FingerImageAnnotationBlock(asn1Encodable));
    }
  }

  @Override
  ASN1Encodable getASN1Object() {
    Map<Integer, ASN1Encodable> taggedObjects = new HashMap<Integer, ASN1Encodable>();
    taggedObjects.put(0, ISO39794Util.encodeCodeAsChoiceExtensionBlockFallback(positionCode.getCode()));
    taggedObjects.put(1, ISO39794Util.encodeCodeAsChoiceExtensionBlockFallback(reasonCode.getCode()));
    return ASN1Util.encodeTaggedObjects(taggedObjects);
  }
}
