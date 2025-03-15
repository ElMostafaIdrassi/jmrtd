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
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.jmrtd.ASN1Util;

import net.sf.scuba.util.Hex;

public class FaceImageReferenceColourMappingBlock extends Block {

  private static final long serialVersionUID = -347556999620185601L;

  public static class ReferenceColourDefinitionAndValueBlock extends Block {

    private static final long serialVersionUID = -7927429988191532374L;

    private byte[] referenceColourDefinition;
    private byte[] referenceColourValue;

    public ReferenceColourDefinitionAndValueBlock(byte[] referenceColourDefinition, byte[] referenceColourValue) {
      this.referenceColourDefinition = referenceColourDefinition;
      this.referenceColourValue = referenceColourValue;
    }

    //    ReferenceColourDefinitionAndValueBlock ::= SEQUENCE {
    //            referenceColourDefinition [0] OCTET STRING OPTIONAL,
    //            referenceColourValue [1] OCTET STRING OPTIONAL,
    //            ...
    //    }

    ReferenceColourDefinitionAndValueBlock(ASN1Encodable asn1Encodable) {
      Map<Integer, ASN1Encodable> taggedObjects = ASN1Util.decodeTaggedObjects(asn1Encodable);
      if (taggedObjects.containsKey(0)) {
        referenceColourDefinition = ASN1OctetString.getInstance(taggedObjects.get(0)).getOctets();
      }
      if (taggedObjects.containsKey(1)) {
        referenceColourValue = ASN1OctetString.getInstance(taggedObjects.get(1)).getOctets();
      }
    }

    public byte[] getReferenceColourDefinition() {
      return referenceColourDefinition;
    }

    public byte[] getReferenceColourValue() {
      return referenceColourValue;
    }

    @Override
    public int hashCode() {
      final int prime = 31;
      int result = 1;
      result = prime * result + Arrays.hashCode(referenceColourDefinition);
      result = prime * result + Arrays.hashCode(referenceColourValue);
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

      ReferenceColourDefinitionAndValueBlock other = (ReferenceColourDefinitionAndValueBlock) obj;
      return Arrays.equals(referenceColourDefinition, other.referenceColourDefinition)
          && Arrays.equals(referenceColourValue, other.referenceColourValue);
    }

    @Override
    public String toString() {
      return "ReferenceColourDefinitionAndValueBlock ["
          + "referenceColourDefinition: " + Hex.bytesToHexString(referenceColourDefinition)
          + ", referenceColourValue: " + Hex.bytesToHexString(referenceColourValue)
          + "]";
    }

    /* PACKAGE */

    static List<ReferenceColourDefinitionAndValueBlock> decodeReferenceColourDefinitionAndValueBlocks(ASN1Encodable asn1Encodable) {
      if (ASN1Util.isSequenceOfSequences(asn1Encodable)) {
        List<ASN1Encodable> blockASN1Objects = ASN1Util.list(asn1Encodable);
        List<ReferenceColourDefinitionAndValueBlock> blocks = new ArrayList<ReferenceColourDefinitionAndValueBlock>(blockASN1Objects.size());
        for (ASN1Encodable blockASN1Object: blockASN1Objects) {
          blocks.add(new ReferenceColourDefinitionAndValueBlock(blockASN1Object));
        }
        return blocks;
      } else {
        return Collections.singletonList(new ReferenceColourDefinitionAndValueBlock(asn1Encodable));
      }
    }

    @Override
    ASN1Encodable getASN1Object() {
      Map<Integer, ASN1Encodable> taggedObjects = new HashMap<Integer, ASN1Encodable>();
      if (referenceColourDefinition != null) {
        taggedObjects.put(0, new DEROctetString(referenceColourDefinition));
      }
      if (referenceColourValue != null) {
        taggedObjects.put(1, new DEROctetString(referenceColourValue));
      }
      return ASN1Util.encodeTaggedObjects(taggedObjects);
    }
  }

  //  ReferenceColourMappingBlock ::= SEQUENCE {
  //    referenceColourSchema [0] OCTET STRING OPTIONAL,
  //    referenceColourDefinitionAndValueBlocks [1] ReferenceColourDefinitionAndValueBlocks OPTIONAL,
  //    ...
  // }

  private byte[] referenceColourSchema;

  private List<ReferenceColourDefinitionAndValueBlock> referenceColourDefinitionAndValueBlocks;

  public FaceImageReferenceColourMappingBlock(byte[] referenceColourSchema,
      List<ReferenceColourDefinitionAndValueBlock> referenceColourDefinitionAndValueBlocks) {
    this.referenceColourSchema = referenceColourSchema;
    this.referenceColourDefinitionAndValueBlocks = referenceColourDefinitionAndValueBlocks;
  }

  FaceImageReferenceColourMappingBlock(ASN1Encodable asn1Encodable) {
    Map<Integer, ASN1Encodable> taggedObjects = ASN1Util.decodeTaggedObjects(asn1Encodable);
    if (taggedObjects.containsKey(0)) {
      referenceColourSchema = ASN1OctetString.getInstance(taggedObjects.get(0)).getOctets();
    }
    if (taggedObjects.containsKey(1)) {
      referenceColourDefinitionAndValueBlocks = ReferenceColourDefinitionAndValueBlock.decodeReferenceColourDefinitionAndValueBlocks(taggedObjects.get(1));
    }
  }

  public byte[] getReferenceColourSchema() {
    return referenceColourSchema;
  }

  public List<ReferenceColourDefinitionAndValueBlock> getReferenceColourDefinitionAndValueBlocks() {
    return referenceColourDefinitionAndValueBlocks;
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + Arrays.hashCode(referenceColourSchema);
    result = prime * result + Objects.hash(referenceColourDefinitionAndValueBlocks);
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

    FaceImageReferenceColourMappingBlock other = (FaceImageReferenceColourMappingBlock) obj;
    return Objects.equals(referenceColourDefinitionAndValueBlocks, other.referenceColourDefinitionAndValueBlocks)
        && Arrays.equals(referenceColourSchema, other.referenceColourSchema);
  }

  @Override
  public String toString() {
    return "FaceImageReferenceColourMappingBlock ["
        + "referenceColourSchema: " + Hex.bytesToHexString(referenceColourSchema)
        + ", referenceColourDefinitionAndValueBlocks: " + referenceColourDefinitionAndValueBlocks
        + "]";
  }

  /* PACAKAGE */

  @Override
  ASN1Encodable getASN1Object() {
    Map<Integer, ASN1Encodable> taggedObjects = new HashMap<Integer, ASN1Encodable>();
    if (referenceColourSchema != null) {
      taggedObjects.put(0, new DEROctetString(referenceColourSchema));
    }
    if (referenceColourDefinitionAndValueBlocks != null) {
      taggedObjects.put(1, ISO39794Util.encodeBlocks(referenceColourDefinitionAndValueBlocks));
    }
    return ASN1Util.encodeTaggedObjects(taggedObjects);
  }
}
