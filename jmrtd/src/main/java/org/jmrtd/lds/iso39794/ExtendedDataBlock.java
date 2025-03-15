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
import org.jmrtd.ASN1Util;

public class ExtendedDataBlock extends Block {

  private static final long serialVersionUID = -1557206933986460059L;

  //  ExtendedDataBlock ::= SEQUENCE {
  //    dataTypeIdBlock         [0] RegistryIdBlock,
  //    data                    [1] OCTET STRING
  //  }

  private RegistryIdBlock dataTypeIdBlock;

  private byte[] data;

  public ExtendedDataBlock(RegistryIdBlock dataTypeIdBlock, byte[] data) {
    this.dataTypeIdBlock = dataTypeIdBlock;
    this.data = data;
  }

  ExtendedDataBlock(ASN1Encodable asn1Encodable) {
    Map<Integer, ASN1Encodable> taggedObjects = ASN1Util.decodeTaggedObjects(asn1Encodable);
    dataTypeIdBlock = new RegistryIdBlock(taggedObjects.get(0));
    data = ASN1OctetString.getInstance(taggedObjects.get(1)).getOctets();
  }

  public RegistryIdBlock getDataTypeIdBlock() {
    return dataTypeIdBlock;
  }

  public byte[] getData() {
    return data;
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + Arrays.hashCode(data);
    result = prime * result + Objects.hash(dataTypeIdBlock);
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

    ExtendedDataBlock other = (ExtendedDataBlock)obj;
    return Arrays.equals(data, other.data) && Objects.equals(dataTypeIdBlock, other.dataTypeIdBlock);
  }

  @Override
  public String toString() {
    return "ExtendedDataBlock ["
        + "dataTypeIdBlock: " + dataTypeIdBlock
        + ", data: " + data.length
        + "]";
  }

  /* PACKAGE */

  static List<ExtendedDataBlock> decodeExtendedDataBlocks(ASN1Encodable asn1Encodable) {
    if (ASN1Util.isSequenceOfSequences(asn1Encodable)) {
      List<ASN1Encodable> blockASN1Objects = ASN1Util.list(asn1Encodable);
      List<ExtendedDataBlock> blocks = new ArrayList<ExtendedDataBlock>(blockASN1Objects.size());
      for (ASN1Encodable blockASN1Object: blockASN1Objects) {
        blocks.add(new ExtendedDataBlock(blockASN1Object));
      }
      return blocks;
    } else {
      return Collections.singletonList(new ExtendedDataBlock(asn1Encodable));
    }
  }

  @Override
  ASN1Encodable getASN1Object() {
    Map<Integer, ASN1Encodable> taggedObjects = new HashMap<Integer, ASN1Encodable>();
    taggedObjects.put(0, dataTypeIdBlock.getASN1Object());
    taggedObjects.put(1, new DEROctetString(data));
    return ASN1Util.encodeTaggedObjects(taggedObjects);
  }
}
