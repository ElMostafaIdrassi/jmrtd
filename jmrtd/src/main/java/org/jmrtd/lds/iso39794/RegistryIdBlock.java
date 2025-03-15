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
import org.bouncycastle.asn1.ASN1Sequence;
import org.jmrtd.ASN1Util;

public class RegistryIdBlock extends Block {

  private static final long serialVersionUID = -5942649140248216405L;

  //  RegistryId ::= INTEGER (1..65535)
  //
  //  RegistryIdBlock ::= SEQUENCE {
  //    organization            [0] RegistryId,
  //    id                      [1] RegistryId
  //  }

  private int organization;

  private int id;

  public RegistryIdBlock(int organzation, int id) {
    this.organization = organzation;
    this.id = id;
  }

  RegistryIdBlock(ASN1Encodable asn1Encodable) {
    if (!(asn1Encodable instanceof ASN1Sequence)) {
      throw new IllegalArgumentException("Cannot decode!");
    }
    Map<Integer, ASN1Encodable> taggedObjects = ASN1Util.decodeTaggedObjects(asn1Encodable);
    organization = ASN1Util.decodeInt(taggedObjects.get(0));
    id = ASN1Util.decodeInt(taggedObjects.get(1));
  }

  public int getOrganization() {
    return organization;
  }

  public int getId() {
    return id;
  }

  @Override
  public int hashCode() {
    return Objects.hash(id, organization);
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

    RegistryIdBlock other = (RegistryIdBlock) obj;
    return id == other.id && organization == other.organization;
  }

  @Override
  public String toString() {
    return "RegistryIdBlock[organization: " + organization + ", id: " + id + "]";
  }

  ASN1Encodable getASN1Object() {
    Map<Integer, ASN1Encodable> taggedObjects = new HashMap<Integer, ASN1Encodable>();
    taggedObjects.put(0,ASN1Util.encodeInt(organization));
    taggedObjects.put(1, ASN1Util.encodeInt(id));
    return ASN1Util.encodeTaggedObjects(taggedObjects);
  }

  // RegistryId ::= INTEGER (1..65535)
  //
  // RegistryIdBlock ::= SEQUENCE {
  //        organization            [0] RegistryId,
  //        id                      [1] RegistryId
  // }

  // CertificationIdBlock ::= RegistryIdBlock
  //
  // CertificationIdBlocks ::= SEQUENCE OF CertificationIdBlock

  static List<RegistryIdBlock> decodeRegistryIdBlocks(ASN1Encodable asn1Encodable) {
    if (ASN1Util.isSequenceOfSequences(asn1Encodable)) {
      List<ASN1Encodable> blockASN1Objects = ASN1Util.list(asn1Encodable);
      List<RegistryIdBlock> blocks = new ArrayList<RegistryIdBlock>(blockASN1Objects.size());
      for (ASN1Encodable blockASN1Object: blockASN1Objects) {
        blocks.add(new RegistryIdBlock(blockASN1Object));
      }
      return blocks;
    } else {
      return Collections.singletonList(new RegistryIdBlock(asn1Encodable));
    }
  }
}
