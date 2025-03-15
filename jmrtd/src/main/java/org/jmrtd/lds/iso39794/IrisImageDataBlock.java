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
 * Based on ISO-IEC-39794-6-ed-1-v1. Disclaimer:
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

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERTaggedObject;
import org.jmrtd.ASN1Util;
import org.jmrtd.cbeff.BiometricDataBlock;
import org.jmrtd.cbeff.StandardBiometricHeader;

public class IrisImageDataBlock extends Block implements BiometricDataBlock {

  private static final long serialVersionUID = 5915816895542698638L;

  private StandardBiometricHeader sbh;

  private VersionBlock versionBlock;

  private List<IrisImageRepresentationBlock> representationBlocks;

  public IrisImageDataBlock(InputStream inputStream) throws IOException {
    this(null, inputStream);
  }

  public IrisImageDataBlock(StandardBiometricHeader sbh, InputStream inputStream) throws IOException {
    this(sbh, ASN1Util.readASN1Object(inputStream));
  }

  //  IrisImageDataBlock ::= [APPLICATION 6] SEQUENCE {
  //    versionBlock         [0]   VersionBlock,
  //    representationBlocks [1]   RepresentationBlocks,
  //    ...
  //  }

  IrisImageDataBlock(StandardBiometricHeader sbh, ASN1Encodable asn1Encodable) {
    asn1Encodable = ASN1Util.checkTag(asn1Encodable, BERTags.APPLICATION, 6);
    if (!(asn1Encodable instanceof ASN1Sequence)) {
      throw new IllegalArgumentException("Cannot decode!");
    }

    Map<Integer, ASN1Encodable> taggedObjects = ASN1Util.decodeTaggedObjects(asn1Encodable);

    versionBlock = new VersionBlock(taggedObjects.get(0));

    representationBlocks = IrisImageRepresentationBlock.decodeRepresentationBlocks(taggedObjects.get(1));
  }

  public VersionBlock getVersionBlock() {
    return versionBlock;
  }

  public List<IrisImageRepresentationBlock> getRepresentationBlocks() {
    return representationBlocks;
  }

  @Override
  public StandardBiometricHeader getStandardBiometricHeader() {
    return sbh;
  }

  @Override
  public int hashCode() {
    return Objects.hash(representationBlocks, sbh, versionBlock);
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

    IrisImageDataBlock other = (IrisImageDataBlock) obj;
    return Objects.equals(representationBlocks, other.representationBlocks) && Objects.equals(sbh, other.sbh)
        && Objects.equals(versionBlock, other.versionBlock);
  }

  @Override
  public String toString() {
    return "IrisImageDataBlock ["
        + "sbh: " + sbh
        + ", versionBlock: " + versionBlock
        + ", representationBlocks: " + representationBlocks
        + "]";
  }

  /* PACKAGE */

  @Override
  ASN1Encodable getASN1Object() {
    Map<Integer, ASN1Encodable> taggedObjects = new HashMap<Integer, ASN1Encodable>();
    taggedObjects.put(0, versionBlock.getASN1Object());
    taggedObjects.put(1, ISO39794Util.encodeBlocks(representationBlocks));
    return  new DERTaggedObject(6, ASN1Util.encodeTaggedObjects(taggedObjects));
  }
}
