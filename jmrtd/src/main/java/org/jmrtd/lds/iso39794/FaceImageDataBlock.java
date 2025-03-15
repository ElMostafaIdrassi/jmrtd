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

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
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

public class FaceImageDataBlock extends Block implements BiometricDataBlock {

  private static final long serialVersionUID = -7831183488053975281L;

  private int representationId;

  private VersionBlock versionBlock;
  private List<FaceImageRepresentationBlock> representationBlocks;

  private StandardBiometricHeader sbh;

  public FaceImageDataBlock(int representationId, VersionBlock versionBlock,
      List<FaceImageRepresentationBlock> representationBlocks, StandardBiometricHeader sbh) {
    this.representationId = representationId;
    this.versionBlock = versionBlock;
    this.representationBlocks = representationBlocks;
    this.sbh = sbh;
  }

  //  FaceImageDataBlock ::= [APPLICATION 5] SEQUENCE {
  //    versionBlock [0] VersionBlock,
  //    representationBlocks [1] RepresentationBlocks,
  //    ...
  //  }

  public FaceImageDataBlock(InputStream inputStream) throws IOException {
    this(null, inputStream);
  }

  public FaceImageDataBlock(StandardBiometricHeader sbh, InputStream inputStream) throws IOException {
    this(sbh, ASN1Util.readASN1Object(inputStream));
  }

  FaceImageDataBlock(StandardBiometricHeader sbh, ASN1Encodable asn1Encodable) {
    asn1Encodable = ASN1Util.checkTag(asn1Encodable, BERTags.APPLICATION, 5);
    if (!(asn1Encodable instanceof ASN1Sequence)) {
      throw new IllegalArgumentException("Cannot decode!");
    }

    Map<Integer, ASN1Encodable> taggedObjects = ASN1Util.decodeTaggedObjects(asn1Encodable);
    versionBlock = new VersionBlock(taggedObjects.get(0));
    representationBlocks = decodeRepresentationBlocks(taggedObjects.get(1));
  }

  public int getRepresentationId() {
    return representationId;
  }

  public VersionBlock getVersionBlock() {
    return versionBlock;
  }

  public List<FaceImageRepresentationBlock> getRepresentationBlocks() {
    return representationBlocks;
  }

  @Override
  public StandardBiometricHeader getStandardBiometricHeader() {
    return sbh;
  }

  @Override
  public int hashCode() {
    return Objects.hash(representationBlocks, representationId, sbh, versionBlock);
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

    FaceImageDataBlock other = (FaceImageDataBlock)obj;
    return Objects.equals(representationBlocks, other.representationBlocks)
        && representationId == other.representationId && Objects.equals(sbh, other.sbh)
        && Objects.equals(versionBlock, other.versionBlock);
  }

  @Override
  public String toString() {
    return "FaceImageDataBlock ["
        + "representationId: " + representationId
        + ", versionBlock: " + versionBlock
        + ", representationBlocks: " + representationBlocks
        + ", sbh: " + sbh
        + "]";
  }

  /* PRIVATE */

  // RepresentationBlocks ::= SEQUENCE SIZE (1) OF RepresentationBlock

  private static List<FaceImageRepresentationBlock> decodeRepresentationBlocks(ASN1Encodable asn1Encodable) {
    List<FaceImageRepresentationBlock> blocks = new ArrayList<FaceImageRepresentationBlock>();
    if (ASN1Util.isSequenceOfSequences(asn1Encodable)) {
      List<ASN1Encodable> blockASN1Objects = ASN1Util.list(asn1Encodable);
      for (ASN1Encodable blockASN1Object: blockASN1Objects) {
        blocks.add(new FaceImageRepresentationBlock(blockASN1Object));
      }
    } else {
      blocks.add(new FaceImageRepresentationBlock(asn1Encodable));
    }

    return blocks;
  }

  /* PACKAGE */

  @Override
  ASN1Encodable getASN1Object() {
    Map<Integer, ASN1Encodable> taggedObjects = new HashMap<Integer, ASN1Encodable>();
    taggedObjects.put(0, versionBlock.getASN1Object());
    taggedObjects.put(1, ISO39794Util.encodeBlocks(representationBlocks));
    return  new DERTaggedObject(5, ASN1Util.encodeTaggedObjects(taggedObjects));
  }
}
