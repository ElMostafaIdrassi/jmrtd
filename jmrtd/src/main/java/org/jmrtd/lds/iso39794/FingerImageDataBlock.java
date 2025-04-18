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

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.SortedMap;
import java.util.TreeMap;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERTaggedObject;
import org.jmrtd.ASN1Util;
import org.jmrtd.cbeff.BiometricDataBlock;
import org.jmrtd.cbeff.CBEFFInfo;
import org.jmrtd.cbeff.ISO781611;
import org.jmrtd.cbeff.StandardBiometricHeader;

public class FingerImageDataBlock extends Block implements BiometricDataBlock {

  private static final long serialVersionUID = -7831183486053375281L;

  private VersionBlock versionBlock;
  private List<FingerImageRepresentationBlock> representationBlocks;

  private StandardBiometricHeader sbh;

  public FingerImageDataBlock(VersionBlock versionBlock,
      List<FingerImageRepresentationBlock> representationBlocks,
      StandardBiometricHeader sbh) {
    this.versionBlock = versionBlock;
    this.representationBlocks = representationBlocks;
    this.sbh = sbh;
  }

  public FingerImageDataBlock(InputStream inputStream) throws IOException {
    this(null, inputStream);
  }

  public FingerImageDataBlock(StandardBiometricHeader sbh, InputStream inputStream) throws IOException {
    this(sbh, ASN1Util.readASN1Object(inputStream));
  }

  //  FingerImageDataBlock ::= [APPLICATION 4] SEQUENCE {
  //    versionBlock [0] VersionBlock,
  //    representationBlocks [1] RepresentationBlocks,
  //    ...
  //  }

  FingerImageDataBlock(StandardBiometricHeader sbh, ASN1Encodable asn1Encodable) {
    this.sbh = sbh;
    asn1Encodable = ASN1Util.checkTag(asn1Encodable, BERTags.APPLICATION, 4);
    if (!(asn1Encodable instanceof ASN1Sequence)) {
      throw new IllegalArgumentException("Cannot decode!");
    }

    Map<Integer, ASN1Encodable> taggedObjects = ASN1Util.decodeTaggedObjects(asn1Encodable);
    versionBlock = new VersionBlock(taggedObjects.get(0));
    representationBlocks = FingerImageRepresentationBlock.decodeRepresentationBlocks(taggedObjects.get(1));
  }

  public VersionBlock getVersionBlock() {
    return versionBlock;
  }

  public List<FingerImageRepresentationBlock> getRepresentationBlocks() {
    return representationBlocks;
  }

  @Override
  /**
   * Returns the standard biometric header of this biometric data block.
   *
   * @return the standard biometric header
   */
  public StandardBiometricHeader getStandardBiometricHeader() {
    if (sbh == null) {
      byte[] biometricType = { (byte)CBEFFInfo.BIOMETRIC_TYPE_FINGERPRINT };
      byte[] biometricSubtype = { (byte)getBiometricSubtype() };
      byte[] formatOwner = { (byte)((StandardBiometricHeader.JTC1_SC37_FORMAT_OWNER_VALUE & 0xFF00) >> 8), (byte)(StandardBiometricHeader.JTC1_SC37_FORMAT_OWNER_VALUE & 0xFF) };
      byte[] formatType = { (byte)((StandardBiometricHeader.ISO_39794_FINGER_IMAGE_FORMAT_TYPE_VALUE & 0xFF00) >> 8), (byte)(StandardBiometricHeader.ISO_39794_FINGER_IMAGE_FORMAT_TYPE_VALUE & 0xFF) };

      SortedMap<Integer, byte[]> elements = new TreeMap<Integer, byte[]>();
      elements.put(ISO781611.BIOMETRIC_TYPE_TAG, biometricType); // 81 -> 08 == finger
      elements.put(ISO781611.BIOMETRIC_SUBTYPE_TAG, biometricSubtype); // 82 -> depends on left/right and finger
      elements.put(ISO781611.FORMAT_OWNER_TAG, formatOwner); // 87 -> 0101
      elements.put(ISO781611.FORMAT_TYPE_TAG, formatType); // 88 -> 0028, corresponds to g3-binary-finger-image

      sbh = new StandardBiometricHeader(elements);
    }
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

    FingerImageDataBlock other = (FingerImageDataBlock) obj;
    return Objects.equals(representationBlocks, other.representationBlocks) && Objects.equals(sbh, other.sbh)
        && Objects.equals(versionBlock, other.versionBlock);
  }

  @Override
  public String toString() {
    return "FingerImageDataBlock ["
        + "versionBlock: " + versionBlock
        + ", representationBlocks: " + representationBlocks
        + ", sbh: " + sbh
        + "]";
  }

  /* PACKAGE */

  @Override
  ASN1Encodable getASN1Object() {
    Map<Integer, ASN1Encodable> taggedObjects = new HashMap<Integer, ASN1Encodable>();
    taggedObjects.put(0, versionBlock.getASN1Object());
    taggedObjects.put(1, ISO39794Util.encodeBlocks(representationBlocks));
    return  new DERTaggedObject(4, ASN1Util.encodeTaggedObjects(taggedObjects));
  }

  /* PRIVATE */

  /**
   * Returns the biometric sub-type bit mask for the fingers in this finger info.
   *
   * @return a biometric sub-type bit mask
   */
  private int getBiometricSubtype() {
    int result = CBEFFInfo.BIOMETRIC_SUBTYPE_NONE;
    boolean isFirst = true;

    List<FingerImageRepresentationBlock> blocks =     getRepresentationBlocks();;
    for (FingerImageRepresentationBlock block: blocks) {
      int subType = block.getBiometricSubtype();
      if (isFirst) {
        result = subType;
        isFirst = false;
      } else {
        result &= subType;
      }
    }
    return result;
  }
}
