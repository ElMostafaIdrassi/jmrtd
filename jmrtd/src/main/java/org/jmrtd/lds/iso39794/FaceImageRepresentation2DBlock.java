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

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.jmrtd.ASN1Util;
import org.jmrtd.lds.iso39794.FaceImageInformation2DBlock.ImageDataFormatCode;

public class FaceImageRepresentation2DBlock extends Block {

  private static final long serialVersionUID = 1942286473160393593L;

  private byte[] representationData2DBytes;

  private FaceImageInformation2DBlock imageInformation2DBlock;

  private FaceImageCaptureDevice2DBlock captureDevice2DBlock;

  public FaceImageRepresentation2DBlock(byte[] representationData2DBytes,
      FaceImageInformation2DBlock imageInformation2DBlock, FaceImageCaptureDevice2DBlock captureDevice2DBlock) {
    this.representationData2DBytes = representationData2DBytes;
    this.imageInformation2DBlock = imageInformation2DBlock;
    this.captureDevice2DBlock = captureDevice2DBlock;
  }

  //  ImageRepresentation2DBlock ::= SEQUENCE {
  //    representationData2D [0] OCTET STRING,
  //    imageInformation2DBlock [1] ImageInformation2DBlock,
  //    captureDevice2DBlock [2] CaptureDevice2DBlock OPTIONAL,
  //    ...
  //  }

  FaceImageRepresentation2DBlock(ASN1Encodable asn1Encodable) {
    if (!(asn1Encodable instanceof ASN1Sequence) && !(asn1Encodable instanceof ASN1TaggedObject)) {
      throw new IllegalArgumentException("Cannot decode!");
    }

    Map<Integer, ASN1Encodable> taggedObjects = ASN1Util.decodeTaggedObjects(asn1Encodable);
    representationData2DBytes = ASN1OctetString.getInstance(taggedObjects.get(0)).getOctets();
    imageInformation2DBlock = new FaceImageInformation2DBlock(taggedObjects.get(1));
    if (taggedObjects.containsKey(2)) {
      captureDevice2DBlock = new FaceImageCaptureDevice2DBlock(taggedObjects.get(2));
    }
  }

  public long getRepresentationData2DInputLength() {
    return representationData2DBytes == null ? 0 : representationData2DBytes.length;
  }

  public String getRepresentationData2DInputMimeType() {
    return ImageDataFormatCode.toMimeType(imageInformation2DBlock.getImageDataFormatCode());
  }

  public InputStream getRepresentationData2DInputStream() {
    return new ByteArrayInputStream(representationData2DBytes);
  }

  public FaceImageInformation2DBlock getImageInformation2DBlock() {
    return imageInformation2DBlock;
  }

  public FaceImageCaptureDevice2DBlock getCaptureDevice2DBlock() {
    return captureDevice2DBlock;
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + Arrays.hashCode(representationData2DBytes);
    result = prime * result + Objects.hash(captureDevice2DBlock, imageInformation2DBlock);
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

    FaceImageRepresentation2DBlock other = (FaceImageRepresentation2DBlock) obj;
    return Objects.equals(captureDevice2DBlock, other.captureDevice2DBlock)
        && Objects.equals(imageInformation2DBlock, other.imageInformation2DBlock)
        && Arrays.equals(representationData2DBytes, other.representationData2DBytes);
  }

  @Override
  public String toString() {
    return "FaceImageRepresentation2DBlock ["
        + "representationData2DBytes: " + (representationData2DBytes == null ? "-" : representationData2DBytes.length)
        + ", imageInformation2DBlock: " + imageInformation2DBlock
        + ", captureDevice2DBlock: " + captureDevice2DBlock
        + "]";
  }

  /* PACKAGE */

  @Override
  ASN1Encodable getASN1Object() {
    Map<Integer, ASN1Encodable> taggedObjects = new HashMap<Integer, ASN1Encodable>();
    taggedObjects.put(0, new DEROctetString(representationData2DBytes));
    taggedObjects.put(1, imageInformation2DBlock.getASN1Object());
    if (captureDevice2DBlock != null) {
      taggedObjects.put(2, captureDevice2DBlock.getASN1Object());
    }
    return ASN1Util.encodeTaggedObjects(taggedObjects);
  }
}
