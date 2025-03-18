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

import java.io.InputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.bouncycastle.asn1.ASN1Encodable;
import org.jmrtd.ASN1Util;
import org.jmrtd.lds.ImageInfo;

public class FaceImageRepresentationBlock extends Block implements ImageInfo {

  private static final long serialVersionUID = -8372278398595506771L;

  private BigInteger representationId;

  private FaceImageRepresentation2DBlock imageRepresentation2DBlock;

  private DateTimeBlock captureDateTimeBlock;

  private List<QualityBlock> qualityBlocks;

  private List<PADDataBlock> padDataBlocks;

  private BigInteger sessionId;

  private BigInteger derivedFrom;

  private FaceImageCaptureDeviceBlock captureDeviceBlock;

  private FaceImageIdentityMetadataBlock identityMetadataBlock;

  private List<FaceImageLandmarkBlock> landmarkBlocks;

  public FaceImageRepresentationBlock(BigInteger representationId,
      FaceImageRepresentation2DBlock imageRepresentation2DBlock, DateTimeBlock captureDateTimeBlock,
      List<QualityBlock> qualityBlocks, List<PADDataBlock> padDataBlocks, BigInteger sessionId, BigInteger derivedFrom,
      FaceImageCaptureDeviceBlock captureDeviceBlock, FaceImageIdentityMetadataBlock identityMetadataBlock,
      List<FaceImageLandmarkBlock> landmarkBlocks) {
    this.representationId = representationId;
    this.imageRepresentation2DBlock = imageRepresentation2DBlock;
    this.captureDateTimeBlock = captureDateTimeBlock;
    this.qualityBlocks = qualityBlocks;
    this.padDataBlocks = padDataBlocks;
    this.sessionId = sessionId;
    this.derivedFrom = derivedFrom;
    this.captureDeviceBlock = captureDeviceBlock;
    this.identityMetadataBlock = identityMetadataBlock;
    this.landmarkBlocks = landmarkBlocks;
  }

  //  RepresentationBlock ::= SEQUENCE {
  //    representationId [0] INTEGER (0..MAX),
  //    imageRepresentation [1] ImageRepresentation,
  //    captureDateTimeBlock [2] CaptureDateTimeBlock OPTIONAL,
  //    qualityBlocks [3] QualityBlocks OPTIONAL,
  //    padDataBlock [4] PADDataBlock OPTIONAL,
  //    sessionId [5] INTEGER (0..MAX) OPTIONAL,
  //    derivedFrom [6] INTEGER (0..MAX) OPTIONAL,
  //    captureDeviceBlock [7] CaptureDeviceBlock OPTIONAL,
  //    identityMetadataBlock [8] IdentityMetadataBlock OPTIONAL,
  //    landmarkBlocks [9] LandmarkBlocks OPTIONAL,
  //    ...
  //  }

  FaceImageRepresentationBlock(ASN1Encodable asn1Encodable) {
    Map<Integer, ASN1Encodable> taggedObjects = ASN1Util.decodeTaggedObjects(asn1Encodable);
    representationId = ASN1Util.decodeBigInteger(taggedObjects.get(0));
    imageRepresentation2DBlock = decodeImageRepresentation2DBlock(taggedObjects.get(1));
    if (taggedObjects.containsKey(2))  {
      captureDateTimeBlock = new DateTimeBlock(taggedObjects.get(2));
    }
    if (taggedObjects.containsKey(3)) {
      qualityBlocks = QualityBlock.decodeQualityBlocks(taggedObjects.get(3));
    }
    if (taggedObjects.containsKey(4)) {
      padDataBlocks = PADDataBlock.decodePADDataBlocks(taggedObjects.get(4));
    }
    if (taggedObjects.containsKey(5)) {
      sessionId = ASN1Util.decodeBigInteger(taggedObjects.get(5));
    }
    if (taggedObjects.containsKey(6)) {
      derivedFrom = ASN1Util.decodeBigInteger(taggedObjects.get(6));
    }
    if (taggedObjects.containsKey(7)) {
      captureDeviceBlock = new FaceImageCaptureDeviceBlock(taggedObjects.get(7));
    }
    if (taggedObjects.containsKey(8)) {
      identityMetadataBlock = new FaceImageIdentityMetadataBlock(taggedObjects.get(8));
    }
    if (taggedObjects.containsKey(9)) {
      landmarkBlocks = FaceImageLandmarkBlock.decodeLandmarkBlocks(taggedObjects.get(9));
    }
  }

  public BigInteger getRepresentationId() {
    return representationId;
  }

  public FaceImageRepresentation2DBlock getImageRepresentation2DBlock() {
    return imageRepresentation2DBlock;
  }

  public FaceImageIdentityMetadataBlock getIdentityMetadataBlock() {
    return identityMetadataBlock;
  }

  public List<FaceImageLandmarkBlock> getLandmarkBlocks() {
    return landmarkBlocks;
  }

  public FaceImageCaptureDeviceBlock getCaptureDeviceBlock() {
    return captureDeviceBlock;
  }

  public DateTimeBlock getCaptureDateTimeBlock() {
    return captureDateTimeBlock;
  }

  public List<QualityBlock> getQualityBlocks() {
    return qualityBlocks;
  }

  public List<PADDataBlock> getPadDataBlocks() {
    return padDataBlocks;
  }

  public BigInteger getSessionId() {
    return sessionId;
  }

  public BigInteger getDerivedFrom() {
    return derivedFrom;
  }

  @Override
  public int hashCode() {
    return Objects.hash(captureDateTimeBlock, captureDeviceBlock, derivedFrom, identityMetadataBlock,
        imageRepresentation2DBlock, landmarkBlocks, padDataBlocks, qualityBlocks, representationId, sessionId);
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

    FaceImageRepresentationBlock other = (FaceImageRepresentationBlock) obj;
    return Objects.equals(captureDateTimeBlock, other.captureDateTimeBlock)
        && Objects.equals(captureDeviceBlock, other.captureDeviceBlock)
        && Objects.equals(derivedFrom, other.derivedFrom)
        && Objects.equals(identityMetadataBlock, other.identityMetadataBlock)
        && Objects.equals(imageRepresentation2DBlock, other.imageRepresentation2DBlock)
        && Objects.equals(landmarkBlocks, other.landmarkBlocks) && Objects.equals(padDataBlocks, other.padDataBlocks)
        && Objects.equals(qualityBlocks, other.qualityBlocks)
        && Objects.equals(representationId, other.representationId) && Objects.equals(sessionId, other.sessionId);
  }

  @Override
  public String toString() {
    return "FaceImageRepresentationBlock ["
        + "representationId: " + representationId
        + ", imageRepresentation: " + imageRepresentation2DBlock
        + ", captureDateTimeBlock: " + captureDateTimeBlock
        + ", qualityBlocks: " + qualityBlocks
        + ", padDataBlocks: " + padDataBlocks
        + ", sessionId: " + sessionId
        + ", derivedFrom: " + derivedFrom
        + ", captureDeviceBlock: " + captureDeviceBlock
        + ", identityMetadataBlock: " + identityMetadataBlock
        + ", landmarkBlocks: " + landmarkBlocks
        + "]";
  }

  /* PRIVATE */

  //  ImageRepresentation ::= CHOICE {
  //    base [0] ImageRepresentationBase,
  //    extensionBlock [1] ImageRepresentationExtensionBlock
  //  }
  //
  //  ImageRepresentationBase ::= CHOICE {
  //    imageRepresentation2DBlock [0] ImageRepresentation2DBlock
  //  }
  //
  //  ImageRepresentationExtensionBlock ::= SEQUENCE {
  //    ...
  //  }

  private static FaceImageRepresentation2DBlock decodeImageRepresentation2DBlock(ASN1Encodable asn1Encodable) {
    Map<Integer, ASN1Encodable> taggedObjects = ASN1Util.decodeTaggedObjects(asn1Encodable);
    if (taggedObjects.containsKey(0)) {
      Map<Integer, ASN1Encodable> baseTaggedObjects = ASN1Util.decodeTaggedObjects(taggedObjects.get(0));
      if (baseTaggedObjects.containsKey(0)) {
        return new FaceImageRepresentation2DBlock(baseTaggedObjects.get(0));
      }

      /* NOTE: Not supporting [1] ShapeRepresentation3DBlock... */
    }

    return null;
  }

  private static ASN1Encodable encodeImageRepresentation2DBlock(FaceImageRepresentation2DBlock faceImageRepresentation2DBlock) {
    Map<Integer, ASN1Encodable> baseTaggedObjects = new HashMap<Integer, ASN1Encodable>();
    baseTaggedObjects.put(0, faceImageRepresentation2DBlock.getASN1Object());

    Map<Integer, ASN1Encodable> taggedObjects = new HashMap<Integer, ASN1Encodable>();
    taggedObjects.put(0, ASN1Util.encodeTaggedObjects(baseTaggedObjects));
    return ASN1Util.encodeTaggedObjects(taggedObjects);
  }

  @Override
  public int getType() {
    return TYPE_PORTRAIT;
  }

  @Override
  public String getMimeType() {
    if (imageRepresentation2DBlock == null) {
      return "image/raw";
    }
    return imageRepresentation2DBlock.getRepresentationData2DInputMimeType();
  }

  @Override
  public int getWidth() {
    if (imageRepresentation2DBlock == null) {
      return 0;
    }
    FaceImageInformation2DBlock faceImageInformation2DBlock = imageRepresentation2DBlock.getImageInformation2DBlock();
    if (faceImageInformation2DBlock == null) {
      return 0;
    }
    FaceImageInformation2DBlock.ImageSizeBlock imageSizeBlock = faceImageInformation2DBlock.getImageSizeBlock();
    if (imageSizeBlock == null) {
      return 0;
    }
    return imageSizeBlock.getWidth();
  }

  @Override
  public int getHeight() {
    if (imageRepresentation2DBlock == null) {
      return 0;
    }
    FaceImageInformation2DBlock faceImageInformation2DBlock = imageRepresentation2DBlock.getImageInformation2DBlock();
    if (faceImageInformation2DBlock == null) {
      return 0;
    }
    FaceImageInformation2DBlock.ImageSizeBlock imageSizeBlock = faceImageInformation2DBlock.getImageSizeBlock();
    if (imageSizeBlock == null) {
      return 0;
    }
    return imageSizeBlock.getWidth();
  }

  @Override
  public long getRecordLength() {
    return 0;
  }

  @Override
  public int getImageLength() {
    if (imageRepresentation2DBlock == null) {
      return 0;
    }
    return (int)imageRepresentation2DBlock.getRepresentationData2DInputLength();
  }

  @Override
  public InputStream getImageInputStream() {
    if (imageRepresentation2DBlock == null) {
      return null;
    }
    return imageRepresentation2DBlock.getRepresentationData2DInputStream();
  }

  /* PACKAGE */

  @Override
  ASN1Encodable getASN1Object() {
    Map<Integer, ASN1Encodable> taggedObjects = new HashMap<Integer, ASN1Encodable>();
    taggedObjects.put(0, ASN1Util.encodeBigInteger(representationId));
    taggedObjects.put(1, encodeImageRepresentation2DBlock(imageRepresentation2DBlock));
    if (captureDateTimeBlock != null) {
      taggedObjects.put(2, captureDateTimeBlock.getASN1Object());
    }
    if (qualityBlocks != null) {
      taggedObjects.put(3, ISO39794Util.encodeBlocks(qualityBlocks));
    }
    if (padDataBlocks != null) {
      taggedObjects.put(4, ISO39794Util.encodeBlocks(padDataBlocks));
    }
    if (sessionId != null) {
      taggedObjects.put(5, ASN1Util.encodeBigInteger(sessionId));
    }
    if (derivedFrom != null) {
      taggedObjects.put(6, ASN1Util.encodeBigInteger(derivedFrom));
    }
    if (captureDeviceBlock != null) {
      taggedObjects.put(7, captureDeviceBlock.getASN1Object());
    }
    if (identityMetadataBlock != null) {
      taggedObjects.put(8, identityMetadataBlock.getASN1Object());
    }
    if (landmarkBlocks != null) {
      taggedObjects.put(9, ISO39794Util.encodeBlocks(landmarkBlocks));
    }
    return ASN1Util.encodeTaggedObjects(taggedObjects);
  }

  // RepresentationBlocks ::= SEQUENCE SIZE (1) OF RepresentationBlock

  static List<FaceImageRepresentationBlock> decodeRepresentationBlocks(ASN1Encodable asn1Encodable) {
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
}
