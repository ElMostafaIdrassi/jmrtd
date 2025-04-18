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

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1VisibleString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERVisibleString;
import org.jmrtd.ASN1Util;
import org.jmrtd.cbeff.CBEFFInfo;
import org.jmrtd.lds.ImageInfo;

public class FingerImageRepresentationBlock extends Block implements ImageInfo {

  private static final long serialVersionUID = -9136319709147388829L;

  public static enum ImpressionCode implements EncodableEnum<ImpressionCode> {
    PLAIN_CONTACT(0),
    ROLLED_CONTACT(1),
    LATENT_IMAGE(4),
    SWIPE_CONTACT(8),
    STATIONARY_SUBJECT_CONTACTLESS_PLAIN(24),
    STATIONARY_SUBJECT_CONTACTLESS_ROLLED(25),
    MOVING_SUBJECT_CONTACTLESS_PLAIN(41),
    MOVING_SUBJECT_CONTACTLESS_ROLLED(42),
    OTHER_IMPRESSION(28),
    UNKNOWN_IMPRESSION(29);

    private int code;

    private ImpressionCode(int code) {
      this.code = code;
    }

    @Override
    public int getCode() {
      return code;
    }

    public static ImpressionCode fromCode(int code) {
      return EncodableEnum.fromCode(code, ImpressionCode.class);
    }
  }

  public static enum ImageDataFormatCode implements EncodableEnum<ImageDataFormatCode> {
    PGM(0, "image/pgm"),
    WSQ(1, "image/x-wsq"),
    JPEG2000_LOSSY(2, "image/jp2"),
    JPEG2000_LOSSLESS(3, "image/jp2"),
    PNG(4, "image/png");

    private int code;
    private String mimeType;

    private ImageDataFormatCode(int code, String mimeType) {
      this.code = code;
    }

    @Override
    public int getCode() {
      return code;
    }

    public String getMimeType() {
      return mimeType;
    }

    public static ImageDataFormatCode fromCode(int code) {
      return EncodableEnum.fromCode(code, ImageDataFormatCode.class);
    }
  }

  private FingerImagePositionCode position;

  private ImpressionCode impression;

  private ImageDataFormatCode imageDataFormat;

  private DateTimeBlock captureDateTimeBlock;

  private FingerImageCaptureDeviceBlock captureDeviceBlock;

  private List<QualityBlock> qualityBlocks;

  private FingerImageSpatialSamplingRateBlock spatialSamplingRateBlock;

  private Boolean isPositionComputedByCaptureSystem;

  /** INTEGER (0..359) */
  private Integer fingerRotation;

  private Boolean isImageRotatedToVertical;

  private Boolean isImageHasBeenLossilyCompressed;

  private List<FingerImageSegmentationBlock> segmentationBlocks;

  private List<FingerImageAnnotationBlock> annotationBlocks;

  private PADDataBlock padDataBlock;

  private byte[] imageData;

  private List<String> commentBlocks;

  private List<ExtendedDataBlock> vendorSpecificDataBlocks;

  public FingerImageRepresentationBlock(FingerImagePositionCode position, ImpressionCode impression,
      ImageDataFormatCode imageDataFormat, DateTimeBlock captureDateTimeBlock,
      FingerImageCaptureDeviceBlock captureDeviceBlock, List<QualityBlock> qualityBlocks,
      FingerImageSpatialSamplingRateBlock spatialSamplingRateBlock, Boolean isPositionComputedByCaptureSystem,
      Integer fingerRotation, Boolean isImageRotatedToVertical, Boolean isImageHasBeenLossilyCompressed,
      List<FingerImageSegmentationBlock> segmentationBlocks, List<FingerImageAnnotationBlock> annotationBlocks,
      PADDataBlock padDataBlock, byte[] imageData, List<String> commentBlocks,
      List<ExtendedDataBlock> vendorSpecificDataBlocks) {
    this.position = position;
    this.impression = impression;
    this.imageDataFormat = imageDataFormat;
    this.captureDateTimeBlock = captureDateTimeBlock;
    this.captureDeviceBlock = captureDeviceBlock;
    this.qualityBlocks = qualityBlocks;
    this.spatialSamplingRateBlock = spatialSamplingRateBlock;
    this.isPositionComputedByCaptureSystem = isPositionComputedByCaptureSystem;
    this.fingerRotation = fingerRotation;
    this.isImageRotatedToVertical = isImageRotatedToVertical;
    this.isImageHasBeenLossilyCompressed = isImageHasBeenLossilyCompressed;
    this.segmentationBlocks = segmentationBlocks;
    this.annotationBlocks = annotationBlocks;
    this.padDataBlock = padDataBlock;
    this.imageData = imageData;
    this.commentBlocks = commentBlocks;
    this.vendorSpecificDataBlocks = vendorSpecificDataBlocks;
  }

  //  RepresentationBlock ::= SEQUENCE {
  //    position [0] Position,
  //    impression [1] Impression,
  //    imageDataFormat [2] ImageDataFormat,
  //    imageData [3] OCTET STRING,
  //    captureDateTimeBlock [4] CaptureDateTimeBlock OPTIONAL,
  //    captureDeviceBlock [5] CaptureDeviceBlock OPTIONAL,
  //    qualityBlocks [6] QualityBlocks OPTIONAL,
  //    spatialSamplingRateBlock [7] SpatialSamplingRateBlock OPTIONAL,
  //    positionComputedByCaptureSystem [8] BOOLEAN OPTIONAL,
  //    originalRotation [9] FingerRotation OPTIONAL,
  //    imageRotatedToVertical [10] BOOLEAN OPTIONAL,
  //    imageHasBeenLossilyCompressed [11] BOOLEAN OPTIONAL,
  //    segmentationBlocks [12] SegmentationBlocks OPTIONAL,
  //    annotationBlocks [13] AnnotationBlocks OPTIONAL,
  //    pADDataBlock [14] PADDataBlock OPTIONAL,
  //    commentBlocks [15] CommentBlocks OPTIONAL,
  //    vendorSpecificDataBlocks [16] VendorSpecificDataBlocks OPTIONAL,
  //    ...
  //  }

  FingerImageRepresentationBlock(ASN1Encodable asn1Encodable) {
    if (asn1Encodable == null) {
      throw new IllegalArgumentException("Cannot decode!");
    }
    Map<Integer, ASN1Encodable> taggedObjects = ASN1Util.decodeTaggedObjects(asn1Encodable);
    position = FingerImagePositionCode.fromCode(ISO39794Util.decodeCodeFromChoiceExtensionBlockFallback(taggedObjects.get(0)));
    impression = ImpressionCode.fromCode(ISO39794Util.decodeCodeFromChoiceExtensionBlockFallback(taggedObjects.get(1)));
    imageDataFormat = ImageDataFormatCode.fromCode(ISO39794Util.decodeCodeFromChoiceExtensionBlockFallback(taggedObjects.get(2)));
    imageData = (ASN1OctetString.getInstance(taggedObjects.get(3))).getOctets();
    if (taggedObjects.containsKey(4)) {
      captureDateTimeBlock = new DateTimeBlock(taggedObjects.get(4));
    }
    if (taggedObjects.containsKey(5)) {
      captureDeviceBlock = new FingerImageCaptureDeviceBlock(taggedObjects.get(5));
    }
    if (taggedObjects.containsKey(6)) {
      qualityBlocks = QualityBlock.decodeQualityBlocks(taggedObjects.get(6));
    }
    if (taggedObjects.containsKey(7)) {
      spatialSamplingRateBlock = new FingerImageSpatialSamplingRateBlock(taggedObjects.get(7));
    }
    if (taggedObjects.containsKey(8)) {
      isPositionComputedByCaptureSystem = ASN1Util.decodeBoolean(taggedObjects.get(8));
    }
    if (taggedObjects.containsKey(9)) {
      fingerRotation = ASN1Util.decodeInt(taggedObjects.get(9));
    }
    if (taggedObjects.containsKey(10)) {
      isImageRotatedToVertical = ASN1Util.decodeBoolean(taggedObjects.get(10));
    }
    if (taggedObjects.containsKey(11)) {
      isImageHasBeenLossilyCompressed = ASN1Util.decodeBoolean(taggedObjects.get(11));
    }
    if (taggedObjects.containsKey(12)) {
      segmentationBlocks = FingerImageSegmentationBlock.decodeFingerImageSegmentationBlocks(taggedObjects.get(12));
    }
    if (taggedObjects.containsKey(13)) {
      annotationBlocks = FingerImageAnnotationBlock.decodeFingerImageAnnotationBlocks(taggedObjects.get(13));
    }
    if (taggedObjects.containsKey(14)) {
      padDataBlock = new PADDataBlock(taggedObjects.get(14));
    }
    if (taggedObjects.containsKey(15)) {
      commentBlocks = decodeCommentBlocks(taggedObjects.get(15));
    }
    if (taggedObjects.containsKey(16)) {
      vendorSpecificDataBlocks = ExtendedDataBlock.decodeExtendedDataBlocks(taggedObjects.get(16));
    }
  }

  public FingerImagePositionCode getPosition() {
    return position;
  }

  public ImpressionCode getImpression() {
    return impression;
  }

  public FingerImageCaptureDeviceBlock getCaptureDeviceBlock() {
    return captureDeviceBlock;
  }

  public DateTimeBlock getCaptureDateTimeBlock() {
    return captureDateTimeBlock;
  }

  public ImageDataFormatCode getImageDataFormat() {
    return imageDataFormat;
  }

  public List<QualityBlock> getQualityBlocks() {
    return qualityBlocks;
  }

  public FingerImageSpatialSamplingRateBlock getSpatialSamplingRateBlock() {
    return spatialSamplingRateBlock;
  }

  public Boolean isPositionComputedByCaptureSystem() {
    return isPositionComputedByCaptureSystem;
  }

  public Integer getFingerRotation() {
    return fingerRotation;
  }

  public Boolean getIsImageRotatedToVertical() {
    return isImageRotatedToVertical;
  }

  public Boolean getIsImageHasBeenLossilyCompressed() {
    return isImageHasBeenLossilyCompressed;
  }

  public List<FingerImageSegmentationBlock> getSegmentationBlocks() {
    return segmentationBlocks;
  }

  public PADDataBlock getPadDataBlock() {
    return padDataBlock;
  }

  public List<FingerImageAnnotationBlock> getAnnotationBlocks() {
    return annotationBlocks;
  }

  public List<String> getCommentBlocks() {
    return commentBlocks;
  }

  public List<ExtendedDataBlock> getVendorSpecificDataBlocks() {
    return vendorSpecificDataBlocks;
  }

  public byte[] geImageData() {
    return imageData;
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + Arrays.hashCode(imageData);
    result = prime * result + Objects.hash(annotationBlocks, captureDateTimeBlock, captureDeviceBlock, commentBlocks,
        fingerRotation, imageDataFormat, impression, isImageHasBeenLossilyCompressed, isImageRotatedToVertical,
        isPositionComputedByCaptureSystem, padDataBlock, position, qualityBlocks, segmentationBlocks,
        spatialSamplingRateBlock, vendorSpecificDataBlocks);
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

    FingerImageRepresentationBlock other = (FingerImageRepresentationBlock) obj;
    return Objects.equals(annotationBlocks, other.annotationBlocks)
        && Objects.equals(captureDateTimeBlock, other.captureDateTimeBlock)
        && Objects.equals(captureDeviceBlock, other.captureDeviceBlock)
        && Objects.equals(commentBlocks, other.commentBlocks) && Objects.equals(fingerRotation, other.fingerRotation)
        && Arrays.equals(imageData, other.imageData) && imageDataFormat == other.imageDataFormat
        && impression == other.impression
        && Objects.equals(isImageHasBeenLossilyCompressed, other.isImageHasBeenLossilyCompressed)
        && Objects.equals(isImageRotatedToVertical, other.isImageRotatedToVertical)
        && Objects.equals(isPositionComputedByCaptureSystem, other.isPositionComputedByCaptureSystem)
        && Objects.equals(padDataBlock, other.padDataBlock) && position == other.position
        && Objects.equals(qualityBlocks, other.qualityBlocks)
        && Objects.equals(segmentationBlocks, other.segmentationBlocks)
        && Objects.equals(spatialSamplingRateBlock, other.spatialSamplingRateBlock)
        && Objects.equals(vendorSpecificDataBlocks, other.vendorSpecificDataBlocks);
  }

  @Override
  public String toString() {
    return "FingerImageRepresentationBlock ["
        + "position: " + position
        + ", impression: " + impression
        + ", imageDataFormat: " + imageDataFormat
        + ", captureDateTimeBlock: " + captureDateTimeBlock
        + ", captureDeviceBlock: " + captureDeviceBlock
        + ", qualityBlocks: " + qualityBlocks
        + ", spatialSamplingRateBlock: " + spatialSamplingRateBlock
        + ", isPositionComputedByCaptureSystem: " + isPositionComputedByCaptureSystem
        + ", fingerRotation: " + fingerRotation
        + ", isImageRotatedToVertical: " + isImageRotatedToVertical
        + ", isImageHasBeenLossilyCompressed: " + isImageHasBeenLossilyCompressed
        + ", segmentationBlocks: " + segmentationBlocks
        + ", annotationBlocks: " + annotationBlocks
        + ", padDataBlock: " + padDataBlock
        + ", imageData: " + imageData.length
        + ", commentBlocks: " + commentBlocks
        + ", vendorSpecificDataBlocks: " + vendorSpecificDataBlocks
        + "]";
  }

  @Override
  public int getType() {
    return TYPE_FINGER;
  }

  @Override
  public String getMimeType() {
    if (imageDataFormat == null) {
      return "image/raw";
    }
    return imageDataFormat.getMimeType();
  }

  @Override
  public int getWidth() {
    return 0;
  }

  @Override
  public int getHeight() {
    return 0;
  }

  @Override
  public long getRecordLength() {
    return 0;
  }

  @Override
  public int getImageLength() {
    return imageData.length;
  }

  @Override
  public InputStream getImageInputStream() {
    return new ByteArrayInputStream(imageData);
  }

  /* PACKAGE */

  /**
   * Returns the biometric sub-type.
   *
   * @return the ICAO/CBEFF (BHT) biometric sub-type
   */
  int getBiometricSubtype() {
    return toBiometricSubtype(position);
  }

  @Override
  ASN1Encodable getASN1Object() {
    Map<Integer, ASN1Encodable> taggedObjects = new HashMap<Integer, ASN1Encodable>();
    taggedObjects.put(0, ISO39794Util.encodeCodeAsChoiceExtensionBlockFallback(position.getCode()));
    taggedObjects.put(1, ISO39794Util.encodeCodeAsChoiceExtensionBlockFallback(impression.getCode()));
    taggedObjects.put(2, ISO39794Util.encodeCodeAsChoiceExtensionBlockFallback(imageDataFormat.getCode()));
    taggedObjects.put(3, new DEROctetString(imageData));
    if (captureDateTimeBlock != null) {
      taggedObjects.put(4, captureDateTimeBlock.getASN1Object());
    }
    if (captureDeviceBlock != null) {
      taggedObjects.put(5, captureDeviceBlock.getASN1Object());
    }
    if (qualityBlocks != null) {
      taggedObjects.put(6, ISO39794Util.encodeBlocks(qualityBlocks));
    }
    if (spatialSamplingRateBlock != null) {
      taggedObjects.put(7, spatialSamplingRateBlock.getASN1Object());
    }
    if (isPositionComputedByCaptureSystem != null) {
      taggedObjects.put(8, ASN1Util.encodeBoolean(isPositionComputedByCaptureSystem));
    }
    if (fingerRotation != null) {
      taggedObjects.put(9, ASN1Util.encodeInt(fingerRotation));
    }
    if (isImageRotatedToVertical != null) {
      taggedObjects.put(10, ASN1Util.encodeBoolean(isImageRotatedToVertical));
    }
    if (isImageHasBeenLossilyCompressed != null) {
      taggedObjects.put(11, ASN1Util.encodeBoolean(isImageHasBeenLossilyCompressed));
    }
    if (segmentationBlocks != null) {
      taggedObjects.put(12, ISO39794Util.encodeBlocks(segmentationBlocks));
    }
    if (annotationBlocks != null) {
      taggedObjects.put(13, ISO39794Util.encodeBlocks(annotationBlocks));
    }
    if (padDataBlock != null) {
      taggedObjects.put(14, padDataBlock.getASN1Object());
    }
    if (commentBlocks != null) {
      taggedObjects.put(15, encodeCommentBlocks(commentBlocks));
    }
    if (vendorSpecificDataBlocks != null) {
      taggedObjects.put(16, ISO39794Util.encodeBlocks(vendorSpecificDataBlocks));
    }
    return ASN1Util.encodeTaggedObjects(taggedObjects);
  }

  static List<FingerImageRepresentationBlock> decodeRepresentationBlocks(ASN1Encodable asn1Encodable) {
    List<FingerImageRepresentationBlock> blocks = new ArrayList<FingerImageRepresentationBlock>();
    if (ASN1Util.isSequenceOfSequences(asn1Encodable)) {
      List<ASN1Encodable> blockASN1Objects = ASN1Util.list(asn1Encodable);
      for (ASN1Encodable blockASN1Object: blockASN1Objects) {
        blocks.add(new FingerImageRepresentationBlock(blockASN1Object));
      }
    } else {
      blocks.add(new FingerImageRepresentationBlock(asn1Encodable));
    }

    return blocks;
  }

  /* PRIVATE */

  private static List<String> decodeCommentBlocks(ASN1Encodable asn1Encodable) {
    if (asn1Encodable instanceof ASN1Sequence) {
      List<ASN1Encodable> blockASN1Objects = ASN1Util.list(asn1Encodable);
      List<String> blocks = new ArrayList<String>(blockASN1Objects.size());
      for (ASN1Encodable blockASN1Object: blockASN1Objects) {
        blocks.add(ASN1VisibleString.getInstance(blockASN1Object).getString());
      }
      return blocks;
    } else if (asn1Encodable instanceof ASN1VisibleString) {
      return Collections.singletonList(ASN1VisibleString.getInstance(asn1Encodable).getString());
    }

    LOGGER.warning("Cannot decode comment blocks!");
    return null;
  }

  private static ASN1Encodable encodeCommentBlocks(List<String> comments) {
    ASN1Encodable[] asn1Objects = new ASN1Encodable[comments.size()];
    int i = 0;
    for (String comment: comments) {
      asn1Objects[i++] = new DERVisibleString(comment);
    }
    return new DERSequence(asn1Objects);
  }

  /**
   * Converts from 37984-4 position coding to 7816-11 (BHT) coding.
   *
   * @param position an ISO 39794-4 finger position code
   *
   * @return a ISO7816-11 biometric subtype mask combination
   */
  private static int toBiometricSubtype(FingerImagePositionCode position) {
    if (position ==  null) {
      return CBEFFInfo.BIOMETRIC_SUBTYPE_NONE;
    }
    switch (position) {
    case UNKNOWN_POSITION:
      return CBEFFInfo.BIOMETRIC_SUBTYPE_NONE;
    case RIGHT_THUMB_FINGER:
      return CBEFFInfo.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo.BIOMETRIC_SUBTYPE_MASK_RIGHT | CBEFFInfo.BIOMETRIC_SUBTYPE_MASK_THUMB;
    case RIGHT_INDEX_FINGER:
      return CBEFFInfo.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo.BIOMETRIC_SUBTYPE_MASK_RIGHT | CBEFFInfo.BIOMETRIC_SUBTYPE_MASK_POINTER_FINGER;
    case RIGHT_MIDDLE_FINGER:
      return CBEFFInfo.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo.BIOMETRIC_SUBTYPE_MASK_RIGHT | CBEFFInfo.BIOMETRIC_SUBTYPE_MASK_MIDDLE_FINGER;
    case RIGHT_RING_FINGER:
      return CBEFFInfo.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo.BIOMETRIC_SUBTYPE_MASK_RIGHT | CBEFFInfo.BIOMETRIC_SUBTYPE_MASK_RING_FINGER;
    case RIGHT_LITTLE_FINGER:
      return CBEFFInfo.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo.BIOMETRIC_SUBTYPE_MASK_RIGHT | CBEFFInfo.BIOMETRIC_SUBTYPE_MASK_LITTLE_FINGER;
    case LEFT_THUMB_FINGER:
      return CBEFFInfo.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo.BIOMETRIC_SUBTYPE_MASK_LEFT | CBEFFInfo.BIOMETRIC_SUBTYPE_MASK_THUMB;
    case LEFT_INDEX_FINGER:
      return CBEFFInfo.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo.BIOMETRIC_SUBTYPE_MASK_LEFT | CBEFFInfo.BIOMETRIC_SUBTYPE_MASK_POINTER_FINGER;
    case LEFT_MIDDLE_FINGER:
      return CBEFFInfo.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo.BIOMETRIC_SUBTYPE_MASK_LEFT | CBEFFInfo.BIOMETRIC_SUBTYPE_MASK_MIDDLE_FINGER;
    case LEFT_RING_FINGER:
      return CBEFFInfo.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo.BIOMETRIC_SUBTYPE_MASK_LEFT | CBEFFInfo.BIOMETRIC_SUBTYPE_MASK_RING_FINGER;
    case LEFT_LITTLE_FINGER:
      return CBEFFInfo.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo.BIOMETRIC_SUBTYPE_MASK_LEFT | CBEFFInfo.BIOMETRIC_SUBTYPE_MASK_LITTLE_FINGER;
    case RIGHT_FOUR_FINGERS:
      return CBEFFInfo.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo.BIOMETRIC_SUBTYPE_MASK_RIGHT;
    case LEFT_FOUR_FINGERS:
      return CBEFFInfo.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo.BIOMETRIC_SUBTYPE_MASK_LEFT;
    case BOTH_THUMB_FINGERS:
      return CBEFFInfo.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo.BIOMETRIC_SUBTYPE_MASK_THUMB;
    case UNKNOWN_PALM:
      return CBEFFInfo.BIOMETRIC_SUBTYPE_NONE;
    case RIGHT_FULL_PALM:
      return CBEFFInfo.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo.BIOMETRIC_SUBTYPE_MASK_RIGHT;
    case RIGHT_WRITERS_PALM:
      return CBEFFInfo.BIOMETRIC_SUBTYPE_NONE;
    case LEFT_FULL_PALM:
      return CBEFFInfo.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo.BIOMETRIC_SUBTYPE_MASK_LEFT;
    case LEFT_WRITERS_PALM:
      return CBEFFInfo.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo.BIOMETRIC_SUBTYPE_MASK_LEFT;
    case RIGHT_LOWER_PALM:
      return CBEFFInfo.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo.BIOMETRIC_SUBTYPE_MASK_RIGHT;
    case RIGHT_UPPER_PALM:
      return CBEFFInfo.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo.BIOMETRIC_SUBTYPE_MASK_RIGHT;
    case LEFT_LOWER_PALM:
      return CBEFFInfo.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo.BIOMETRIC_SUBTYPE_MASK_LEFT;
    case LEFT_UPPER_PALM:
      return CBEFFInfo.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo.BIOMETRIC_SUBTYPE_MASK_LEFT;
    case RIGHT_INTERDIGITAL:
      return CBEFFInfo.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo.BIOMETRIC_SUBTYPE_MASK_RIGHT;
    case RIGHT_THENAR:
      return CBEFFInfo.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo.BIOMETRIC_SUBTYPE_MASK_RIGHT;
    case RIGHT_HYPOTHENAR:
      return CBEFFInfo.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo.BIOMETRIC_SUBTYPE_MASK_RIGHT;
    case LEFT_INTERDIGITAL:
      return CBEFFInfo.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo.BIOMETRIC_SUBTYPE_MASK_LEFT;
    case LEFT_THENAR:
      return CBEFFInfo.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo.BIOMETRIC_SUBTYPE_MASK_LEFT;
    case LEFT_HYPOTHENAR:
      return CBEFFInfo.BIOMETRIC_SUBTYPE_NONE | CBEFFInfo.BIOMETRIC_SUBTYPE_MASK_LEFT;
    case OTHER_POSITION:
      // Fall through...
    default:
      return CBEFFInfo.BIOMETRIC_SUBTYPE_NONE;
    }
  }
}
