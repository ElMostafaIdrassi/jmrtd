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

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.jmrtd.ASN1Util;

public class FaceImageInformation2DBlock extends Block {

  private static final long serialVersionUID = 76880187801114756L;

  public static enum ImageDataFormatCode implements EncodableEnum<ImageDataFormatCode> {
    UNKNOWN(0, "image/raw"),
    JPEG(2, "image/jpeg"),
    JPEG2000_LOSSY(3, "image/jp2"),
    JPEG2000_LOSSLESS(4, "image/jp2");

    private int code;

    private String mimeType;

    private ImageDataFormatCode(int code, String mimeType) {
      this.code = code;
      this.mimeType = mimeType;
    }

    public int getCode() {
      return code;
    }

    public static ImageDataFormatCode fromCode(int code) {
      return EncodableEnum.fromCode(code, ImageDataFormatCode.class);
    }

    public String getMimeType() {
      return mimeType;
    }

    static String toMimeType(ImageDataFormatCode imageDataFormatCode) {
      if (imageDataFormatCode == null) {
        return "image/raw";
      }
      return imageDataFormatCode.getMimeType();
    }
  }

  public static enum FaceImageKind2DCode implements EncodableEnum<FaceImageKind2DCode> {
    MRTD(0),
    GENERAL_PURPOSE(1);

    private int code;

    private FaceImageKind2DCode(int code) {
      this.code = code;
    }

    public int getCode() {
      return code;
    }

    public static FaceImageKind2DCode fromCode(int code) {
      return EncodableEnum.fromCode(code, FaceImageKind2DCode.class);
    }
  }

  public static enum LossyTransformationAttemptsCode implements EncodableEnum<LossyTransformationAttemptsCode> {
    UNKNOWN(0),
    ZERO(1),
    ONE(2),
    MORE_THAN_ONE(3);

    private int code;

    private LossyTransformationAttemptsCode(int code) {
      this.code = code;
    }

    public int getCode() {
      return code;
    }

    public static LossyTransformationAttemptsCode fromCode(int code) {
      return EncodableEnum.fromCode(code, LossyTransformationAttemptsCode.class);
    }
  }

  public static enum ImageColourSpaceCode implements EncodableEnum<ImageColourSpaceCode> {
    UNKNOWN(0),
    OTHER(1),
    RGB_24BIT(2),
    RGB_48BIT(3),
    YUV_422(4),
    GREYSCALE_8BIT(5),
    GREYSCALE_16BIT(6);

    private int code;

    private ImageColourSpaceCode(int code) {
      this.code = code;
    }

    public int getCode() {
      return code;
    }

    public static ImageColourSpaceCode fromCode(int code) {
      return EncodableEnum.fromCode(code, ImageColourSpaceCode.class);
    }
  }

  //  ImageSizeBlock ::= SEQUENCE {
  //    width [0] ImageSize,
  //    height [1] ImageSize
  //  }

  public static class ImageSizeBlock extends Block {

    private static final long serialVersionUID = -261040653361008230L;

    private int width;
    private int height;

    public ImageSizeBlock(int width, int height) {
      this.width = width;
      this.height = height;
    }

    public ImageSizeBlock(ASN1Encodable asn1Encodable) {

      if (!(asn1Encodable instanceof ASN1Sequence)) {
        throw new IllegalArgumentException("Cannot decode!");
      }

      Map<Integer, ASN1Encodable> taggedObjects = ASN1Util.decodeTaggedObjects(asn1Encodable);
      width = ASN1Util.decodeInt(taggedObjects.get(0));
      height = ASN1Util.decodeInt(taggedObjects.get(1));
    }

    public int getWidth() {
      return width;
    }

    public int getHeight() {
      return height;
    }

    @Override
    public int hashCode() {
      return Objects.hash(height, width);
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

      ImageSizeBlock other = (ImageSizeBlock) obj;
      return height == other.height && width == other.width;
    }

    @Override
    public String toString() {
      return "ImageSizeBlock [width: " + width + ", height: " + height + "]";
    }

    @Override
    ASN1Encodable getASN1Object() {
      Map<Integer, ASN1Encodable> taggedObjects = new HashMap<Integer, ASN1Encodable>();
      taggedObjects.put(0,ASN1Util.encodeInt(width));
      taggedObjects.put(1, ASN1Util.encodeInt(height));
      return ASN1Util.encodeTaggedObjects(taggedObjects);
    }
  }

  public static class ImageFaceMeasurementsBlock extends Block {

    private static final long serialVersionUID = -5665022845073986540L;

    private BigInteger imageHeadWidth;
    private BigInteger imageInterEyeDistance;
    private BigInteger imageEyeToMouthDistance;
    private BigInteger imageHeadLength;

    public ImageFaceMeasurementsBlock(BigInteger imageHeadWidth, BigInteger imageInterEyeDistance,
        BigInteger imageEyeToMouthDistance, BigInteger imageHeadLength) {
      this.imageHeadWidth = imageHeadWidth;
      this.imageInterEyeDistance = imageInterEyeDistance;
      this.imageEyeToMouthDistance = imageEyeToMouthDistance;
      this.imageHeadLength = imageHeadLength;
    }

    ImageFaceMeasurementsBlock(ASN1Encodable asn1Encodable) {
      Map<Integer, ASN1Encodable>  taggedObjects = ASN1Util.decodeTaggedObjects(asn1Encodable);
      if (taggedObjects.containsKey(0)) {
        imageHeadWidth = ASN1Util.decodeBigInteger(taggedObjects.get(0));
      }
      if (taggedObjects.containsKey(1)) {
        imageInterEyeDistance = ASN1Util.decodeBigInteger(taggedObjects.get(1));
      }
      if (taggedObjects.containsKey(2)) {
        imageEyeToMouthDistance =  ASN1Util.decodeBigInteger(taggedObjects.get(2));
      }
      if (taggedObjects.containsKey(3)) {
        imageHeadLength =  ASN1Util.decodeBigInteger(taggedObjects.get(3));
      }
    }

    public BigInteger getImageHeadWidth() {
      return imageHeadWidth;
    }

    public BigInteger getImageInterEyeDistance() {
      return imageInterEyeDistance;
    }

    public BigInteger getImageEyeToMouthDistance() {
      return imageEyeToMouthDistance;
    }

    public BigInteger getImageHeadLength() {
      return imageHeadLength;
    }

    @Override
    public int hashCode() {
      return Objects.hash(imageEyeToMouthDistance, imageHeadLength, imageHeadWidth, imageInterEyeDistance);
    }

    @Override
    public boolean equals(Object obj) {
      if (this == obj)
        return true;
      if (obj == null)
        return false;
      if (getClass() != obj.getClass())
        return false;
      ImageFaceMeasurementsBlock other = (ImageFaceMeasurementsBlock) obj;
      return Objects.equals(imageEyeToMouthDistance, other.imageEyeToMouthDistance)
          && Objects.equals(imageHeadLength, other.imageHeadLength)
          && Objects.equals(imageHeadWidth, other.imageHeadWidth)
          && Objects.equals(imageInterEyeDistance, other.imageInterEyeDistance);
    }

    @Override
    public String toString() {
      return "ImageFaceMeasurementsBlock ["
          + "imageHeadWidth: " + imageHeadWidth
          + ", imageInterEyeDistance: " + imageInterEyeDistance
          + ", imageEyeToMouthDistance: " + imageEyeToMouthDistance
          + ", imageHeadLength: " + imageHeadLength
          + "]";
    }

    /* PACKAGE */

    @Override
    ASN1Encodable getASN1Object() {
      Map<Integer, ASN1Encodable> taggedObjects = new HashMap<Integer, ASN1Encodable>();
      if (imageHeadWidth != null) {
        taggedObjects.put(0, ASN1Util.encodeBigInteger(imageHeadWidth));
      }
      if (imageInterEyeDistance != null) {
        taggedObjects.put(1, ASN1Util.encodeBigInteger(imageInterEyeDistance));
      }
      if (imageEyeToMouthDistance != null) {
        taggedObjects.put(2, ASN1Util.encodeBigInteger(imageEyeToMouthDistance));
      }
      if (imageHeadLength != null) {
        taggedObjects.put(3, ASN1Util.encodeBigInteger(imageHeadLength));
      }
      return ASN1Util.encodeTaggedObjects(taggedObjects);
    }
  }

  private ImageSizeBlock imageSizeBlock;

  private ImageDataFormatCode imageDataFormatCode;

  private FaceImageKind2DCode faceImageKind2DCode;

  private FaceImagePostAcquisitionProcessingBlock postAcquisitionProcessingBlock;

  private LossyTransformationAttemptsCode lossyTransformationAttemptsCode;

  private Integer cameraToSubjectDistance;

  private Integer sensorDiagonal;

  private Integer lensFocalLength;

  private ImageFaceMeasurementsBlock imageFaceMeasurementsBlock;

  private ImageColourSpaceCode imageColourSpaceCode;

  private FaceImageReferenceColourMappingBlock referenceColourMappingBlock;

  public FaceImageInformation2DBlock(ImageSizeBlock imageSizeBlock, ImageDataFormatCode imageDataFormatCode,
      FaceImageKind2DCode faceImageKind2DCode, FaceImagePostAcquisitionProcessingBlock postAcquisitionProcessingBlock,
      LossyTransformationAttemptsCode lossyTransformationAttemptsCode, Integer cameraToSubjectDistance,
      Integer sensorDiagonal, Integer lensFocalLength, ImageFaceMeasurementsBlock imageFaceMeasurementsBlock,
      ImageColourSpaceCode imageColourSpaceCode, FaceImageReferenceColourMappingBlock referenceColourMappingBlock) {
    this.imageSizeBlock = imageSizeBlock;
    this.imageDataFormatCode = imageDataFormatCode;
    this.faceImageKind2DCode = faceImageKind2DCode;
    this.postAcquisitionProcessingBlock = postAcquisitionProcessingBlock;
    this.lossyTransformationAttemptsCode = lossyTransformationAttemptsCode;
    this.cameraToSubjectDistance = cameraToSubjectDistance;
    this.sensorDiagonal = sensorDiagonal;
    this.lensFocalLength = lensFocalLength;
    this.imageFaceMeasurementsBlock = imageFaceMeasurementsBlock;
    this.imageColourSpaceCode = imageColourSpaceCode;
    this.referenceColourMappingBlock = referenceColourMappingBlock;
  }

  //  ImageInformation2DBlock ::= SEQUENCE {
  //    imageDataFormat [0] ImageDataFormat,
  //    faceImageKind2D [1] FaceImageKind2D OPTIONAL,
  //    postAcquisitionProcessingBlock [2] PostAcquisitionProcessingBlock OPTIONAL,
  //    lossyTransformationAttempts [3] LossyTransformationAttempts OPTIONAL,
  //    cameraToSubjectDistance [4] CameraToSubjectDistance OPTIONAL,
  //    sensorDiagonal [5] SensorDiagonal OPTIONAL,
  //    lensFocalLength [6] LensFocalLength OPTIONAL,
  //    imageSizeBlock [7] ImageSizeBlock OPTIONAL,
  //    imageFaceMeasurementsBlock [8] ImageFaceMeasurementsBlock OPTIONAL,
  //    imageColourSpace [9] ImageColourSpace OPTIONAL,
  //    referenceColourMappingBlock [10] ReferenceColourMappingBlock OPTIONAL,
  //    ...
  //  }

  FaceImageInformation2DBlock(ASN1Encodable asn1Encodable) {
    if (!(asn1Encodable instanceof ASN1Sequence) && !(asn1Encodable instanceof ASN1TaggedObject)) {
      throw new IllegalArgumentException("Cannot decode!");
    }

    Map<Integer, ASN1Encodable> taggedObjects = ASN1Util.decodeTaggedObjects(asn1Encodable);
    if (taggedObjects.containsKey(0)) {
      imageDataFormatCode = ImageDataFormatCode.fromCode(ISO39794Util.decodeCodeFromChoiceExtensionBlockFallback(taggedObjects.get(0)));
    }
    if (taggedObjects.containsKey(1)) {
      faceImageKind2DCode = FaceImageKind2DCode.fromCode(ISO39794Util.decodeCodeFromChoiceExtensionBlockFallback(taggedObjects.get(1)));
    }
    if (taggedObjects.containsKey(2)) {
      postAcquisitionProcessingBlock = new FaceImagePostAcquisitionProcessingBlock(taggedObjects.get(2));
    }
    if (taggedObjects.containsKey(3)) {
      lossyTransformationAttemptsCode = LossyTransformationAttemptsCode.fromCode(ISO39794Util.decodeCodeFromChoiceExtensionBlockFallback(taggedObjects.get(3)));
    }
    if (taggedObjects.containsKey(4)) {
      cameraToSubjectDistance = ASN1Util.decodeInt(taggedObjects.get(4));
    }
    if (taggedObjects.containsKey(5)) {
      sensorDiagonal = ASN1Util.decodeInt(taggedObjects.get(5));
    }
    if (taggedObjects.containsKey(6)) {
      lensFocalLength = ASN1Util.decodeInt(taggedObjects.get(6));
    }
    if (taggedObjects.containsKey(7)) {
      imageSizeBlock = new ImageSizeBlock(taggedObjects.get(7));
    }
    if (taggedObjects.containsKey(8)) {
      imageFaceMeasurementsBlock = new ImageFaceMeasurementsBlock(taggedObjects.get(8));
    }
    if (taggedObjects.containsKey(9)) {
      imageColourSpaceCode = ImageColourSpaceCode.fromCode(ISO39794Util.decodeCodeFromChoiceExtensionBlockFallback(taggedObjects.get(9)));
    }
    if (taggedObjects.containsKey(10)) {
      referenceColourMappingBlock = new FaceImageReferenceColourMappingBlock(taggedObjects.get(10));
    }
  }

  /**
   * Returns the image data format.
   * One of {@code JPEG}, {@code JPEG2000_LOSSY}, or {@code JPEG2000_LOSSLESS}.
   *
   * @return the image data format
   */
  public ImageDataFormatCode getImageDataFormatCode() {
    return imageDataFormatCode;
  }

  public FaceImageKind2DCode getFaceImageKind2DCode() {
    return faceImageKind2DCode;
  }

  public FaceImagePostAcquisitionProcessingBlock getPostAcquisitionProcessingBlock() {
    return postAcquisitionProcessingBlock;
  }

  public LossyTransformationAttemptsCode getLossyTransformationAttemptsCode() {
    return lossyTransformationAttemptsCode;
  }

  public Integer getCameraToSubjectDistance() {
    return cameraToSubjectDistance;
  }

  public Integer getSensorDiagonal() {
    return sensorDiagonal;
  }

  public Integer getLensFocalLength() {
    return lensFocalLength;
  }

  public ImageSizeBlock getImageSizeBlock() {
    return imageSizeBlock;
  }

  public ImageFaceMeasurementsBlock getImageFaceMeasurementsBlock() {
    return imageFaceMeasurementsBlock;
  }

  public ImageColourSpaceCode getImageColourSpaceCode() {
    return imageColourSpaceCode;
  }

  public FaceImageReferenceColourMappingBlock getReferenceColourMappingBlock() {
    return referenceColourMappingBlock;
  }

  @Override
  public int hashCode() {
    return Objects.hash(cameraToSubjectDistance, faceImageKind2DCode, imageColourSpaceCode, imageDataFormatCode,
        imageFaceMeasurementsBlock, imageSizeBlock, lensFocalLength, lossyTransformationAttemptsCode,
        postAcquisitionProcessingBlock, referenceColourMappingBlock, sensorDiagonal);
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

    FaceImageInformation2DBlock other = (FaceImageInformation2DBlock) obj;
    return Objects.equals(cameraToSubjectDistance, other.cameraToSubjectDistance)
        && faceImageKind2DCode == other.faceImageKind2DCode && imageColourSpaceCode == other.imageColourSpaceCode
        && imageDataFormatCode == other.imageDataFormatCode
        && Objects.equals(imageFaceMeasurementsBlock, other.imageFaceMeasurementsBlock)
        && Objects.equals(imageSizeBlock, other.imageSizeBlock)
        && Objects.equals(lensFocalLength, other.lensFocalLength)
        && lossyTransformationAttemptsCode == other.lossyTransformationAttemptsCode
        && Objects.equals(postAcquisitionProcessingBlock, other.postAcquisitionProcessingBlock)
        && Objects.equals(referenceColourMappingBlock, other.referenceColourMappingBlock)
        && Objects.equals(sensorDiagonal, other.sensorDiagonal);
  }

  @Override
  public String toString() {
    return "FaceImageInformation2DBlock ["
        + "imageSizeBlock: " + imageSizeBlock
        + ", imageDataFormatCode: " + imageDataFormatCode
        + ", faceImageKind2DCode: " + faceImageKind2DCode
        + ", postAcquisitionProcessingBlock: " + postAcquisitionProcessingBlock
        + ", lossyTransformationAttemptsCode: " + lossyTransformationAttemptsCode
        + ", cameraToSubjectDistance: " + cameraToSubjectDistance
        + ", sensorDiagonal: " + sensorDiagonal
        + ", lensFocalLength: " + lensFocalLength
        + ", imageFaceMeasurementsBlock: " + imageFaceMeasurementsBlock
        + ", imageColourSpaceCode: " + imageColourSpaceCode
        + ", referenceColourMappingBlock: " + referenceColourMappingBlock
        + "]";
  }

  /* PACAKAGE */

  @Override
  ASN1Encodable getASN1Object() {
    Map<Integer, ASN1Encodable> taggedObjects = new HashMap<Integer, ASN1Encodable>();
    taggedObjects.put(0, ISO39794Util.encodeCodeAsChoiceExtensionBlockFallback(imageDataFormatCode.getCode()));
    if (faceImageKind2DCode != null) {
      taggedObjects.put(1, ISO39794Util.encodeCodeAsChoiceExtensionBlockFallback(faceImageKind2DCode.getCode()));
    }
    if (postAcquisitionProcessingBlock != null) {
      taggedObjects.put(2, postAcquisitionProcessingBlock.getASN1Object());
    }
    if (lossyTransformationAttemptsCode != null) {
      taggedObjects.put(3,
          ISO39794Util.encodeCodeAsChoiceExtensionBlockFallback(lossyTransformationAttemptsCode.getCode()));
    }
    if (cameraToSubjectDistance != null) {
      taggedObjects.put(4, ASN1Util.encodeInt(cameraToSubjectDistance));
    }
    if (sensorDiagonal != null) {
      taggedObjects.put(5, ASN1Util.encodeInt(sensorDiagonal));
    }
    if (lensFocalLength != null) {
      taggedObjects.put(6, ASN1Util.encodeInt(lensFocalLength));
    }
    if (imageSizeBlock != null) {
      taggedObjects.put(7, imageSizeBlock.getASN1Object());
    }
    if (imageFaceMeasurementsBlock != null) {
      taggedObjects.put(8, imageFaceMeasurementsBlock.getASN1Object());
    }
    if (imageColourSpaceCode != null) {
      taggedObjects.put(9, ISO39794Util.encodeCodeAsChoiceExtensionBlockFallback(imageColourSpaceCode.getCode()));
    }
    if (referenceColourMappingBlock != null) {
      taggedObjects.put(10, referenceColourMappingBlock.getASN1Object());
    }
    return ASN1Util.encodeTaggedObjects(taggedObjects);
  }
}
