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

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.jmrtd.ASN1Util;
import org.jmrtd.lds.ImageInfo;

public class IrisImageRepresentationBlock extends Block implements ImageInfo {

  private static final long serialVersionUID = -982987535985932641L;

  public enum EyeLabelCode {
    UNKNOWN(0) ,
    RIGHT_IRIS(1) ,
    LEFT_IRIS(2);

    private int code;

    private EyeLabelCode(int code) {
      this.code = code;
    }

    public int getCode() {
      return code;
    }

    public static EyeLabelCode fromCode(int code) {
      if (code < 0) {
        return null;
      }
      for (EyeLabelCode value: values()) {
        if (code == value.code) {
          return value;
        }
      }

      return null;
    }
  }

  public enum IrisImageKindCode {
    UNCROPPED(1),
    VGA(2),
    CROPPED(3),
    CROPPED_AND_MASKED(7);

    private int code;

    private IrisImageKindCode(int code) {
      this.code = code;
    }

    public int getCode() {
      return code;
    }

    public static IrisImageKindCode fromCode(int code) {
      if (code < 0) {
        return null;
      }
      for (IrisImageKindCode value: values()) {
        if (code == value.code) {
          return value;
        }
      }

      return null;
    }
  }

  public enum ImageDataFormatCode {
    PGM(0, "image/pgm"),
    PPM(1, "image/ppm"),
    PNG(2, "image/png"),
    JPEG2000_LOSSLESS(3, "image/jp2"),
    JPEG2000_LOSSY(4, "image/jp2");

    private int code;
    private String mimeType;

    private ImageDataFormatCode(int code, String mimeType) {
      this.code = code;
      this.mimeType = mimeType;
    }

    public int getCode() {
      return code;
    }

    public String getMimeType() {
      return mimeType;
    }

    public static ImageDataFormatCode fromCode(int code) {
      if (code < 0) {
        return null;
      }
      for (ImageDataFormatCode value: values()) {
        if (code == value.code) {
          return value;
        }
      }

      return null;
    }
  }

  public enum HorizontalOrientationCode {
    UNDEFINED(0) ,
    LEFT_TO_RIGHT(1) ,
    RIGHT_TO_LEFT(2);

    private int code;

    private HorizontalOrientationCode(int code) {
      this.code = code;
    }

    public int getCode() {
      return code;
    }

    public static HorizontalOrientationCode fromCode(int code) {
      if (code < 0) {
        return null;
      }
      for (HorizontalOrientationCode value: values()) {
        if (code == value.code) {
          return value;
        }
      }

      return null;
    }
  }

  public enum VerticalOrientationCode {
    UNDEFINED(0),
    TOP_TO_BOTTOM(1) ,
    BOTTOM_TO_TOP(2);

    private int code;

    private VerticalOrientationCode(int code) {
      this.code = code;
    }

    public int getCode() {
      return code;
    }

    public static VerticalOrientationCode fromCode(int code) {
      if (code < 0) {
        return null;
      }
      for (VerticalOrientationCode value: values()) {
        if (code == value.code) {
          return value;
        }
      }

      return null;
    }
  }

  public enum CompressionHistoryCode {
    UNDEFINED(0),
    LOSSLESS_OR_NONE(1) ,
    LOSSY(2);

    private int code;

    private CompressionHistoryCode(int code) {
      this.code = code;
    }

    public int getCode() {
      return code;
    }

    public static CompressionHistoryCode fromCode(int code) {
      if (code < 0) {
        return null;
      }
      for (CompressionHistoryCode value: values()) {
        if (code == value.code) {
          return value;
        }
      }

      return null;
    }
  }

  public enum RangingErrorCode {
    UNASSIGNED(0),
    FAILED(1),
    OVERFLOW(2);

    private int code;

    private RangingErrorCode(int code) {
      this.code = code;
    }

    public int getCode() {
      return code;
    }

    public static RangingErrorCode fromCode(int code) {
      if (code < 0) {
        return null;
      }
      for (RangingErrorCode value: values()) {
        if (code == value.code) {
          return value;
        }
      }

      return null;
    }
  }

  public static class RollAngleBlock extends Block {

    private static final long serialVersionUID = -1867300334704286030L;

    private int angle;
    private int uncertainty;

    public RollAngleBlock(int angle, int uncertainty) {
      this.angle = angle;
      this.uncertainty = uncertainty;
    }

    RollAngleBlock(ASN1Encodable asn1Encodable) {
      Map<Integer, ASN1Encodable> taggedObjects = ASN1Util.decodeTaggedObjects(asn1Encodable);
      angle = ASN1Util.decodeInt(taggedObjects.get(0));
      uncertainty = ASN1Util.decodeInt(taggedObjects.get(1));
    }

    public int getAngle() {
      return angle;
    }

    public int getUncertainty() {
      return uncertainty;
    }

    @Override
    public int hashCode() {
      return Objects.hash(angle, uncertainty);
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

      RollAngleBlock other = (RollAngleBlock) obj;
      return angle == other.angle && uncertainty == other.uncertainty;
    }

    @Override
    ASN1Encodable getASN1Object() {
      Map<Integer, ASN1Encodable> taggedObjects = new HashMap<Integer, ASN1Encodable>();
      taggedObjects.put(0, ASN1Util.encodeInt(angle));
      taggedObjects.put(1, ASN1Util.encodeInt(uncertainty));
      return ASN1Util.encodeTaggedObjects(taggedObjects);
    }
  }

  private EyeLabelCode eyeLabelCode;

  private IrisImageKindCode irisImageKind;

  private int bitDepth;

  private ImageDataFormatCode imageDataFormatCode;

  private HorizontalOrientationCode horizontalOrientationCode;

  private VerticalOrientationCode verticalOrientationCode;

  private CompressionHistoryCode compressionHistoryCode;

  private byte[] imageData;

  /** INTEGER (2..65533), is null iff rangingErrorCode is not null. */
  private Integer range;
  private RangingErrorCode rangingErrorCode;

  private DateTimeBlock captureDateTimeBlock;


  private IrisImageCaptureDeviceBlock captureDeviceBlock;

  private List<QualityBlock> qualityBlocks;

  private RollAngleBlock rollAngleBlock;

  private IrisImageLocalisationBlock localisationBlock;

  private PADDataBlock padDataBlock;

  //  RepresentationBlock ::= SEQUENCE {
  //    eyeLabelCode              [0]          EyeLabelCode,
  //    irisImageKind             [1]          IrisImageKind,
  //    bitDepth                  [2]          INTEGER (8..24),
  //    imageDataFormat           [3]          ImageDataFormat,
  //    horizontalOrientationCode [4]          HorizontalOrientationCode,
  //    verticalOrientationCode   [5]          VerticalOrientationCode,
  //    compressionHistoryCode    [6]          CompressionHistoryCode,
  //    range                     [7]          RangeOrError,
  //    captureDateTimeBlock      [8]          CaptureDateTimeBlock,
  //    irisImageData             [9]          OCTET STRING,
  //    captureDeviceBlock        [10]         CaptureDeviceBlock             OPTIONAL,
  //    qualityBlocks             [11]         QualityBlocks                  OPTIONAL,
  //    rollAngleBlock            [12]         RollAngleBlock                 OPTIONAL,
  //    localisationBlock         [13]         LocalisationBlock              OPTIONAL,
  //    pADDataBlock              [14]         PADDataBlock                   OPTIONAL,
  //    ...
  //  }

  public IrisImageRepresentationBlock(ASN1Encodable asn1Encodable) {
    if (asn1Encodable == null) {
      throw new IllegalArgumentException("Cannot decode!");
    }
    Map<Integer, ASN1Encodable> taggedObjects = ASN1Util.decodeTaggedObjects(asn1Encodable);
    eyeLabelCode = EyeLabelCode.fromCode(ASN1Util.decodeInt(taggedObjects.get(0)));
    irisImageKind = IrisImageKindCode.fromCode(ISO39794Util.decodeCodeFromChoiceExtensionBlockFallback(taggedObjects.get(1)));
    bitDepth = ASN1Util.decodeInt(taggedObjects.get(2));
    imageDataFormatCode = ImageDataFormatCode.fromCode(ISO39794Util.decodeCodeFromChoiceExtensionBlockFallback(taggedObjects.get(3)));
    horizontalOrientationCode =  HorizontalOrientationCode.fromCode(ASN1Util.decodeInt(taggedObjects.get(4)));
    verticalOrientationCode =  VerticalOrientationCode.fromCode(ASN1Util.decodeInt(taggedObjects.get(5)));
    compressionHistoryCode =  CompressionHistoryCode.fromCode(ASN1Util.decodeInt(taggedObjects.get(6)));
    captureDateTimeBlock = new DateTimeBlock(taggedObjects.get(7));
    decodeRangeOrError(taggedObjects.get(8));
    imageData = (ASN1OctetString.getInstance(taggedObjects.get(9))).getOctets();
    if (taggedObjects.containsKey(10)) {
      captureDeviceBlock = new IrisImageCaptureDeviceBlock(taggedObjects.get(10));
    }
    if (taggedObjects.containsKey(11)) {
      qualityBlocks = QualityBlock.decodeQualityBlocks(taggedObjects.get(11));
    }
    if (taggedObjects.containsKey(12)) {
      rollAngleBlock = new RollAngleBlock(taggedObjects.get(12));
    }
    if (taggedObjects.containsKey(13)) {
      localisationBlock = new IrisImageLocalisationBlock(taggedObjects.get(13));
    }
    if (taggedObjects.containsKey(14)) {
      padDataBlock = new PADDataBlock(taggedObjects.get(14));
    }
  }

  //  RangeOrError ::= CHOICE {
  //    range   [0]     INTEGER (2..65533),
  //    errorCode       [1]     RangingErrorCode
  //  }

  public EyeLabelCode getEyeLabelCode() {
    return eyeLabelCode;
  }

  public IrisImageKindCode getIrisImageKind() {
    return irisImageKind;
  }

  public int getBitDepth() {
    return bitDepth;
  }

  public ImageDataFormatCode getImageDataFormat() {
    return imageDataFormatCode;
  }

  public HorizontalOrientationCode getHorizontalOrientationCode() {
    return horizontalOrientationCode;
  }

  public VerticalOrientationCode getVerticalOrientationCode() {
    return verticalOrientationCode;
  }

  public CompressionHistoryCode getCompressionHistoryCode() {
    return compressionHistoryCode;
  }

  public byte[] geImageData() {
    return imageData;
  }

  public IrisImageCaptureDeviceBlock getCaptureDeviceBlock() {
    return captureDeviceBlock;
  }

  public List<QualityBlock> getQualityBlocks() {
    return qualityBlocks;
  }

  public RollAngleBlock getRollAngleBlock() {
    return rollAngleBlock;
  }

  public IrisImageLocalisationBlock getLocalisationBlock() {
    return localisationBlock;
  }

  public PADDataBlock getPADDataBlock() {
    return padDataBlock;
  }

  /* PACKAGE */

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + Arrays.hashCode(imageData);
    result = prime * result + Objects.hash(bitDepth, captureDateTimeBlock, captureDeviceBlock, compressionHistoryCode,
        eyeLabelCode, horizontalOrientationCode, imageDataFormatCode, irisImageKind, localisationBlock, padDataBlock,
        qualityBlocks, range, rangingErrorCode, rollAngleBlock, verticalOrientationCode);
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

    IrisImageRepresentationBlock other = (IrisImageRepresentationBlock) obj;
    return bitDepth == other.bitDepth && Objects.equals(captureDateTimeBlock, other.captureDateTimeBlock)
        && Objects.equals(captureDeviceBlock, other.captureDeviceBlock)
        && compressionHistoryCode == other.compressionHistoryCode && eyeLabelCode == other.eyeLabelCode
        && horizontalOrientationCode == other.horizontalOrientationCode && Arrays.equals(imageData, other.imageData)
        && imageDataFormatCode == other.imageDataFormatCode && irisImageKind == other.irisImageKind
        && Objects.equals(localisationBlock, other.localisationBlock)
        && Objects.equals(padDataBlock, other.padDataBlock) && Objects.equals(qualityBlocks, other.qualityBlocks)
        && Objects.equals(range, other.range) && rangingErrorCode == other.rangingErrorCode
        && Objects.equals(rollAngleBlock, other.rollAngleBlock)
        && verticalOrientationCode == other.verticalOrientationCode;
  }

  @Override
  public String toString() {
    return "IrisImageRepresentationBlock ["
        + "eyeLabelCode: " + eyeLabelCode
        + ", irisImageKind: " + irisImageKind
        + ", bitDepth: " + bitDepth
        + ", imageDataFormat: " + imageDataFormatCode
        + ", horizontalOrientationCode: " + horizontalOrientationCode
        + ", verticalOrientationCode: " + verticalOrientationCode
        + ", compressionHistoryCode: " + compressionHistoryCode
        + ", imageData: " + (imageData != null ? "null" : imageData.length)
        + ", range: " + (range != null ? range : rangingErrorCode)
        + ", captureDateTimeBlock: " + captureDateTimeBlock
        + ", captureDeviceBlock: " + captureDeviceBlock
        + ", qualityBlocks: " + qualityBlocks
        + ", rollAngleBlock: " + rollAngleBlock
        + ", localisationBlock: " + localisationBlock
        + ", padDataBlock: " + padDataBlock
        + "]";
  }

  @Override
  public int getType() {
    return TYPE_IRIS;
  }

  @Override
  public String getMimeType() {
    if (imageDataFormatCode == null) {
      return "image/raw";
    }

    return imageDataFormatCode.getMimeType();
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
    return imageData == null ? 0 : imageData.length;
  }

  @Override
  public InputStream getImageInputStream() {
    return new ByteArrayInputStream(imageData);
  }

  @Override
  ASN1Encodable getASN1Object() {
    Map<Integer, ASN1Encodable> taggedObjects = new HashMap<Integer, ASN1Encodable>();
    taggedObjects.put(0, ASN1Util.encodeInt(eyeLabelCode.getCode()));
    taggedObjects.put(1, ISO39794Util.encodeCodeAsChoiceExtensionBlockFallback(irisImageKind.getCode()));
    taggedObjects.put(2, ASN1Util.encodeInt(bitDepth));
    taggedObjects.put(3, ISO39794Util.encodeCodeAsChoiceExtensionBlockFallback(imageDataFormatCode.getCode()));
    taggedObjects.put(4, ASN1Util.encodeInt(horizontalOrientationCode.getCode()));
    taggedObjects.put(5, ASN1Util.encodeInt(verticalOrientationCode.getCode()));
    taggedObjects.put(6, ASN1Util.encodeInt(compressionHistoryCode.getCode()));
    if (range != null) {
      taggedObjects.put(8, ASN1Util.encodeInt(range));
    } else if (rangingErrorCode != null) {
      taggedObjects.put(8, ASN1Util.encodeInt(rangingErrorCode.getCode()));
    }
    // TODO: 8
    taggedObjects.put(9, new DEROctetString(imageData));
    if (captureDeviceBlock != null) {
      taggedObjects.put(10, captureDeviceBlock.getASN1Object());
    }
    if (qualityBlocks != null) {
      taggedObjects.put(10, ISO39794Util.encodeBlocks(qualityBlocks));
    }
    if (rollAngleBlock != null) {
      taggedObjects.put(12, rollAngleBlock.getASN1Object());
    }
    if (localisationBlock != null) {
      taggedObjects.put(13, localisationBlock.getASN1Object());
    }
    if (padDataBlock != null) {
      taggedObjects.put(14, padDataBlock.getASN1Object());
    }
    return ASN1Util.encodeTaggedObjects(taggedObjects);
  }

  static List<IrisImageRepresentationBlock> decodeRepresentationBlocks(ASN1Encodable asn1Encodable) {
    List<IrisImageRepresentationBlock> result = new ArrayList<IrisImageRepresentationBlock>();
    if (ASN1Util.isSequenceOfSequences(asn1Encodable)) {
      List<ASN1Encodable> representationBlockASN1Objects = ASN1Util.list(asn1Encodable);
      for (ASN1Encodable representationBlockASN1Object: representationBlockASN1Objects) {
        result.add(new IrisImageRepresentationBlock(representationBlockASN1Object));
      }
    } else {
      result.add(new IrisImageRepresentationBlock(asn1Encodable));
    }

    return result;
  }

  /* PRIVATE */

  private void decodeRangeOrError(ASN1Encodable asn1Encodable) {
    Map<Integer, ASN1Encodable> taggedObjects = ASN1Util.decodeTaggedObjects(asn1Encodable);
    if (taggedObjects.containsKey(0)) {
      range = ASN1Util.decodeInt(taggedObjects.get(0));
    } else if (taggedObjects.containsKey(1)) {
      rangingErrorCode = RangingErrorCode.fromCode(ASN1Util.decodeInt(taggedObjects.get(1)));
    }
  }
}
