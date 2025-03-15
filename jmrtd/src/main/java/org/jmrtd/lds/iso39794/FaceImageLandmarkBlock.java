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

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.bouncycastle.asn1.ASN1Encodable;
import org.jmrtd.ASN1Util;

public class FaceImageLandmarkBlock extends Block {

  private static final long serialVersionUID = -8008877005187206392L;

  public abstract interface LandmarkKind {

    int hashCode();

    boolean equals(Object other);

    int getCode();
  }

  public enum MPEGFeaturePointCode implements LandmarkKind {
    MPEG4_POINT_CODE_02_01(0),
    MPEG4_POINT_CODE_02_02(1),
    MPEG4_POINT_CODE_02_03(2),
    MPEG4_POINT_CODE_02_04(3),
    MPEG4_POINT_CODE_02_05(4),
    MPEG4_POINT_CODE_02_06(5),
    MPEG4_POINT_CODE_02_07(6),
    MPEG4_POINT_CODE_02_08(7),
    MPEG4_POINT_CODE_02_09(8),
    MPEG4_POINT_CODE_02_10(9),
    MPEG4_POINT_CODE_02_11(10),
    MPEG4_POINT_CODE_02_12(11),
    MPEG4_POINT_CODE_02_13(12),
    MPEG4_POINT_CODE_02_14(13),
    MPEG4_POINT_CODE_03_01(14),
    MPEG4_POINT_CODE_03_02(15),
    MPEG4_POINT_CODE_03_03(16),
    MPEG4_POINT_CODE_03_04(17),
    MPEG4_POINT_CODE_03_05(18),
    MPEG4_POINT_CODE_03_06(19),
    MPEG4_POINT_CODE_03_07(20),
    MPEG4_POINT_CODE_03_08(21),
    MPEG4_POINT_CODE_03_09(22),
    MPEG4_POINT_CODE_03_10(23),
    MPEG4_POINT_CODE_03_11(24),
    MPEG4_POINT_CODE_03_12(25),
    MPEG4_POINT_CODE_03_13(26),
    MPEG4_POINT_CODE_03_14(27),
    MPEG4_POINT_CODE_04_01(28),
    MPEG4_POINT_CODE_04_02(29),
    MPEG4_POINT_CODE_04_03(30),
    MPEG4_POINT_CODE_04_04(31),
    MPEG4_POINT_CODE_04_05(32),
    MPEG4_POINT_CODE_04_06(33),
    MPEG4_POINT_CODE_05_01(34),
    MPEG4_POINT_CODE_05_02(35),
    MPEG4_POINT_CODE_05_03(36),
    MPEG4_POINT_CODE_05_04(37),
    MPEG4_POINT_CODE_06_01(38),
    MPEG4_POINT_CODE_06_02(39),
    MPEG4_POINT_CODE_06_03(40),
    MPEG4_POINT_CODE_06_04(41),
    MPEG4_POINT_CODE_07_01(42),
    MPEG4_POINT_CODE_08_01(43),
    MPEG4_POINT_CODE_08_02(44),
    MPEG4_POINT_CODE_08_03(45),
    MPEG4_POINT_CODE_08_04(46),
    MPEG4_POINT_CODE_08_05(47),
    MPEG4_POINT_CODE_08_06(48),
    MPEG4_POINT_CODE_08_07(49),
    MPEG4_POINT_CODE_08_08(50),
    MPEG4_POINT_CODE_08_09(51),
    MPEG4_POINT_CODE_08_10(52),
    MPEG4_POINT_CODE_09_01(53),
    MPEG4_POINT_CODE_09_02(54),
    MPEG4_POINT_CODE_09_03(55),
    MPEG4_POINT_CODE_09_04(56),
    MPEG4_POINT_CODE_09_05(57),
    MPEG4_POINT_CODE_09_06(58),
    MPEG4_POINT_CODE_09_07(59),
    MPEG4_POINT_CODE_09_08(60),
    MPEG4_POINT_CODE_09_09(61),
    MPEG4_POINT_CODE_09_10(62),
    MPEG4_POINT_CODE_09_11(63),
    MPEG4_POINT_CODE_09_12(64),
    MPEG4_POINT_CODE_09_13(65),
    MPEG4_POINT_CODE_09_14(66),
    MPEG4_POINT_CODE_09_15(67),
    MPEG4_POINT_CODE_10_01(68),
    MPEG4_POINT_CODE_10_02(69),
    MPEG4_POINT_CODE_10_03(70),
    MPEG4_POINT_CODE_10_04(71),
    MPEG4_POINT_CODE_10_05(72),
    MPEG4_POINT_CODE_10_06(73),
    MPEG4_POINT_CODE_10_07(74),
    MPEG4_POINT_CODE_10_08(75),
    MPEG4_POINT_CODE_10_09(76),
    MPEG4_POINT_CODE_10_10(77),
    MPEG4_POINT_CODE_11_01(78),
    MPEG4_POINT_CODE_11_02(79),
    MPEG4_POINT_CODE_11_03(80),
    MPEG4_POINT_CODE_11_04(81),
    MPEG4_POINT_CODE_11_05(82),
    MPEG4_POINT_CODE_11_06(83),
    MPEG4_POINT_CODE_12_01(84),
    MPEG4_POINT_CODE_12_02(85),
    MPEG4_POINT_CODE_12_03(86),
    MPEG4_POINT_CODE_12_04(87);

    private int code;

    private MPEGFeaturePointCode(int code) {
      this.code = code;
    }

    public int getCode() {
      return code;
    }

    public static MPEGFeaturePointCode fromCode(int code) {
      if (code < 0) {
        return null;
      }
      for (MPEGFeaturePointCode value: values()) {
        if (code == value.code) {
          return value;
        }
      }

      return null;
    }
  }

  public enum AnthropometricLandmarkNameCode implements LandmarkKind {
    VERTEX(0),
    GLABELLA(1),
    OPISTHOCRANION(2),
    EURION_LEFT(3),
    EURION_RIGHT(4),
    FRONTOTEMPORALE_LEFT(5),
    FRONTOTEMPORALE_RIGHT(6),
    TRICHION(7),
    ZYGION_LEFT(8),
    ZYGION_RIGHT(9),
    GONION_LEFT(10),
    GONION_RIGHT(11),
    SUBLABIALE(12),
    POGONION(13),
    MENTON(14),
    CONDYLION_LATERALE_LEFT(15),
    CONDYLION_LATERALE_RIGHT(16),
    ENDOCANTHION_LEFT(17),
    ENDOCANTHION_RIGHT(18),
    EXOCANTHION_LEFT(19),
    EXOCANTHION_RIGHT(20),
    CENTER_POINT_OF_PUPIL_LEFT(21),
    CENTER_POINT_OF_PUPIL_RIGHT(22),
    ORBITALE_LEFT(23),
    ORBITALE_RIGHT(24),
    PALPEBRALE_SUPERIUS_LEFT(25),
    PALPEBRALE_SUPERIUS_RIGHT(26),
    PALPEBRALE_INFERIUS_LEFT(27),
    PALPEBRALE_INFERIUS_RIGHT(28),
    ORBITALE_SUPERIUS_LEFT(29),
    ORBITALE_SUPERIUS_RIGHT(30),
    SUPERCILIARE_LEFT(31),
    SUPERCILIARE_RIGHT(32),
    NASION(33),
    SELLION(34),
    ALARE_LEFT(35),
    ALARE_RIGHT(36),
    PRONASALE(37),
    SUBNASALE(38),
    SUBALARE(39),
    ALAR_CURVATURE_LEFT(40),
    ALAR_CURVATURE_RIGHT(41),
    MAXILLOFRONTALE(42),
    CHRISTA_PHILTRA_LANDMARK_LEFT(43),
    CHRISTA_PHILTRA_LANDMARK_RIGHT(44),
    LABIALE_SUPERIUS(45),
    LABIALE_INFERIUS(46),
    CHEILION_LEFT(47),
    CHEILION_RIGHT(48),
    STOMION(49),
    SUPERAURALE_LEFT(50),
    SUPERAURALE_RIGHT(51),
    SUBAURALE_LEFT(52),
    SUBAURALE_RIGHT(53),
    PREAURALE(54),
    POSTAURALE(55),
    OTOBASION_SUPERIUS_LEFT(56),
    OTOBASION_SUPERIUS_RIGHT(57),
    OTOBASION_INFERIUS(58),
    PORION(59),
    TRAGION(60);

    private int code;

    private AnthropometricLandmarkNameCode(int code) {
      this.code = code;
    }

    public int getCode() {
      return code;
    }

    public static AnthropometricLandmarkNameCode fromCode(int code) {
      if (code < 0) {
        return null;
      }
      for (AnthropometricLandmarkNameCode value: values()) {
        if (code == value.code) {
          return value;
        }
      }

      return null;
    }
  }

  public enum AnthropometricLandmarkPointNameCode implements LandmarkKind {
    POINTCODE_01_01(0),
    POINTCODE_01_02(1),
    POINTCODE_01_05(2),
    POINTCODE_01_06(3),
    POINTCODE_01_07(4),
    POINTCODE_01_08(5),
    POINTCODE_01_09(6),
    POINTCODE_02_01(7),
    POINTCODE_02_02(8),
    POINTCODE_02_03(9),
    POINTCODE_02_04(10),
    POINTCODE_02_05(11),
    POINTCODE_02_06(12),
    POINTCODE_02_07(13),
    POINTCODE_02_09(14),
    POINTCODE_02_10(15),
    POINTCODE_03_01(16),
    POINTCODE_03_02(17),
    POINTCODE_03_03(18),
    POINTCODE_03_04(19),
    POINTCODE_03_05(20),
    POINTCODE_03_06(21),
    POINTCODE_03_07(22),
    POINTCODE_03_08(23),
    POINTCODE_03_09(24),
    POINTCODE_03_10(25),
    POINTCODE_03_11(26),
    POINTCODE_03_12(27),
    POINTCODE_04_01(28),
    POINTCODE_04_02(29),
    POINTCODE_04_03(30),
    POINTCODE_04_04(31),
    POINTCODE_05_01(32),
    POINTCODE_05_02(33),
    POINTCODE_05_03(34),
    POINTCODE_05_04(35),
    POINTCODE_05_06(36);

    private int code;

    private AnthropometricLandmarkPointNameCode(int code) {
      this.code = code;
    }

    public int getCode() {
      return code;
    }

    public static AnthropometricLandmarkPointNameCode fromCode(int code) {
      if (code < 0) {
        return null;
      }
      for (AnthropometricLandmarkPointNameCode value: values()) {
        if (code == value.code) {
          return value;
        }
      }

      return null;
    }

  }

  public enum AnthropometricLandmarkPointIdCode implements LandmarkKind {
    V(0),
    G(1),
    OP(2),
    EU_LEFT(3),
    EU_RIGHT(4),
    FT_LEFT(5),
    FT_RIGHT(6),
    TR(7),
    ZY_LEFT(8),
    ZY_RIGHT(9),
    GO_LEFT(10),
    GO_RIGHT(11),
    SL(12),
    PG(13),
    GN(14),
    CDL_LEFT(15),
    CDL_RIGHT(16),
    EN_LEFT(17),
    EN_RIGHT(18),
    EX_LEFT(19),
    EX_RIGHT(20),
    P_LEFT(21),
    P_RIGHT(22),
    OR_LEFT(23),
    OR_RIGHT(24),
    PS_LEFT(25),
    PS_RIGHT(26),
    PI_LEFT(27),
    PI_RIGHT(28),
    OS_LEFT(29),
    OS_RIGHT(30),
    SCI_LEFT(31),
    SCI_RIGHT(32),
    N(33),
    SE(34),
    AL_LEFT(35),
    AL_RIGHT(36),
    PRN(37),
    SN(38),
    SBAL(39),
    AC_LEFT(40),
    AC_RIGHT(41),
    MF_LEFT(42),
    MF_RIGHT(43),
    CPH_LEFT(44),
    CPH_RIGHT(45),
    LS(46),
    LI(47),
    CH_LEFT(48),
    CH_RIGHT(49),
    STO(50),
    SA_LEFT(51),
    SA_RIGHT(52),
    SBA_LEFT(53),
    SBA_RIGHT(54),
    PRA_LEFT(55),
    PRA_RIGHT(56),
    PA(57),
    OBS_LEFT(58),
    OBS_RIGHT(59),
    OBI(60),
    PO(61),
    T(62);

    private int code;

    private AnthropometricLandmarkPointIdCode(int code) {
      this.code = code;
    }

    public int getCode() {
      return code;
    }

    public static AnthropometricLandmarkPointIdCode fromCode(int code) {
      if (code < 0) {
        return null;
      }
      for (AnthropometricLandmarkPointIdCode value: values()) {
        if (code == value.code) {
          return value;
        }
      }

      return null;
    }
  }

  private LandmarkKind landmarkKind;

  private FaceImageLandmarkCoordinates landmarkCoordinates;

  public FaceImageLandmarkBlock(LandmarkKind landmarkKind, FaceImageLandmarkCoordinates landmarkCoordinates) {
    this.landmarkKind = landmarkKind;
    this.landmarkCoordinates = landmarkCoordinates;
  }

  //  LandmarkBlock ::= SEQUENCE {
  //    landmarkKind [0] LandmarkKind,
  //    landmarkCoordinates [1] LandmarkCoordinates OPTIONAL,
  //    ...
  //  }

  //  LandmarkKind ::= CHOICE {
  //    base [0] LandmarkKindBase,
  //    extensionBlock [1] LandmarkKindExtensionBlock
  //  }

  //  LandmarkKindBase ::= CHOICE {
  //    mpeg4FeaturePoint [0] MPEG4FeaturePoint,
  //    anthropometricLandmark [1] AnthropometricLandmark
  //  }

  FaceImageLandmarkBlock(ASN1Encodable asn1Encodable) {
    Map<Integer, ASN1Encodable> taggedObjects = ASN1Util.decodeTaggedObjects(asn1Encodable);
    landmarkKind = decodeLandmarkKind(taggedObjects.get(0));
    if (taggedObjects.containsKey(1)) {
      landmarkCoordinates = decodeLandmarkCoordinates(taggedObjects.get(1));
    }
  }

  public LandmarkKind getLandmarkKind() {
    return landmarkKind;
  }

  public FaceImageLandmarkCoordinates getLandmarkCoordinates() {
    return landmarkCoordinates;
  }

  @Override
  public int hashCode() {
    return Objects.hash(landmarkCoordinates, landmarkKind);
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

    FaceImageLandmarkBlock other = (FaceImageLandmarkBlock) obj;
    return Objects.equals(landmarkCoordinates, other.landmarkCoordinates)
        && Objects.equals(landmarkKind, other.landmarkKind);
  }

  @Override
  public String toString() {
    return "FaceImageLandmarkBlock ["
        + "landmarkKind: " + landmarkKind
        + ", landmarkCoordinates: " + landmarkCoordinates
        + "]";
  }

  /* PACKAGE */

  @Override
  ASN1Encodable getASN1Object() {
    Map<Integer, ASN1Encodable> taggedObjects = new HashMap<Integer, ASN1Encodable>();
    taggedObjects.put(0, encodeLandmarkKind(landmarkKind));
    if (landmarkCoordinates != null) { taggedObjects.put(1, encodeLandmarkCoordinates(landmarkCoordinates)); }
    return ASN1Util.encodeTaggedObjects(taggedObjects);
  }

  static List<FaceImageLandmarkBlock> decodeLandmarkBlocks(ASN1Encodable asn1Encodable) {
    if (ASN1Util.isSequenceOfSequences(asn1Encodable)) {
      List<ASN1Encodable> blockASN1Objects = ASN1Util.list(asn1Encodable);
      List<FaceImageLandmarkBlock> blocks = new ArrayList<FaceImageLandmarkBlock>(blockASN1Objects.size());
      for (ASN1Encodable blockASN1Object: blockASN1Objects) {
        blocks.add(new FaceImageLandmarkBlock(blockASN1Object));
      }
      return blocks;
    } else {
      return Collections.singletonList(new FaceImageLandmarkBlock(asn1Encodable));
    }
  }

  /* PRIVATE */

  private static LandmarkKind decodeLandmarkKind(ASN1Encodable asn1Encodable) {
    Map<Integer, ASN1Encodable> taggedObjects = ASN1Util.decodeTaggedObjects(asn1Encodable);
    if (taggedObjects.containsKey(0)) {
      // base case...
      Map<Integer, ASN1Encodable> baseTaggedObjects = ASN1Util.decodeTaggedObjects(taggedObjects.get(0));
      if (baseTaggedObjects.containsKey(0)) {
        // MPEG feature point case...
        return MPEGFeaturePointCode.fromCode(ISO39794Util.decodeCodeFromChoiceExtensionBlockFallback(baseTaggedObjects.get(0)));
      } else if (baseTaggedObjects.containsKey(1)) {
        decodeAnthropometricLandmark(baseTaggedObjects.get(1));
      }
    }

    return null;
  }

  //  AnthropometricLandmark ::= CHOICE {
  //    base [0] AnthropometricLandmarkBase,
  //    extensionBlock [1] AnthropometricLandmarkExtensionBlock
  //  }

  //  AnthropometricLandmarkBase ::= CHOICE {
  //    anthropometricLandmarkName [0] AnthropometricLandmarkName,
  //    anthropometricLandmarkPointName [1] AnthropometricLandmarkPointName,
  //    anthropometricLandmarkPointId [2] AnthropometricLandmarkPointId
  //  }


  private static LandmarkKind decodeAnthropometricLandmark(ASN1Encodable asn1Encodable) {
    Map<Integer, ASN1Encodable> taggedObjects = ASN1Util.decodeTaggedObjects(asn1Encodable);
    if (taggedObjects.containsKey(0)) {
      // base case...
      Map<Integer, ASN1Encodable> baseTaggedObjects = ASN1Util.decodeTaggedObjects(taggedObjects.get(0));
      if (baseTaggedObjects.containsKey(0)) {
        return AnthropometricLandmarkNameCode.fromCode(ISO39794Util.decodeCodeFromChoiceExtensionBlockFallback(baseTaggedObjects.get(0)));
      } else if (baseTaggedObjects.containsKey(1)) {
        return AnthropometricLandmarkPointNameCode.fromCode(ISO39794Util.decodeCodeFromChoiceExtensionBlockFallback(baseTaggedObjects.get(1)));
      } else if (baseTaggedObjects.containsKey(2)) {
        return AnthropometricLandmarkPointIdCode.fromCode(ISO39794Util.decodeCodeFromChoiceExtensionBlockFallback(baseTaggedObjects.get(2)));
      }
    }

    return null;
  }

  //  LandmarkCoordinates ::= CHOICE {
  //    base [0] LandmarkCoordinatesBase,
  //    extensionBlock [1] LandmarkCoordinatesExtensionBlock
  //  }
  //
  //  LandmarkCoordinatesBase ::= CHOICE {
  //    coordinateCartesian2DBlock [0] CoordinateCartesian2DUnsignedShortBlock,
  //    coordinateTextureImageBlock [1] CoordinateTextureImageBlock,
  //    coordinateCartesian3DBlock [2] CoordinateCartesian3DUnsignedShortBlock
  //  }

  private static FaceImageLandmarkCoordinates decodeLandmarkCoordinates(ASN1Encodable asn1Encodable) {
    Map<Integer, ASN1Encodable> taggedObjects = ASN1Util.decodeTaggedObjects(asn1Encodable);
    if (taggedObjects.containsKey(0)) {
      Map<Integer, ASN1Encodable> baseTaggedObjects = ASN1Util.decodeTaggedObjects(taggedObjects.get(0));
      if (baseTaggedObjects.containsKey(0)) {
        return new CoordinateCartesian2DUnsignedShortBlock(baseTaggedObjects.get(0));
      } else if (baseTaggedObjects.containsKey(1)) {
        return new FaceImageCoordinateTextureImageBlock(baseTaggedObjects.get(1));
      } else if (baseTaggedObjects.containsKey(2)) {
        return new CoordinateCartesian3DUnsignedShortBlock(baseTaggedObjects.get(2));
      }
    }

    return null;
  }

  private static ASN1Encodable encodeLandmarkCoordinates(FaceImageLandmarkCoordinates landmarkCoordinates) {
    Map<Integer, ASN1Encodable> baseTaggedObjects = new HashMap<Integer, ASN1Encodable>();
    if (landmarkCoordinates instanceof CoordinateCartesian2DUnsignedShortBlock) {
      baseTaggedObjects.put(0, ((CoordinateCartesian2DUnsignedShortBlock)landmarkCoordinates).getASN1Object());
    } else if (landmarkCoordinates instanceof FaceImageCoordinateTextureImageBlock) {
      baseTaggedObjects.put(1, ((FaceImageCoordinateTextureImageBlock)landmarkCoordinates).getASN1Object());
    } else if (landmarkCoordinates instanceof CoordinateCartesian3DUnsignedShortBlock) {
      baseTaggedObjects.put(2, ((CoordinateCartesian3DUnsignedShortBlock)landmarkCoordinates).getASN1Object());
    }

    Map<Integer, ASN1Encodable> taggedObjects = new HashMap<Integer, ASN1Encodable>();
    taggedObjects.put(0, ASN1Util.encodeTaggedObjects(baseTaggedObjects));
    return ASN1Util.encodeTaggedObjects(taggedObjects);
  }

  private static ASN1Encodable encodeLandmarkKind(LandmarkKind landmarkKind) {
    Map<Integer, ASN1Encodable> baseTaggedObjects = new HashMap<Integer, ASN1Encodable>();
    if (landmarkKind instanceof MPEGFeaturePointCode) {
      baseTaggedObjects.put(0, ISO39794Util.encodeCodeAsChoiceExtensionBlockFallback(((MPEGFeaturePointCode)landmarkKind).getCode()));
    } else {
      baseTaggedObjects.put(1, encodeAnthropmetricLandmark(landmarkKind));
    }

    Map<Integer, ASN1Encodable> taggedObjects = new HashMap<Integer, ASN1Encodable>();
    taggedObjects.put(0, ASN1Util.encodeTaggedObjects(baseTaggedObjects));
    return ASN1Util.encodeTaggedObjects(taggedObjects);
  }

  private static ASN1Encodable encodeAnthropmetricLandmark(LandmarkKind landmarkKind) {
    Map<Integer, ASN1Encodable> baseTaggedObjects = new HashMap<Integer, ASN1Encodable>();
    if (landmarkKind instanceof AnthropometricLandmarkNameCode) {
      baseTaggedObjects.put(0, ISO39794Util.encodeCodeAsChoiceExtensionBlockFallback(((AnthropometricLandmarkNameCode)landmarkKind).getCode()));
    } else if (landmarkKind instanceof AnthropometricLandmarkPointNameCode) {
      baseTaggedObjects.put(1, ISO39794Util.encodeCodeAsChoiceExtensionBlockFallback(((AnthropometricLandmarkPointNameCode)landmarkKind).getCode()));
    } else if (landmarkKind instanceof AnthropometricLandmarkPointIdCode) {
      baseTaggedObjects.put(2, ISO39794Util.encodeCodeAsChoiceExtensionBlockFallback(((AnthropometricLandmarkPointIdCode)landmarkKind).getCode()));
    }

    Map<Integer, ASN1Encodable> taggedObjects = new HashMap<Integer, ASN1Encodable>();
    taggedObjects.put(0, ASN1Util.encodeTaggedObjects(baseTaggedObjects));
    return ASN1Util.encodeTaggedObjects(taggedObjects);
  }
}
