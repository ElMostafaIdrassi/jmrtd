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

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.jmrtd.ASN1Util;

public class FaceImageIdentityMetadataBlock extends Block {

  private static final long serialVersionUID = 5968313840533997792L;

  public static enum GenderCode implements EncodableEnum<GenderCode> {
    UNKNOWN(0),
    OTHER(1),
    MALE(2),
    FEMALE(3);

    private int code;

    private GenderCode(int code) {
      this.code = code;
    }

    public int getCode() {
      return code;
    }

    public static GenderCode fromCode(int code) {
      return EncodableEnum.fromCode(code, GenderCode.class);
    }
  }

  public static enum EyeColourCode implements EncodableEnum<EyeColourCode> {
    UNKNOWN(0),
    OTHER(1),
    BLACK(2),
    BLUE(3),
    BROWN(4),
    GREY(5),
    GREEN(6),
    HAZEL(7),
    MULTI_COLOURED(8),
    PINK(9);

    private int code;

    private EyeColourCode(int code) {
      this.code = code;
    }

    public int getCode() {
      return code;
    }

    public static EyeColourCode fromCode(int code) {
      return EncodableEnum.fromCode(code, EyeColourCode.class);
    }
  }

  public static enum HairColourCode implements EncodableEnum<HairColourCode> {
    UNKNOWN(0),
    OTHER(1),
    BALD(2),
    BLACK(3),
    BLONDE(4),
    BROWN(5),
    GREY(6),
    WHITE(7),
    RED(8),
    KNOWN_COLOURED(9);

    private int code;

    private HairColourCode(int code) {
      this.code = code;
    }

    public int getCode() {
      return code;
    }

    public static HairColourCode fromCode(int code) {
      return EncodableEnum.fromCode(code, HairColourCode.class);
    }
  }

  private GenderCode genderCode;

  private EyeColourCode eyeColourCode;

  private HairColourCode hairColourCode;

  private int subjectHeight;

  private FaceImagePropertiesBlock propertiesBlock;

  private FaceImageExpressionBlock expressionBlock;

  private FaceImagePoseAngleBlock poseAngleBlock;

  public FaceImageIdentityMetadataBlock(GenderCode genderCode, EyeColourCode eyeColourCode,
      HairColourCode hairColourCode, int subjectHeight, FaceImagePropertiesBlock propertiesBlock,
      FaceImageExpressionBlock expressionBlock, FaceImagePoseAngleBlock poseAngleBlock) {
    this.genderCode = genderCode;
    this.eyeColourCode = eyeColourCode;
    this.hairColourCode = hairColourCode;
    this.subjectHeight = subjectHeight;
    this.propertiesBlock = propertiesBlock;
    this.expressionBlock = expressionBlock;
    this.poseAngleBlock = poseAngleBlock;
  }

  //  IdentityMetadataBlock ::= SEQUENCE {
  //    gender [0] Gender OPTIONAL,
  //    eyeColour [1] EyeColour OPTIONAL,
  //    hairColour [2] HairColour OPTIONAL,
  //    subjectHeight [3] SubjectHeight OPTIONAL,
  //    propertiesBlock [4] PropertiesBlock OPTIONAL,
  //    expressionBlock [5] ExpressionBlock OPTIONAL,
  //    poseAngleBlock [6] PoseAngleBlock OPTIONAL,
  //    ...
  //  }

  FaceImageIdentityMetadataBlock(ASN1Encodable asn1Encodable) {
    if (asn1Encodable == null) {
      throw new IllegalArgumentException("Cannot decode null!");
    }
    if (!(asn1Encodable instanceof ASN1Sequence) && !(asn1Encodable instanceof ASN1TaggedObject)) {
      throw new IllegalArgumentException("Cannot decode!");
    }

    Map<Integer, ASN1Encodable> taggedObjects = ASN1Util.decodeTaggedObjects(asn1Encodable);
    if (taggedObjects.containsKey(0)) {
      genderCode = GenderCode.fromCode(ISO39794Util.decodeCodeFromChoiceExtensionBlockFallback(taggedObjects.get(0)));
    }
    if (taggedObjects.containsKey(1)) {
      eyeColourCode = EyeColourCode.fromCode(ISO39794Util.decodeCodeFromChoiceExtensionBlockFallback(taggedObjects.get(1)));
    }
    if (taggedObjects.containsKey(2)) {
      hairColourCode = HairColourCode.fromCode(ISO39794Util.decodeCodeFromChoiceExtensionBlockFallback(taggedObjects.get(2)));
    }
    if (taggedObjects.containsKey(3)) {
      subjectHeight = ASN1Util.decodeInt(taggedObjects.get(3));
    }
    if (taggedObjects.containsKey(4)) {
      propertiesBlock = new FaceImagePropertiesBlock(taggedObjects.get(4));
    }
    if (taggedObjects.containsKey(5)) {
      expressionBlock = new FaceImageExpressionBlock(taggedObjects.get(5));
    }
    if (taggedObjects.containsKey(6)) {
      poseAngleBlock = new FaceImagePoseAngleBlock(taggedObjects.get(6));
    }
  }

  public GenderCode getGenderCode() {
    return genderCode;
  }

  public EyeColourCode getEyeColourCode() {
    return eyeColourCode;
  }

  public HairColourCode getHairColourCode() {
    return hairColourCode;
  }

  public int getSubjectHeight() {
    return subjectHeight;
  }

  public FaceImagePropertiesBlock getPropertiesBlock() {
    return propertiesBlock;
  }

  public FaceImageExpressionBlock getExpressionBlock() {
    return expressionBlock;
  }

  public FaceImagePoseAngleBlock getPoseAngleBlock() {
    return poseAngleBlock;
  }

  @Override
  public int hashCode() {
    return Objects.hash(expressionBlock, eyeColourCode, genderCode, hairColourCode, poseAngleBlock, propertiesBlock,
        subjectHeight);
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

    FaceImageIdentityMetadataBlock other = (FaceImageIdentityMetadataBlock) obj;
    return Objects.equals(expressionBlock, other.expressionBlock) && eyeColourCode == other.eyeColourCode
        && genderCode == other.genderCode && hairColourCode == other.hairColourCode
        && Objects.equals(poseAngleBlock, other.poseAngleBlock)
        && Objects.equals(propertiesBlock, other.propertiesBlock) && subjectHeight == other.subjectHeight;
  }

  @Override
  public String toString() {
    return "FaceImageIdentityMetadataBlock ["
        + "genderCode: " + genderCode
        + ", eyeColourCode: " + eyeColourCode
        + ", hairColourCode: " + hairColourCode
        + ", subjectHeight: " + subjectHeight
        + ", propertiesBlock: " + propertiesBlock
        + ", expressionBlock: " + expressionBlock
        + ", poseAngleBlock: " + poseAngleBlock
        + "]";
  }

  /* PACKAGE */

  @Override
  ASN1Encodable getASN1Object() {
    Map<Integer, ASN1Encodable> taggedObjects = new HashMap<Integer, ASN1Encodable>();
    if (genderCode != null) {
      taggedObjects.put(0, ISO39794Util.encodeCodeAsChoiceExtensionBlockFallback(genderCode.getCode()));
    }
    if (eyeColourCode != null) {
      taggedObjects.put(1, ISO39794Util.encodeCodeAsChoiceExtensionBlockFallback(eyeColourCode.getCode()));
    }
    if (hairColourCode != null) {
      taggedObjects.put(2, ISO39794Util.encodeCodeAsChoiceExtensionBlockFallback(hairColourCode.getCode()));
    }
    if (subjectHeight >= 0) {
      taggedObjects.put(3, ASN1Util.encodeInt(subjectHeight));
    }
    if (propertiesBlock != null) {
      taggedObjects.put(4, propertiesBlock.getASN1Object());
    }
    if (expressionBlock != null) {
      taggedObjects.put(5, expressionBlock.getASN1Object());
    }
    if (poseAngleBlock != null) {
      taggedObjects.put(6, poseAngleBlock.getASN1Object());
    }
    return ASN1Util.encodeTaggedObjects(taggedObjects);
  }
}
