package org.jmrtd.lds.iso39794;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import org.bouncycastle.asn1.ASN1Encodable;
import org.jmrtd.ASN1Util;

public class FaceImagePoseAngleBlock extends Block {

  private static final long serialVersionUID = -7526271037214134760L;

  public static class AngleDataBlock extends Block {

    private static final long serialVersionUID = 3589963464356857977L;

    /** INTEGER (-180..180). */
    private int angleValue;

    /** INTEGER (0..180). */
    private int angleUncertainty;

    public AngleDataBlock(int angleValue, int angleUncertainty) {
      this.angleValue = angleValue;
      this.angleUncertainty = angleUncertainty;
    }

    AngleDataBlock(ASN1Encodable asn1Encodable) {
      Map<Integer, ASN1Encodable> taggedObjects = ASN1Util.decodeTaggedObjects(asn1Encodable);
      angleValue = ASN1Util.decodeInt(taggedObjects.get(0));
      if (taggedObjects.containsKey(1)) {
        angleUncertainty = ASN1Util.decodeInt(taggedObjects.get(1));
      } else {
        angleUncertainty = -1;
      }
    }

    public int getAngleValue() {
      return angleValue;
    }

    public int getAngleUncertainty() {
      return angleUncertainty;
    }

    @Override
    public int hashCode() {
      return Objects.hash(angleUncertainty, angleValue);
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

      AngleDataBlock other = (AngleDataBlock) obj;
      return angleUncertainty == other.angleUncertainty && angleValue == other.angleValue;
    }

    @Override
    public String toString() {
      return "AngleDataBlock ["
          + "angleValue: " + angleValue
          + ", angleUncertainty: " + angleUncertainty
          + "]";
    }

    @Override
    ASN1Encodable getASN1Object() {
      Map<Integer, ASN1Encodable> taggedObjects = new HashMap<Integer, ASN1Encodable>();
      taggedObjects.put(0, ASN1Util.encodeInt(angleValue));
      if (angleUncertainty >= 0) {
        taggedObjects.put(1, ASN1Util.encodeInt(angleUncertainty));
      }
      return ASN1Util.encodeTaggedObjects(taggedObjects);
    }
  }

  private AngleDataBlock yawAngleDataBlock;

  private AngleDataBlock pitchAngleDataBlock;

  private AngleDataBlock rollAngleDataBlock;

  //  PoseAngleBlock ::= SEQUENCE {
  //    yawAngleBlock [0] AngleDataBlock OPTIONAL,
  //    pitchAngleBlock [1] AngleDataBlock OPTIONAL,
  //    rollAngleBlock [2] AngleDataBlock OPTIONAL
  //  }

  FaceImagePoseAngleBlock(ASN1Encodable asn1Encodable) {
    Map<Integer, ASN1Encodable> taggedObjects = ASN1Util.decodeTaggedObjects(asn1Encodable);
    if (taggedObjects.containsKey(0)) {
      yawAngleDataBlock = new AngleDataBlock(taggedObjects.get(0));
    }
    if (taggedObjects.containsKey(1)) {
      pitchAngleDataBlock = new AngleDataBlock(taggedObjects.get(1));
    }
    if (taggedObjects.containsKey(2)) {
      rollAngleDataBlock = new AngleDataBlock(taggedObjects.get(2));
    }
  }

  public static long getSerialversionuid() {
    return serialVersionUID;
  }

  public AngleDataBlock getYawAngleDataBlock() {
    return yawAngleDataBlock;
  }

  public AngleDataBlock getPitchAngleDataBlock() {
    return pitchAngleDataBlock;
  }

  public AngleDataBlock getRollAngleDataBlock() {
    return rollAngleDataBlock;
  }

  @Override
  public int hashCode() {
    return Objects.hash(pitchAngleDataBlock, rollAngleDataBlock, yawAngleDataBlock);
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

    FaceImagePoseAngleBlock other = (FaceImagePoseAngleBlock) obj;
    return Objects.equals(pitchAngleDataBlock, other.pitchAngleDataBlock)
        && Objects.equals(rollAngleDataBlock, other.rollAngleDataBlock)
        && Objects.equals(yawAngleDataBlock, other.yawAngleDataBlock);
  }

  @Override
  public String toString() {
    return "FaceImagePoseAngleBlock ["
        + "yawAngleDataBlock: " + yawAngleDataBlock
        + ", pitchAngleDataBlock: " + pitchAngleDataBlock
        + ", rollAngleDataBlock: " + rollAngleDataBlock
        + "]";
  }

  /* PACKAGE */

  @Override
  ASN1Encodable getASN1Object() {
    Map<Integer, ASN1Encodable> taggedObjects = new HashMap<Integer, ASN1Encodable>();
    if (yawAngleDataBlock != null) {
      taggedObjects.put(0, yawAngleDataBlock.getASN1Object());
    }
    if (pitchAngleDataBlock != null) {
      taggedObjects.put(1, pitchAngleDataBlock.getASN1Object());
    }
    if (rollAngleDataBlock != null) {
      taggedObjects.put(2, rollAngleDataBlock.getASN1Object());
    }
    return ASN1Util.encodeTaggedObjects(taggedObjects);
  }
}
