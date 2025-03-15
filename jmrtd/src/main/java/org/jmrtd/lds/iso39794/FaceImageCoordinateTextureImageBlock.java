package org.jmrtd.lds.iso39794;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import org.bouncycastle.asn1.ASN1Encodable;
import org.jmrtd.ASN1Util;

public class FaceImageCoordinateTextureImageBlock extends Block implements FaceImageLandmarkCoordinates {

  private static final long serialVersionUID = -563037651358748573L;

  private BigInteger uInPixel;
  private BigInteger vInPixel;

  public FaceImageCoordinateTextureImageBlock(BigInteger uInPixel, BigInteger vInPixel) {
    this.uInPixel = uInPixel;
    this.vInPixel = vInPixel;
  }

  //  CoordinateTextureImageBlock ::= SEQUENCE {
  //    uInPixel [0] INTEGER (0..MAX),
  //    vInPixel [1] INTEGER (0..MAX)
  //  }

  FaceImageCoordinateTextureImageBlock(ASN1Encodable asn1Encodable) {
    Map<Integer, ASN1Encodable> taggedObjects = ASN1Util.decodeTaggedObjects(asn1Encodable);
    uInPixel = ASN1Util.decodeBigInteger(taggedObjects.get(0));
    vInPixel = ASN1Util.decodeBigInteger(taggedObjects.get(1));
  }

  public BigInteger getUInPixel() {
    return uInPixel;
  }

  public BigInteger getVInPixel() {
    return vInPixel;
  }

  @Override
  public int hashCode() {
    return Objects.hash(uInPixel, vInPixel);
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

    FaceImageCoordinateTextureImageBlock other = (FaceImageCoordinateTextureImageBlock) obj;
    return Objects.equals(uInPixel, other.uInPixel) && Objects.equals(vInPixel, other.vInPixel);
  }

  @Override
  public String toString() {
    return "CoordinateTextureImageBlock ["
        + "uInPixel: " + uInPixel
        + ", vInPixel: " + vInPixel
        + "]";
  }

  /* PACKAGE */

  @Override
  ASN1Encodable getASN1Object() {
    Map<Integer, ASN1Encodable> taggedObjects = new HashMap<Integer, ASN1Encodable>();
    taggedObjects.put(0,ASN1Util.encodeBigInteger(uInPixel));
    taggedObjects.put(1, ASN1Util.encodeBigInteger(vInPixel));
    return ASN1Util.encodeTaggedObjects(taggedObjects);
  }
}
