package org.jmrtd.lds.iso39794;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import org.bouncycastle.asn1.ASN1Encodable;
import org.jmrtd.ASN1Util;

public class CoordinateCartesian3DUnsignedShortBlock extends Block implements FaceImageLandmarkCoordinates {

  private static final long serialVersionUID = -6100355379192071041L;

  private int x;
  private int y;
  private int z;

  public CoordinateCartesian3DUnsignedShortBlock(int x, int y, int z) {
    this.x = x;
    this.y = y;
    this.z = z;
  }

  //  CoordinateCartesian3DUnsignedShortBlock ::= SEQUENCE {
  //    x               [0] INTEGER (0..65535),
  //    y               [1] INTEGER (0..65535),
  //    z               [2] INTEGER (0..65535)
  //  }

  CoordinateCartesian3DUnsignedShortBlock(ASN1Encodable asn1Encodable) {
    Map<Integer, ASN1Encodable> taggedObjects = ASN1Util.decodeTaggedObjects(asn1Encodable);
    x = ASN1Util.decodeInt(taggedObjects.get(0));
    y = ASN1Util.decodeInt(taggedObjects.get(1));
    z = ASN1Util.decodeInt(taggedObjects.get(2));
  }

  public int getX() {
    return x;
  }

  public int getY() {
    return y;
  }

  public int getZ() {
    return z;
  }

  @Override
  public int hashCode() {
    return Objects.hash(x, y, z);
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

    CoordinateCartesian3DUnsignedShortBlock other = (CoordinateCartesian3DUnsignedShortBlock) obj;
    return x == other.x && y == other.y && z == other.z;
  }

  @Override
  public String toString() {
    return "CoordinateCartesian3DUnsignedShortBlock ["
        + "x: " + x
        + ", y: " + y
        + ", z: " + z
        + "]";
  }

  /* PACKAGE */

  @Override
  ASN1Encodable getASN1Object() {
    Map<Integer, ASN1Encodable> taggedObjects = new HashMap<Integer, ASN1Encodable>();
    taggedObjects.put(0,ASN1Util.encodeInt(x));
    taggedObjects.put(1, ASN1Util.encodeInt(y));
    taggedObjects.put(2, ASN1Util.encodeInt(z));
    return ASN1Util.encodeTaggedObjects(taggedObjects);
  }
}
