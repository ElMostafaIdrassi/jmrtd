package org.jmrtd.lds.iso39794;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.bouncycastle.asn1.ASN1Encodable;
import org.jmrtd.ASN1Util;

public class CoordinateCartesian2DUnsignedShortBlock extends Block implements FaceImageLandmarkCoordinates {

  private static final long serialVersionUID = -3221155578581711766L;

  //  CoordinateCartesian2DUnsignedShortBlock ::= SEQUENCE {
  //    x               [0] INTEGER (0..65535),
  //    y               [1] INTEGER (0..65535)
  //  }

  private int x;
  private int y;

  public CoordinateCartesian2DUnsignedShortBlock(int x, int y) {
    this.x = x;
    this.y = y;
  }

  CoordinateCartesian2DUnsignedShortBlock(ASN1Encodable asn1Encodable) {
    Map<Integer, ASN1Encodable> taggedObjects = ASN1Util.decodeTaggedObjects(asn1Encodable);
    x = ASN1Util.decodeInt(taggedObjects.get(0));
    y = ASN1Util.decodeInt(taggedObjects.get(1));
  }

  public int getX() {
    return x;
  }

  public int getY() {
    return y;
  }

  @Override
  public int hashCode() {
    return Objects.hash(x, y);
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

    CoordinateCartesian2DUnsignedShortBlock other = (CoordinateCartesian2DUnsignedShortBlock) obj;
    return x == other.x && y == other.y;
  }

  @Override
  public String toString() {
    return "CoordinateCartesian2DUnsignedShortBlock ["
        + "x: " + x
        + ", y: " + y
        + "]";
  }

  /* PACKAGE */

  static List<CoordinateCartesian2DUnsignedShortBlock> decodeCoordinateCartesian2DUnsignedShortBlocks(ASN1Encodable asn1Encodable) {
    if (ASN1Util.isSequenceOfSequences(asn1Encodable)) {
      List<ASN1Encodable> blockASN1Objects = ASN1Util.list(asn1Encodable);
      List<CoordinateCartesian2DUnsignedShortBlock> blocks = new ArrayList<CoordinateCartesian2DUnsignedShortBlock>(blockASN1Objects.size());
      for (ASN1Encodable blockASN1Object: blockASN1Objects) {
        blocks.add(new CoordinateCartesian2DUnsignedShortBlock(blockASN1Object));
      }
      return blocks;
    } else {
      return Collections.singletonList(new CoordinateCartesian2DUnsignedShortBlock(asn1Encodable));
    }
  }

  @Override
  ASN1Encodable getASN1Object() {
    Map<Integer, ASN1Encodable> taggedObjects = new HashMap<Integer, ASN1Encodable>();
    taggedObjects.put(0,ASN1Util.encodeInt(x));
    taggedObjects.put(1, ASN1Util.encodeInt(y));
    return ASN1Util.encodeTaggedObjects(taggedObjects);
  }
}
