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
 */

package org.jmrtd.lds.iso39794;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.jmrtd.ASN1Util;

class ISO39794Util {

  /** Hides default constructor. */
  private ISO39794Util() {
  }

  public static Integer decodeCodeFromChoiceExtensionBlockFallback(ASN1Encodable asn1Encodable) {
    Map<Integer, ASN1Encodable> taggedObjects = ASN1Util.decodeTaggedObjects(asn1Encodable);
    if (taggedObjects.containsKey(0)) {
      return ASN1Util.decodeInt(taggedObjects.get(0));
    }
    if (taggedObjects.containsKey(1)) {
      Map<Integer, ASN1Encodable> extensionTaggedObjects = ASN1Util.decodeTaggedObjects(taggedObjects.get(1));
      /* Fallback: */
      return ASN1Util.decodeInt(extensionTaggedObjects.get(0));
    }

    return null;
  }

  public static ASN1Encodable encodeCodeAsChoiceExtensionBlockFallback(int code) {
    return new DERSequence(new DERTaggedObject(false, 0, ASN1Util.encodeInt(code)));
  }

  //  ScoreOrError ::= CHOICE {
  //    score   [0] Score,
  //    error   [1] ScoringError
  //  }

  public static int decodeScoreOrError(ASN1Encodable asn1Encodable) {
    Map<Integer, ASN1Encodable> taggedObjects = ASN1Util.decodeTaggedObjects(asn1Encodable);
    if (taggedObjects.containsKey(0)) {
      return ASN1Util.decodeInt(taggedObjects.get(0));
    }

    /* NOTE: We could navigate the object under [1], and distinguish between failureToAssess or extension. */
    return -1;
  }

  public static ASN1Encodable encodeScoreOrError(int score) {
    Map<Integer, ASN1Encodable> taggedObjects = new HashMap<Integer, ASN1Encodable>();
    if (score >= 0) {
      taggedObjects.put(0, ASN1Util.encodeInt(score));
    }
    return ASN1Util.encodeTaggedObjects(taggedObjects);
  }

  public static ASN1Encodable encodeBlocks(List<? extends Block> blocks) {
    ASN1Encodable[] asn1Objects = new ASN1Encodable[blocks.size()];
    int i = 0;
    for (Block block: blocks) {
      asn1Objects[i++] = block.getASN1Object();
    }
    return new DERSequence(asn1Objects);
  }
}
