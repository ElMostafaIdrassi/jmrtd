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

import java.util.ArrayList;
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
    return encodeCodeAsChoiceExtensionBlockFallback(code, false);
  }

  public static ASN1Encodable encodeCodeAsChoiceExtensionBlockFallback(int code,
      ISO39794EncodingProfile profile, ISO39794EncodingProfile.ChoiceType choiceType) {
    return encodeCodeAsChoiceExtensionBlockFallback(code, profile.usesExtensionBlockFallback(choiceType));
  }

  private static ASN1Encodable encodeCodeAsChoiceExtensionBlockFallback(int code, boolean useExtensionBlock) {
    if (!useExtensionBlock) {
      return new DERSequence(new DERTaggedObject(false, 0, ASN1Util.encodeInt(code)));
    }
    ASN1Encodable fallback = new DERSequence(new DERTaggedObject(false, 0, ASN1Util.encodeInt(code)));
    return new DERSequence(new DERTaggedObject(false, 1, fallback));
  }

  public static ASN1Encodable encodeBlocks(List<? extends Block> blocks) {
    return encodeBlocks(blocks, ISO39794EncodingProfile.BASE);
  }

  public static ASN1Encodable encodeBlocks(List<? extends Block> blocks, ISO39794EncodingProfile profile) {
    if (blocks == null) {
      return null;
    }
    List<ASN1Encodable> asn1Objects = new ArrayList<ASN1Encodable>(blocks.size());
    for (Block block: blocks) {
      if (block != null) {
        asn1Objects.add(block.getASN1Object(profile));
      }
    }
    return new DERSequence(asn1Objects.toArray(new ASN1Encodable[0]));
  }
}
