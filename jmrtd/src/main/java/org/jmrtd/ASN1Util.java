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
 * $Id: $
 */

package org.jmrtd;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

public class ASN1Util {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  public static ASN1Encodable readASN1Object(InputStream inputStream) throws IOException {
    ASN1InputStream asn1InputStream = new ASN1InputStream(inputStream, true);
    return asn1InputStream.readObject();
  }

  /**
   * Checks whether an ASN1 object is a tagged object with a specific tag class and tag number.
   * Throws an unchecked exception if not.
   *
   * @param asn1Encodable the ASN1 object
   * @param tagClass the expected tag class
   * @param tagNo the exepected tag number
   *
   * @return the base object
   */
  public static ASN1Encodable checkTag(ASN1Encodable asn1Encodable, int tagClass, int tagNo) {
    if (asn1Encodable == null) {
      throw new IllegalArgumentException("Expected a tagged object. Found null.");
    }

    if (!(asn1Encodable instanceof ASN1TaggedObject)) {
      throw new IllegalArgumentException("Expected a tagged object. Found " + asn1Encodable.getClass());
    }

    ASN1TaggedObject asn1TaggedObject = ASN1TaggedObject.getInstance(asn1Encodable);
    if (asn1TaggedObject.getTagClass() != tagClass && asn1TaggedObject.getTagNo() != tagNo) {
      throw new IllegalArgumentException("Expected "
          + "[" + tagClassToString(tagClass) + " " + tagNo + "], found "
          + "[" + tagClassToString(asn1TaggedObject.getTagClass())
          + " " + asn1TaggedObject.getTagNo() + "]");
    }

    return asn1TaggedObject.getBaseObject();
  }

  /**
   * Checks whether an ASN1 object is itself a sequence and contains sequences.
   *
   * @param asn1Encodable an ASN1 object
   *
   * @return a boolean indicating whether the ASN1 object is a sequence of only sequences
   */
  public static boolean isSequenceOfSequences(ASN1Encodable asn1Encodable) {
    if (!(asn1Encodable instanceof ASN1Sequence)) {
      return false;
    }
    ASN1Sequence asn1Sequence = ASN1Sequence.getInstance(asn1Encodable);
    int count = asn1Sequence.size();
    for (int i = 0; i < count; i++) {
      ASN1Encodable asn1Object = asn1Sequence.getObjectAt(i);
      if (!(asn1Object instanceof ASN1Sequence)) {
        return false;
      }
    }

    return true;
  }

  /**
   * Converts an ASN1 sequence of tagged objects to a map.
   * Maps tag numbers to base objects.
   *
   * @param asn1Encodable an ASN1 sequence of tagged objects
   *
   * @return a map
   */
  public static Map<Integer, ASN1Encodable> decodeTaggedObjects(ASN1Encodable asn1Encodable) {
    Map<Integer, ASN1Encodable> taggedObjects = new HashMap<Integer, ASN1Encodable>();
    if (asn1Encodable == null) {
      return taggedObjects;
    }

    if (asn1Encodable instanceof ASN1Sequence) {
      ASN1Sequence asn1Sequence = ASN1Sequence.getInstance(asn1Encodable);

      int count = asn1Sequence.size();
      for (int i = 0; i < count; i++) {
        ASN1Encodable asn1Object = asn1Sequence.getObjectAt(i);
        if (!(asn1Object instanceof ASN1TaggedObject)) {
          LOGGER.warning("Not a tagged object. Skipping " + asn1Object.getClass());
          continue;
        }

        ASN1TaggedObject asn1TaggedObject = ASN1TaggedObject.getInstance(asn1Object);
        int tagClass = asn1TaggedObject.getTagClass();
        int tagNo = asn1TaggedObject.getTagNo();
        if (taggedObjects.containsKey(tagNo)) {
          LOGGER.warning("Double key " + tagNo);
        }
        ASN1Encodable baseObject = asn1TaggedObject.getBaseObject();
        taggedObjects.put(tagNo, baseObject);
      }
    } else if (asn1Encodable instanceof ASN1TaggedObject) {
      ASN1TaggedObject asn1TaggedObject = ASN1TaggedObject.getInstance(asn1Encodable);
      int tagNo = asn1TaggedObject.getTagNo();
      taggedObjects.put(tagNo, asn1TaggedObject.getBaseObject());
    } else {
      throw new IllegalArgumentException("Not a sequence and not a tagged object " + asn1Encodable.getClass());
    }

    return taggedObjects;
  }

  /**
   * Converts an ASN1 sequence to a list.
   *
   * @param asn1Encodable the ASN1 sequence
   *
   * @return a list with element ASN1 objects
   */
  public static List<ASN1Encodable> list(ASN1Encodable asn1Encodable) {
    if (asn1Encodable == null) {
      return null;
    }

    if (asn1Encodable instanceof ASN1Sequence) {
      ASN1Sequence asn1Sequence = (ASN1Sequence)asn1Encodable;
      int count = asn1Sequence.size();
      List<ASN1Encodable> result = new ArrayList<ASN1Encodable>(count);
      for (int i = 0; i < count; i++) {
        ASN1Encodable subObject = asn1Sequence.getObjectAt(i);
        result.add(subObject);
      }
      return result;
    }

    return Collections.singletonList(asn1Encodable);
  }

  public static int decodeInt(ASN1Encodable asn1Encodable) {
    BigInteger bigInteger = decodeBigInteger(asn1Encodable);
    if (bigInteger == null) {
      throw new NumberFormatException("Could not parse integer");
    }
    return bigInteger.intValue();
  }

  public static BigInteger decodeBigInteger(ASN1Encodable asn1Encodable) {
    if (!(asn1Encodable instanceof ASN1OctetString)) {
      throw new NumberFormatException("Could not parse integer");
    }
    ASN1OctetString octetString = ASN1OctetString.getInstance(asn1Encodable);
    if (octetString == null) {
      throw new NumberFormatException("Could not parse integer");
    }
    byte[] octets = octetString.getOctets();
    return new BigInteger(octets);
  }

  public static boolean decodeBoolean(ASN1Encodable asn1Encodable) {
    if (asn1Encodable instanceof ASN1Boolean) {
      ASN1Boolean asn1Boolean = (ASN1Boolean)asn1Encodable;
      return asn1Boolean.isTrue();
    } else if (asn1Encodable instanceof ASN1OctetString) {
      byte[] octets = ((ASN1OctetString)asn1Encodable).getOctets();
      return (octets[0] & 0xFF) != 0x00;
    } else {
      throw new IllegalArgumentException("Could not decode boolean from " + asn1Encodable);
    }
  }

  public static ASN1Encodable encodeBoolean(boolean b) {
    return new DEROctetString(new byte[] { (byte)(b ? 0xFF : 0x00) });
  }

  public static ASN1Encodable encodeInt(int n) {
    return encodeBigInteger(BigInteger.valueOf(n));
  }

  public static ASN1Encodable encodeBigInteger(BigInteger n) {
    return new DEROctetString(n.toByteArray());
  }

  public static ASN1Encodable encodeTaggedObjects(Map<Integer, ASN1Encodable> taggedObjects) {
    ASN1Encodable[] asn1Objects = new ASN1Encodable[taggedObjects.size()];
    int i = 0;
    for (Map.Entry<Integer, ASN1Encodable> entry: taggedObjects.entrySet()) {
      asn1Objects[i++] = new DERTaggedObject(entry.getKey(), entry.getValue());
    }
    return new DERSequence(asn1Objects);
  }

  /* PRIVATE. */

  private static String tagClassToString(int tagClass) {
    switch (tagClass) {
    case BERTags.APPLICATION: return "APPLICATION";
    case BERTags.UNIVERSAL: return "UNIVERSAL";
    case BERTags.CONTEXT_SPECIFIC: return "CONTEXT_SPECIFIC";
    case BERTags.PRIVATE: return "PRIVATE";
    default:
      return Integer.toString(tagClass);
    }
  }
}
