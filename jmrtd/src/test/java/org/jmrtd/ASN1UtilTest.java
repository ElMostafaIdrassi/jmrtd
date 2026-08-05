/*
 * JMRTD - A Java API for accessing machine readable travel documents.
 *
 * Copyright (C) 2006 - 2026  The JMRTD team
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
 */

package org.jmrtd;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.junit.Test;

public class ASN1UtilTest {

  @Test
  public void testReadASN1Object() throws IOException {
    byte[] sequenceBytes = new DERSequence(new ASN1Integer(42)).getEncoded();
    ByteArrayInputStream bais = new ByteArrayInputStream(sequenceBytes);
    ASN1Encodable obj = ASN1Util.readASN1Object(bais);
    assertNotNull(obj);
    assertTrue(obj instanceof ASN1Primitive);
  }

  @Test
  public void testCheckTag() {
    DEROctetString octets = new DEROctetString(new byte[] { 1, 2, 3 });
    // Creating a tagged object with class CONTEXT_SPECIFIC (128) and tag number 1
    DERTaggedObject tagged = new DERTaggedObject(true, 1, octets);

    ASN1Encodable base = ASN1Util.checkTag(tagged, BERTags.CONTEXT_SPECIFIC, 1);
    assertNotNull(base);
    assertTrue(base instanceof DEROctetString);

    // Mismatched tag class
    try {
      ASN1Util.checkTag(tagged, BERTags.APPLICATION, 1);
      fail("Should have thrown IllegalArgumentException for mismatched tag class");
    } catch (IllegalArgumentException e) {
      // Expected
    }

    // Mismatched tag number
    try {
      ASN1Util.checkTag(tagged, BERTags.CONTEXT_SPECIFIC, 2);
      fail("Should have thrown IllegalArgumentException for mismatched tag number");
    } catch (IllegalArgumentException e) {
      // Expected
    }

    // Null object
    try {
      ASN1Util.checkTag(null, BERTags.CONTEXT_SPECIFIC, 1);
      fail("Should have thrown IllegalArgumentException for null object");
    } catch (IllegalArgumentException e) {
      // Expected
    }
  }

  @Test
  public void testIsSequenceOfSequences() {
    DERSequence inner1 = new DERSequence(new ASN1Integer(1));
    DERSequence inner2 = new DERSequence(new ASN1Integer(2));
    DERSequence outerSequence = new DERSequence(new ASN1Encodable[] { inner1, inner2 });

    assertTrue(ASN1Util.isSequenceOfSequences(outerSequence));

    // Outer is not a sequence of sequences if one of them is not a sequence
    DERSequence invalidSequence = new DERSequence(new ASN1Encodable[] { inner1, ASN1Boolean.TRUE });
    assertFalse(ASN1Util.isSequenceOfSequences(invalidSequence));

    // Not even a sequence
    assertFalse(ASN1Util.isSequenceOfSequences(ASN1Boolean.TRUE));
  }

  @Test
  public void testDecodeTaggedObjects() {
    DEROctetString octets1 = new DEROctetString(new byte[] { 1 });
    DEROctetString octets2 = new DEROctetString(new byte[] { 2 });

    DERTaggedObject tagged1 = new DERTaggedObject(true, 1, octets1);
    DERTaggedObject tagged2 = new DERTaggedObject(true, 2, octets2);

    DERSequence sequenceOfTagged = new DERSequence(new ASN1Encodable[] { tagged1, tagged2 });

    Map<Integer, ASN1Encodable> map = ASN1Util.decodeTaggedObjects(sequenceOfTagged);
    assertNotNull(map);
    assertEquals(2, map.size());
    assertTrue(map.containsKey(1));
    assertTrue(map.containsKey(2));

    // Decode single tagged object directly
    Map<Integer, ASN1Encodable> singleMap = ASN1Util.decodeTaggedObjects(tagged1);
    assertNotNull(singleMap);
    assertEquals(1, singleMap.size());
    assertTrue(singleMap.containsKey(1));
  }

  @Test
  public void testList() {
    DERSequence seq = new DERSequence(new ASN1Encodable[] { new ASN1Integer(1), new ASN1Integer(2) });
    List<ASN1Encodable> list = ASN1Util.list(seq);
    assertNotNull(list);
    assertEquals(2, list.size());
    assertEquals(new ASN1Integer(1), list.get(0));
    assertEquals(new ASN1Integer(2), list.get(1));

    // Non-sequence single object fallback
    ASN1Integer single = new ASN1Integer(42);
    List<ASN1Encodable> listSingle = ASN1Util.list(single);
    assertNotNull(listSingle);
    assertEquals(1, listSingle.size());
    assertEquals(single, listSingle.get(0));

    // Null case
    List<ASN1Encodable> listNull = ASN1Util.list(null);
    assertNull(listNull);
  }

  @Test
  public void testDecodeIntAndBigInteger() {
    byte[] bytes = new byte[] { 0x01, 0x02 }; // 258
    DEROctetString octets = new DEROctetString(bytes);

    assertEquals(258, ASN1Util.decodeInt(octets));
    assertEquals(BigInteger.valueOf(258), ASN1Util.decodeBigInteger(octets));

    // Exceptional flow
    try {
      ASN1Util.decodeInt(new ASN1Integer(1));
      fail("Should have thrown NumberFormatException");
    } catch (NumberFormatException e) {
      // Expected
    }

    try {
      ASN1Util.decodeBigInteger(new ASN1Integer(1));
      fail("Should have thrown NumberFormatException");
    } catch (NumberFormatException e) {
      // Expected
    }
  }

  @Test
  public void testDecodeAndEncodeBoolean() {
    ASN1Encodable encTrue = ASN1Util.encodeBoolean(true);
    assertTrue(ASN1Util.decodeBoolean(encTrue));

    ASN1Encodable encFalse = ASN1Util.encodeBoolean(false);
    assertFalse(ASN1Util.decodeBoolean(encFalse));

    assertTrue(ASN1Util.decodeBoolean(ASN1Boolean.TRUE));
    assertFalse(ASN1Util.decodeBoolean(ASN1Boolean.FALSE));

    try {
      ASN1Util.decodeBoolean(new ASN1Integer(1));
      fail("Should have thrown IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      // Expected
    }
  }

  @Test
  public void testEncodeIntAndBigInteger() {
    ASN1Encodable encInt = ASN1Util.encodeInt(12345);
    assertEquals(BigInteger.valueOf(12345), ASN1Util.decodeBigInteger(encInt));

    ASN1Encodable encBig = ASN1Util.encodeBigInteger(BigInteger.valueOf(9876543210L));
    assertEquals(BigInteger.valueOf(9876543210L), ASN1Util.decodeBigInteger(encBig));
  }

  @Test
  public void testEncodeTaggedObjects() {
    java.util.Map<Integer, ASN1Encodable> map = new java.util.HashMap<Integer, ASN1Encodable>();
    map.put(3, new ASN1Integer(100));
    map.put(4, null); // should be skipped
    map.put(5, new ASN1Integer(200));

    ASN1Encodable encoded = ASN1Util.encodeTaggedObjects(map);
    assertNotNull(encoded);
    assertTrue(encoded instanceof DERSequence);

    java.util.Map<Integer, ASN1Encodable> decoded = ASN1Util.decodeTaggedObjects(encoded);
    assertEquals(2, decoded.size());
    assertEquals(new ASN1Integer(100), decoded.get(3));
    assertEquals(new ASN1Integer(200), decoded.get(5));

    assertNull(ASN1Util.encodeTaggedObjects(null));
  }
}
