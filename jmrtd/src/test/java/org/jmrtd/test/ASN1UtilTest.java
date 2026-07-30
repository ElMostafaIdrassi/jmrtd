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

package org.jmrtd.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.jmrtd.ASN1Util;
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
}
