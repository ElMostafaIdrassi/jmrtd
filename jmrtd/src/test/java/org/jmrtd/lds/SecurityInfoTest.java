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

package org.jmrtd.lds;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.EllipticCurve;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.ECPointUtil;
import org.jmrtd.lds.ActiveAuthenticationInfo;
import org.jmrtd.lds.ChipAuthenticationInfo;
import org.jmrtd.lds.ChipAuthenticationPublicKeyInfo;
import org.jmrtd.lds.PACEDomainParameterInfo;
import org.jmrtd.lds.PACEInfo;
import org.jmrtd.lds.SecurityInfo;
import org.jmrtd.lds.TerminalAuthenticationInfo;
import org.junit.Test;

import net.sf.scuba.util.Hex;

/**
 * Tests the polymorphic getInstance() factory and round-tripping for SecurityInfo subclasses.
 *
 * @author The JMRTD team (info@jmrtd.org)
 */
public class SecurityInfoTest {

  @Test
  public void testActiveAuthenticationInfoRoundTrip() {
    ActiveAuthenticationInfo original = new ActiveAuthenticationInfo(
        ActiveAuthenticationInfo.ECDSA_PLAIN_SHA256_OID);

    ASN1Primitive der = original.getDERObject();
    assertNotNull(der);

    SecurityInfo parsed = SecurityInfo.getInstance(der);
    assertNotNull(parsed);
    assertTrue(parsed instanceof ActiveAuthenticationInfo);
    ActiveAuthenticationInfo actual = (ActiveAuthenticationInfo) parsed;

    assertEquals(original.getObjectIdentifier(), actual.getObjectIdentifier());
    assertEquals(original.getVersion(), actual.getVersion());
    assertEquals(original.getSignatureAlgorithmOID(), actual.getSignatureAlgorithmOID());
    assertEquals(original, actual);
  }

  @Test
  public void testChipAuthenticationInfoRoundTrip() {
    ChipAuthenticationInfo original = new ChipAuthenticationInfo(
        SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128, 2, BigInteger.valueOf(42));

    ASN1Primitive der = original.getDERObject();
    assertNotNull(der);

    SecurityInfo parsed = SecurityInfo.getInstance(der);
    assertNotNull(parsed);
    assertTrue(parsed instanceof ChipAuthenticationInfo);
    ChipAuthenticationInfo actual = (ChipAuthenticationInfo) parsed;

    assertEquals(original.getObjectIdentifier(), actual.getObjectIdentifier());
    assertEquals(original.getVersion(), actual.getVersion());
    assertEquals(original.getKeyId(), actual.getKeyId());
    assertEquals(original, actual);
  }

  @Test
  public void testChipAuthenticationPublicKeyInfoRoundTrip() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
    kpg.initialize(256);
    KeyPair kp = kpg.generateKeyPair();

    ChipAuthenticationPublicKeyInfo original = new ChipAuthenticationPublicKeyInfo(
        SecurityInfo.ID_PK_ECDH, kp.getPublic(), BigInteger.valueOf(99));

    ASN1Primitive der = original.getDERObject();
    assertNotNull(der);

    SecurityInfo parsed = SecurityInfo.getInstance(der);
    assertNotNull(parsed);
    assertTrue(parsed instanceof ChipAuthenticationPublicKeyInfo);
    ChipAuthenticationPublicKeyInfo actual = (ChipAuthenticationPublicKeyInfo) parsed;

    assertEquals(original.getObjectIdentifier(), actual.getObjectIdentifier());
    assertEquals(original.getKeyId(), actual.getKeyId());
    assertEquals(original.getSubjectPublicKey(), actual.getSubjectPublicKey());
    assertEquals(original, actual);
  }

  @Test
  public void testTerminalAuthenticationInfoRoundTrip() {
    TerminalAuthenticationInfo original = new TerminalAuthenticationInfo((short) 0x011C, (byte) 2);

    ASN1Primitive der = original.getDERObject();
    assertNotNull(der);

    SecurityInfo parsed = SecurityInfo.getInstance(der);
    assertNotNull(parsed);
    assertTrue(parsed instanceof TerminalAuthenticationInfo);
    TerminalAuthenticationInfo actual = (TerminalAuthenticationInfo) parsed;

    assertEquals(original.getObjectIdentifier(), actual.getObjectIdentifier());
    assertEquals(original.getVersion(), actual.getVersion());
    assertEquals(original.getFileId(), actual.getFileId());
    assertEquals(original.getShortFileId(), actual.getShortFileId());
    assertEquals(original, actual);
  }

  @Test
  public void testPACEInfoRoundTrip() {
    PACEInfo original = new PACEInfo(
        SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128, 2, BigInteger.valueOf(3));

    ASN1Primitive der = original.getDERObject();
    assertNotNull(der);

    SecurityInfo parsed = SecurityInfo.getInstance(der);
    assertNotNull(parsed);
    assertTrue(parsed instanceof PACEInfo);
    PACEInfo actual = (PACEInfo) parsed;

    assertEquals(original.getObjectIdentifier(), actual.getObjectIdentifier());
    assertEquals(original.getVersion(), actual.getVersion());
    assertEquals(original.getParameterId(), actual.getParameterId());
    assertEquals(original, actual);
  }

  @Test
  public void testPACEDomainParameterInfoRoundTrip() throws Exception {
    EllipticCurve curve = new EllipticCurve(
        new ECFieldFp(new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839")),
        new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16),
        new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16));
    ECParameterSpec ecSpec = new ECParameterSpec(
        curve,
        ECPointUtil.decodePoint(curve, Hex.hexStringToBytes("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")),
        new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307"),
        1);

    AlgorithmIdentifier ai = PACEDomainParameterInfo.toAlgorithmIdentifier(ecSpec);
    PACEDomainParameterInfo original = new PACEDomainParameterInfo(
        SecurityInfo.ID_PACE_ECDH_GM, ai, BigInteger.valueOf(11));

    ASN1Primitive der = original.getDERObject();
    assertNotNull(der);

    SecurityInfo parsed = SecurityInfo.getInstance(der);
    assertNotNull(parsed);
    assertTrue(parsed instanceof PACEDomainParameterInfo);
    PACEDomainParameterInfo actual = (PACEDomainParameterInfo) parsed;

    assertEquals(original.getObjectIdentifier(), actual.getObjectIdentifier());
    assertEquals(original.getParameterId(), actual.getParameterId());
    assertEquals(original, actual);
  }

  @Test
  public void testMalformedInput() {
    // Non-sequence ASN1Encodable should fail parsing
    ASN1Primitive nonSeq = new ASN1Integer(42);
    try {
      SecurityInfo.getInstance(nonSeq);
      fail("Expected IllegalArgumentException for non-sequence structure");
    } catch (IllegalArgumentException e) {
      assertEquals("Malformed input stream.", e.getMessage());
    }

    // Sequence with wrong type inside
    ASN1EncodableVector vec = new ASN1EncodableVector();
    vec.add(new ASN1Integer(123)); // Should be ASN1ObjectIdentifier
    vec.add(new ASN1Integer(1));
    DERSequence badSeq = new DERSequence(vec);

    try {
      SecurityInfo.getInstance(badSeq);
      fail("Expected IllegalArgumentException for incorrect type elements");
    } catch (IllegalArgumentException e) {
      assertEquals("Malformed input stream.", e.getMessage());
    }
  }

  @Test
  public void testUnsupportedProtocolOID() {
    // Sequence with unrecognized OID should return null
    ASN1EncodableVector vec = new ASN1EncodableVector();
    vec.add(new ASN1ObjectIdentifier("1.2.3.4.5.6.7"));
    vec.add(new ASN1Integer(1));
    DERSequence unsupportedSeq = new DERSequence(vec);

    SecurityInfo result = SecurityInfo.getInstance(unsupportedSeq);
    assertNull(result);
  }
}
