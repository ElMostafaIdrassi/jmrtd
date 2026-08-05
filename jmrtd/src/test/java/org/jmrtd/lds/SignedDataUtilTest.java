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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.jmrtd.CertificateUtil;
import org.jmrtd.Util;
import org.junit.BeforeClass;
import org.junit.Test;

public class SignedDataUtilTest {

  @BeforeClass
  public static void setUp() {
    Security.addProvider(Util.getBouncyCastleProvider());
  }

  @Test
  public void testOidMnemonicTranslations() throws Exception {
    // Standard digests
    assertEquals("SHA-256", SignedDataUtil.lookupMnemonicByOID("2.16.840.1.101.3.4.2.1"));
    assertEquals("SHA-512", SignedDataUtil.lookupMnemonicByOID("2.16.840.1.101.3.4.2.3"));
    assertEquals("SHA-384", SignedDataUtil.lookupMnemonicByOID("2.16.840.1.101.3.4.2.2"));
    assertEquals("SHA-224", SignedDataUtil.lookupMnemonicByOID("2.16.840.1.101.3.4.2.4"));

    assertEquals("2.16.840.1.101.3.4.2.1", SignedDataUtil.lookupOIDByMnemonic("SHA-256"));
    assertEquals("2.16.840.1.101.3.4.2.3", SignedDataUtil.lookupOIDByMnemonic("SHA-512"));
    assertEquals("2.16.840.1.101.3.4.2.2", SignedDataUtil.lookupOIDByMnemonic("SHA-384"));
    assertEquals("2.16.840.1.101.3.4.2.4", SignedDataUtil.lookupOIDByMnemonic("SHA-224"));

    // Directory attributes
    assertEquals("CN", SignedDataUtil.lookupMnemonicByOID("2.5.4.3"));
    assertEquals("OU", SignedDataUtil.lookupMnemonicByOID("2.5.4.11"));
    assertEquals("O", SignedDataUtil.lookupMnemonicByOID("2.5.4.10"));
    assertEquals("C", SignedDataUtil.lookupMnemonicByOID("2.5.4.6"));

    assertEquals("2.5.4.3", SignedDataUtil.lookupOIDByMnemonic("CN"));
    assertEquals("2.5.4.11", SignedDataUtil.lookupOIDByMnemonic("OU"));
    assertEquals("2.5.4.10", SignedDataUtil.lookupOIDByMnemonic("O"));
    assertEquals("2.5.4.6", SignedDataUtil.lookupOIDByMnemonic("C"));

    // Signature algorithms
    assertEquals("SHA256withRSA", SignedDataUtil.lookupMnemonicByOID("1.2.840.113549.1.1.11"));
    assertEquals("1.2.840.113549.1.1.11", SignedDataUtil.lookupOIDByMnemonic("SHA256withRSA"));

    // Null and exceptional values
    assertNull(SignedDataUtil.lookupMnemonicByOID(null));

    try {
      SignedDataUtil.lookupMnemonicByOID("1.3.5.7.9");
      fail("Should have thrown NoSuchAlgorithmException");
    } catch (NoSuchAlgorithmException e) {
      // Expected
    }

    try {
      SignedDataUtil.lookupOIDByMnemonic("InvalidMnemonicName");
      fail("Should have thrown NoSuchAlgorithmException");
    } catch (NoSuchAlgorithmException e) {
      // Expected
    }
  }

  @Test
  public void testSignedDataRoundTripAndVerification() throws Exception {
    KeyPairGenerator rsaGenerator = KeyPairGenerator.getInstance("RSA");
    rsaGenerator.initialize(1024);
    KeyPair keyPair = rsaGenerator.generateKeyPair();
    PublicKey publicKey = keyPair.getPublic();
    PrivateKey privateKey = keyPair.getPrivate();

    Date validFrom = new Date(System.currentTimeMillis() - 10000);
    Date validTo = new Date(System.currentTimeMillis() + 10000);
    X509Certificate docSigningCertificate = CertificateUtil.createCertificate(
        "C=NL, O=JMRTD, CN=DocSigning",
        "C=NL, O=JMRTD, CN=DocSigning",
        validFrom,
        validTo,
        publicKey,
        privateKey,
        "SHA256withRSA"
    );

    // Create simple content info containing a valid encoded ASN.1 object
    ASN1ObjectIdentifier testOid = new ASN1ObjectIdentifier("1.2.3.4.5.6");
    DEROctetString testInner = new DEROctetString(new byte[] { 0x10, 0x20, 0x30, 0x40 });
    DEROctetString testData = new DEROctetString(testInner.getEncoded());
    ContentInfo contentInfo = new ContentInfo(testOid, testData);

    // Sign using SignedDataUtil
    byte[] encryptedDigest = SignedDataUtil.signData(
        "SHA-256",
        "SHA256withRSA",
        "1.2.3.4.5.6",
        contentInfo,
        privateKey,
        Util.getBouncyCastleProvider().getName()
    );
    assertNotNull(encryptedDigest);

    // Create SignedData structure
    SignedData signedData = SignedDataUtil.createSignedData(
        "SHA-256",
        "SHA256withRSA",
        "1.2.3.4.5.6",
        contentInfo,
        encryptedDigest,
        docSigningCertificate
    );
    assertNotNull(signedData);

    // Write to byte output stream
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    SignedDataUtil.writeData(signedData, baos);
    byte[] serializedBytes = baos.toByteArray();
    assertTrue(serializedBytes.length > 0);

    // Read back via SignedDataUtil
    SignedData parsedSignedData = SignedDataUtil.readSignedData(new ByteArrayInputStream(serializedBytes));
    assertNotNull(parsedSignedData);

    // Verify parsed data attributes
    assertEquals("SHA-256", SignedDataUtil.getSignerInfoDigestAlgorithm(parsedSignedData));
    assertEquals("SHA256withRSA", SignedDataUtil.getDigestEncryptionAlgorithm(parsedSignedData));

    byte[] parsedEncryptedDigest = SignedDataUtil.getEncryptedDigest(parsedSignedData);
    assertNotNull(parsedEncryptedDigest);
    assertTrue(parsedEncryptedDigest.length > 0);

    List<X509Certificate> certificates = SignedDataUtil.getCertificates(parsedSignedData);
    assertNotNull(certificates);
    assertEquals(1, certificates.size());
    assertEquals(docSigningCertificate.getSerialNumber(), certificates.get(0).getSerialNumber());

    ASN1Primitive content = SignedDataUtil.getContent(parsedSignedData);
    assertNotNull(content);
    assertTrue(content instanceof DEROctetString);
    assertEquals(testInner, content);

    assertNotNull(SignedDataUtil.getIssuerAndSerialNumber(parsedSignedData));
  }
}
