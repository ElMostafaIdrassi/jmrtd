/*
 * JMRTD - A Java API for accessing machine readable travel documents.
 *
 * Copyright (C) 2006 - 2016  The JMRTD team
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

package org.jmrtd.test.lds;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.ECParameterSpec;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.jmrtd.lds.CardSecurityFile;
import org.jmrtd.lds.ChipAuthenticationInfo;
import org.jmrtd.lds.SecurityInfo;
import org.jmrtd.lds.TerminalAuthenticationInfo;
import org.jmrtd.test.CertificateUtil;
import org.jmrtd.test.ResourceUtil;

import junit.framework.TestCase;
import net.sf.scuba.util.Hex;

/**
 * Tests for the CardSecurity file.
 * 
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision$
 *
 * @since 0.5.6
 */
public class CardSecurityFileTest extends TestCase {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  public void testParseSampleCardSecurityFileFromResource() {
    try {
      InputStream inputStream = createSampleInputStream();
      CardSecurityFile cardSecurityFile = new CardSecurityFile(inputStream);
      testAttributesSHA256withECDSASample(cardSecurityFile);

      /* Re-encode it, and test again. */
      byte[] encoded = cardSecurityFile.getEncoded();
      assertNotNull(encoded);
      CardSecurityFile cardSecurityFile2 = new CardSecurityFile(new ByteArrayInputStream(encoded));

      testSimilar(cardSecurityFile, cardSecurityFile2);

      testAttributesSHA256withECDSASample(cardSecurityFile2);      
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Unexpected exception", e);
      fail(e.getMessage());
    }
  }

  private void testSimilar(CardSecurityFile cardSecurityFile, CardSecurityFile cardSecurityFile2) {
    assertEquals(cardSecurityFile, cardSecurityFile2);
    assertEquals(cardSecurityFile.getDigestAlgorithm(), cardSecurityFile2.getDigestAlgorithm());    
    assertEquals(cardSecurityFile.getDigestEncryptionAlgorithm(), cardSecurityFile2.getDigestEncryptionAlgorithm());
  }

  public void testConstructedSample() {
    try {
      Security.insertProviderAt(new BouncyCastleProvider(), 0);

      CardSecurityFile cardSecurityFile = createConstructedSample();
      assertNotNull(cardSecurityFile);

      testAttributesSHA256withECDSASample(cardSecurityFile);

      /* Encode it. */
      byte[] encoded = cardSecurityFile.getEncoded();
      assertNotNull(encoded);
      LOGGER.info("DEBUG: file\n" + Hex.bytesToPrettyString(encoded));

      /* Decode it, test again. */
      CardSecurityFile cardSecurityFile2 = new CardSecurityFile(new ByteArrayInputStream(encoded));
      testAttributesSHA256withECDSASample(cardSecurityFile2);

      testSimilar(cardSecurityFile, cardSecurityFile2);

    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Unexpected exception", e);
      fail(e.getMessage());
    }
  }

  public void testAttributesSHA256withECDSASample(CardSecurityFile cardSecurityFile) {
    assertEquals("SHA-256", cardSecurityFile.getDigestAlgorithm());
    assertEquals("SHA256withECDSA", cardSecurityFile.getDigestEncryptionAlgorithm());

    Collection<SecurityInfo> securityInfos = cardSecurityFile.getSecurityInfos();

    assertNotNull(securityInfos);

    assertTrue(securityInfos.size() > 0);

    for (SecurityInfo securityInfo: securityInfos) {
      LOGGER.info("DEBUG: securityInfo = " + securityInfo);
    }
  }

  public CardSecurityFile createConstructedSample() {
    try {
      SecurityInfo caSecurityInfo = new ChipAuthenticationInfo(ChipAuthenticationInfo.ID_CA_ECDH_AES_CBC_CMAC_256, ChipAuthenticationInfo.VERSION_1);
      SecurityInfo taSecurityInfo = new TerminalAuthenticationInfo();

      Set<SecurityInfo> securityInfos = new HashSet<SecurityInfo>(2);
      securityInfos.add(caSecurityInfo);
      securityInfos.add(taSecurityInfo);

      /* Generate a document signer certificate and private signing key. */
      String digestAlgorithm = "SHA-256";
      String digestEncryptionAlgorithm = "SHA256withECDSA";

      ECNamedCurveParameterSpec bcParamSpec = ECNamedCurveTable.getParameterSpec("brainpoolp256r1");
      ECParameterSpec jceParamSpec = new ECNamedCurveSpec(bcParamSpec.getName(), bcParamSpec.getCurve(), bcParamSpec.getG(), bcParamSpec.getN(), bcParamSpec.getH(), bcParamSpec.getSeed());

      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
      keyPairGenerator.initialize(jceParamSpec);

      KeyPair cscaKeyPair = keyPairGenerator.generateKeyPair();
      KeyPair dsKeyPair = keyPairGenerator.generateKeyPair();

      Calendar calendar = Calendar.getInstance();

      Date dateOfIssuing = calendar.getTime();
      calendar.add(Calendar.MONTH, 2);
      Date dateOfDSExpiry = calendar.getTime();
      calendar.add(Calendar.YEAR, 5);
      Date dateOfCSCAExpiry = calendar.getTime();

      String issuer = "C=UT, O=Gov, CN=CSCA";
      String subject = "C=UT, O=Gov, CN=DS-01";

      X509Certificate cscaCert = CertificateUtil.createCertificate(issuer, issuer, dateOfIssuing, dateOfCSCAExpiry, cscaKeyPair.getPublic(), cscaKeyPair.getPrivate(), digestEncryptionAlgorithm);

      X509Certificate dsCert = CertificateUtil.createCertificate(issuer, subject, dateOfIssuing, dateOfDSExpiry, dsKeyPair.getPublic(), cscaKeyPair.getPrivate(), digestEncryptionAlgorithm);

      /* Create the card security file. */
      return new CardSecurityFile(digestAlgorithm, digestEncryptionAlgorithm, securityInfos, dsKeyPair.getPrivate(), dsCert, "BC");
    } catch (Exception e) {
      LOGGER.log(Level.SEVERE, "Exception during construction of sample", e);
      fail(e.getMessage());
      return null;
    }
  }

  public InputStream createSampleInputStream() {
    try {
      return ResourceUtil.getInputStream("/efcardsecurity/efcardsecurity.dump");
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Unexpected exception", e);
      fail(e.getMessage());
      return null;
    }
  }
}
