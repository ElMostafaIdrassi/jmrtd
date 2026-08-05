/*
 * JMRTD - A Java API for accessing machine readable travel documents.
 *
 * Copyright (C) 2006 - 2018  The JMRTD team
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

package org.jmrtd.protocol;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.util.Collections;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.jmrtd.PassportService;
import org.jmrtd.Util;
import org.jmrtd.cert.CVCPrincipal;
import org.jmrtd.cert.CardVerifiableCertificate;
import org.junit.Test;

/**
 * Tests for TAResult class.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision$
 *
 * @since 0.6.2
 */
public class TAResultTest {

  private static final Provider BC_PROVIDER = Util.getBouncyCastleProvider();

  @Test
  public void testTAResult() {
    try {
      BigInteger keyId = BigInteger.valueOf(-1L);

      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDH", BC_PROVIDER);
      keyPairGenerator.initialize(256);
      KeyPair piccKeyPair = keyPairGenerator.generateKeyPair();
      PublicKey piccPublicKey = piccKeyPair.getPublic();

      KeyPair pcdKeyPair = keyPairGenerator.generateKeyPair();
      PublicKey pcdPublicKey = pcdKeyPair.getPublic();
      PrivateKey pcdPrivateKey = pcdKeyPair.getPrivate();

      SecureMessagingWrapper wrapper = new AESSecureMessagingWrapper(getRandomAESKey(), getRandomAESKey(), PassportService.NORMAL_MAX_TRANCEIVE_LENGTH, true, 0L);

      EACCAResult caResult = new EACCAResult(keyId, piccPublicKey, EACCAProtocol.getKeyHash("ECDH", pcdPublicKey), pcdPublicKey, pcdPrivateKey, wrapper);

      CVCPrincipal cvcPrincipal = new CVCPrincipal("CAReference00001");
      List<CardVerifiableCertificate> terminalCertificates = Collections.emptyList();
      PrivateKey terminalKey = null;
      String documentNumber = "123456789";
      byte[] cardChallenge = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
      byte[] expectedCardChallenge = cardChallenge.clone();
      EACTAResult taResult = new EACTAResult(caResult, cvcPrincipal, terminalCertificates, terminalKey, documentNumber, cardChallenge);

      assertEquals(caResult, taResult.getChipAuthenticationResult());
      assertEquals(cvcPrincipal, taResult.getCAReference());
      assertEquals(terminalCertificates, taResult.getCVCertificates());
      assertEquals(terminalKey, taResult.getTerminalKey());
      assertEquals(documentNumber, taResult.getDocumentNumber());
      assertArrayEquals(expectedCardChallenge, taResult.getCardChallenge());

      cardChallenge[0] ^= 0x7F;
      assertArrayEquals(expectedCardChallenge, taResult.getCardChallenge());
      byte[] returnedCardChallenge = taResult.getCardChallenge();
      returnedCardChallenge[0] ^= 0x7F;
      assertArrayEquals(expectedCardChallenge, taResult.getCardChallenge());
    } catch (Exception e) {
      fail(e.getMessage());
    }
  }

  @Test
  public void testTAResultEquals() {
    try {
      BigInteger keyId = BigInteger.valueOf(-1L);

      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDH", BC_PROVIDER);
      keyPairGenerator.initialize(256);
      KeyPair piccKeyPair = keyPairGenerator.generateKeyPair();
      PublicKey piccPublicKey = piccKeyPair.getPublic();

      KeyPair pcdKeyPair = keyPairGenerator.generateKeyPair();
      PublicKey pcdPublicKey = pcdKeyPair.getPublic();
      PrivateKey pcdPrivateKey = pcdKeyPair.getPrivate();

      SecretKey encKey = getRandomAESKey();
      SecretKey macKey = getRandomAESKey();
      SecureMessagingWrapper wrapper = new AESSecureMessagingWrapper(encKey, macKey, PassportService.NORMAL_MAX_TRANCEIVE_LENGTH, true, 0L);
      SecureMessagingWrapper anotherWrapper = new AESSecureMessagingWrapper(encKey, macKey, PassportService.NORMAL_MAX_TRANCEIVE_LENGTH, true, 0L);

      EACCAResult caResult = new EACCAResult(keyId, piccPublicKey, EACCAProtocol.getKeyHash("ECDH", pcdPublicKey), pcdPublicKey, pcdPrivateKey, wrapper);
      EACCAResult anotherCAResult = new EACCAResult(keyId, piccPublicKey, EACCAProtocol.getKeyHash("ECDH", pcdPublicKey), pcdPublicKey, pcdPrivateKey, anotherWrapper);

      CVCPrincipal cvcPrincipal = new CVCPrincipal("CAReference00001");
      List<CardVerifiableCertificate> terminalCertificates = Collections.emptyList();
      PrivateKey terminalKey = null;
      String documentNumber = "123456789";
      byte[] cardChallenge = null;
      EACTAResult taResult = new EACTAResult(caResult, cvcPrincipal, terminalCertificates, terminalKey, documentNumber, cardChallenge);
      EACTAResult anotherTAResult = new EACTAResult(anotherCAResult, cvcPrincipal, terminalCertificates, terminalKey, documentNumber, cardChallenge);

      assertEquals(taResult.hashCode(), anotherTAResult.hashCode());
      assertEquals(taResult, anotherTAResult);
      assertEquals(taResult.toString(), anotherTAResult.toString());
    } catch (Exception e) {
      fail(e.getMessage());
    }
  }

  private static SecretKey getRandomAESKey() throws NoSuchAlgorithmException {
    KeyGenerator keyFactory = KeyGenerator.getInstance("AES");
    return keyFactory.generateKey();
  }
}
