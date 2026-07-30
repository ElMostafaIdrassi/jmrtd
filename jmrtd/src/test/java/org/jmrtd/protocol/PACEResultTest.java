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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.jmrtd.AccessKeySpec;
import org.jmrtd.PACEKeySpec;
import org.jmrtd.PassportService;
import org.jmrtd.Util;
import org.jmrtd.lds.PACEInfo;
import org.jmrtd.lds.PACEInfo.MappingType;
import org.jmrtd.protocol.AESSecureMessagingWrapper;
import org.jmrtd.protocol.PACEMappingResult;
import org.jmrtd.protocol.PACEResult;
import org.jmrtd.protocol.SecureMessagingWrapper;
import org.junit.Test;

public class PACEResultTest {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  private static final Provider BC_PROVIDER = Util.getBouncyCastleProvider();

  @Test
  public void testPACEResult() {
    try {
      String oid = PACEInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_256;

      AccessKeySpec paceKey = PACEKeySpec.createCANKey("12345");

      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDH", BC_PROVIDER);
      keyPairGenerator.initialize(256);
      KeyPair piccKeyPair = keyPairGenerator.generateKeyPair();
      PublicKey piccPublicKey = piccKeyPair.getPublic();

      KeyPair pcdKeyPair = keyPairGenerator.generateKeyPair();

      SecureMessagingWrapper wrapper = new AESSecureMessagingWrapper(getRandomAESKey(), getRandomAESKey(), PassportService.NORMAL_MAX_TRANCEIVE_LENGTH, true, 0L);

      MappingType mappingType = PACEInfo.toMappingType(oid);
      String agreementType = PACEInfo.toKeyAgreementAlgorithm(oid);
      String cipherAlg = PACEInfo.toCipherAlgorithm(oid);
      String digestAlg = PACEInfo.toDigestAlgorithm(oid);
      int keyLength = PACEInfo.toKeyLength(oid);

      PACEMappingResult mappingResult = null;

      PACEResult paceResult = new PACEResult(paceKey, mappingType, agreementType, cipherAlg, digestAlg, keyLength, mappingResult, pcdKeyPair, piccPublicKey, wrapper);

      assertEquals(paceKey, paceResult.getPACEKey());
      assertEquals(mappingType, paceResult.getMappingType());
      assertEquals(agreementType, paceResult.getAgreementAlg());
      assertEquals(cipherAlg, paceResult.getCipherAlg());
      assertEquals(digestAlg, paceResult.getDigestAlg());
      assertEquals(keyLength, paceResult.getKeyLength());
      assertEquals(mappingResult, paceResult.getMappingResult());
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Unexpected exception", e);
      fail(e.getMessage());
    }
  }

  @Test
  public void testPACEResultEquals() {
      try {
        String oid = PACEInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_256;

        AccessKeySpec paceKey = PACEKeySpec.createCANKey("12345");

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDH", BC_PROVIDER);
        keyPairGenerator.initialize(256);
        KeyPair piccKeyPair = keyPairGenerator.generateKeyPair();
        PublicKey piccPublicKey = piccKeyPair.getPublic();

        KeyPair pcdKeyPair = keyPairGenerator.generateKeyPair();

        SecureMessagingWrapper wrapper = new AESSecureMessagingWrapper(getRandomAESKey(), getRandomAESKey(), PassportService.NORMAL_MAX_TRANCEIVE_LENGTH, true, 0L);

        MappingType mappingType = PACEInfo.toMappingType(oid);
        String agreementType = PACEInfo.toKeyAgreementAlgorithm(oid);
        String cipherAlg = PACEInfo.toCipherAlgorithm(oid);
        String digestAlg = PACEInfo.toDigestAlgorithm(oid);
        int keyLength = PACEInfo.toKeyLength(oid);

        PACEMappingResult mappingResult = null;

        PACEResult paceResult = new PACEResult(paceKey, mappingType, agreementType, cipherAlg, digestAlg, keyLength, mappingResult, pcdKeyPair, piccPublicKey, wrapper);
        PACEResult anotherPACEResult = new PACEResult(paceKey, mappingType, agreementType, cipherAlg, digestAlg, keyLength, mappingResult, pcdKeyPair, piccPublicKey, wrapper);

        assertEquals(paceResult.hashCode(), anotherPACEResult.hashCode());
        assertEquals(paceResult, anotherPACEResult);
        assertEquals(paceResult.toString(), anotherPACEResult.toString());
      } catch (Exception e) {
        LOGGER.log(Level.WARNING, "Unexpected exception", e);
        fail(e.getMessage());
      }
  }

  @Test
  public void testMappingResultDefensivelyCopiesPICCNonce() {
    byte[] piccNonce = new byte[] { 1, 2, 3, 4 };
    byte[] expectedPICCNonce = piccNonce.clone();
    PACEMappingResult mappingResult = new PACEMappingResult(null, piccNonce, null) {
      private static final long serialVersionUID = 1L;
    };

    piccNonce[0] ^= 0x7F;
    assertArrayEquals(expectedPICCNonce, mappingResult.getPICCNonce());

    byte[] returnedPICCNonce = mappingResult.getPICCNonce();
    returnedPICCNonce[0] ^= 0x7F;
    assertArrayEquals(expectedPICCNonce, mappingResult.getPICCNonce());
  }

  private static SecretKey getRandomAESKey() throws NoSuchAlgorithmException {
    KeyGenerator keyFactory = KeyGenerator.getInstance("AES");
    return keyFactory.generateKey();
  }
}
