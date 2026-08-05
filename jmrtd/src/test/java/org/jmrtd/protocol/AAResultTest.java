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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jmrtd.Util;
import org.junit.Test;

public class AAResultTest {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  private static final Provider BC_PROVIDER = Util.getBouncyCastleProvider();

  @Test
  public void testAAResult() {
    try {
      String digAlg = "SHA-256";
      String sigAlg = "SHA256WithECDSA";

      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", BC_PROVIDER);
      keyPairGenerator.initialize(256);

      KeyPair aaKeyPair = keyPairGenerator.generateKeyPair();
      PublicKey publicKey = aaKeyPair.getPublic();
      PrivateKey privateKey = aaKeyPair.getPrivate();

      Signature signature = Signature.getInstance(sigAlg, BC_PROVIDER);
      signature.initSign(privateKey);
      byte[] challenge = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
      signature.update(challenge);
      byte[] response = signature.sign();
      assertNotNull(response);

      AAResult aaResult = new AAResult(publicKey, digAlg, sigAlg, challenge, response);
      assertEquals(digAlg, aaResult.getDigestAlgorithm());
      assertEquals(sigAlg, aaResult.getSignatureAlgorithm());
      assertEquals(publicKey, aaResult.getPublicKey());
      assertTrue(Arrays.equals(challenge, aaResult.getChallenge()));
      assertTrue(Arrays.equals(response, aaResult.getResponse()));

      AAResult anotherAAResult = new AAResult(publicKey, digAlg, sigAlg, Arrays.copyOf(challenge, challenge.length), Arrays.copyOf(response, response.length));
      assertEquals(aaResult.hashCode(), anotherAAResult.hashCode());
      assertEquals(aaResult, anotherAAResult);
      assertEquals(aaResult.toString(), anotherAAResult.toString());

      int originalHashCode = aaResult.hashCode();
      challenge[0] ^= 0x7F;
      response[0] ^= 0x7F;
      assertArrayEquals(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 },
          aaResult.getChallenge());
      byte[] returnedChallenge = aaResult.getChallenge();
      byte[] returnedResponse = aaResult.getResponse();
      returnedChallenge[0] ^= 0x7F;
      returnedResponse[0] ^= 0x7F;
      assertEquals(originalHashCode, aaResult.hashCode());
      assertEquals(anotherAAResult, aaResult);
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Unexpected exception", e);
      fail(e.getMessage());
    }
  }
}
