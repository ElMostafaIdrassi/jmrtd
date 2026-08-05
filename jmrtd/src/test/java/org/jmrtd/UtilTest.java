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

package org.jmrtd;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECPoint;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.junit.Test;

import net.sf.scuba.util.Hex;

/**
 * Tests some of the utility functions.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision$
 *
 * @since 0.6.2
 */
public class UtilTest {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  @Test
  public void testPadding() {
    testPadding(3, 64);
    testPadding(31, 64);
    testPadding(32, 64);
    testPadding(58, 64);
    testPadding(63, 64);
    testPadding(64, 64);
    testPadding(65, 64);
    testPadding(65, 128);
    testPadding(127, 128);
  }

  public void testPadding(int arraySize, int blockSize) {
    try {
      Random random = new Random();
      byte[] bytes = new byte[arraySize];
      random.nextBytes(bytes);

      byte[] paddedBytes = Util.pad(bytes, blockSize);
      assertNotNull(paddedBytes);
      assertTrue(paddedBytes.length >= bytes.length);
      assertTrue(isPrefixOf(bytes, paddedBytes));

      byte[] unpaddedPaddedBytes = Util.unpad(paddedBytes);
      assertTrue(Arrays.equals(bytes, unpaddedPaddedBytes));

    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Unexpected exception", e);
    }
  }

  @Test
  public void testApproximateSignatureSize() {
    Security.addProvider(Util.getBouncyCastleProvider());
    try {
      KeyPairGenerator keyPairGenerator;

      keyPairGenerator = KeyPairGenerator.getInstance("RSA");

      keyPairGenerator.initialize(512);
      testApproximateSignatureSize(512, "SHA256WithRSA", keyPairGenerator.generateKeyPair());

      keyPairGenerator.initialize(1024);
      testApproximateSignatureSize(1024, "SHA256WithRSA", keyPairGenerator.generateKeyPair());

      keyPairGenerator.initialize(2048);
      testApproximateSignatureSize(2048, "SHA256WithRSA", keyPairGenerator.generateKeyPair());

      keyPairGenerator = KeyPairGenerator.getInstance("EC", Util.getBouncyCastleProvider());

      keyPairGenerator.initialize(Util.getECParameterSpec("secp224r1"));
      testApproximateSignatureSize(448, "SHA256WithECDSA", keyPairGenerator.generateKeyPair());

      keyPairGenerator.initialize(Util.getECParameterSpec("secp256r1"));
      testApproximateSignatureSize(512, "SHA256WithECDSA", keyPairGenerator.generateKeyPair());

      keyPairGenerator.initialize(Util.getECParameterSpec("secp384r1"));
      testApproximateSignatureSize(768, "SHA256WithECDSA", keyPairGenerator.generateKeyPair());

      keyPairGenerator.initialize(Util.getECParameterSpec("brainpoolP224r1"));
      testApproximateSignatureSize(448, "SHA256WithECDSA", keyPairGenerator.generateKeyPair());

      keyPairGenerator.initialize(Util.getECParameterSpec("brainpoolP384r1"));
      testApproximateSignatureSize(768, "SHA256WithECDSA", keyPairGenerator.generateKeyPair());

      keyPairGenerator.initialize(Util.getECParameterSpec("brainpoolP512r1"));
      testApproximateSignatureSize(1024, "SHA256WithECDSA", keyPairGenerator.generateKeyPair());

    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public void testApproximateSignatureSize(int expectedSize, String sigAlg, KeyPair keyPair) throws GeneralSecurityException {
    assertEquals(expectedSize, Util.getApproximateSignatureSize(keyPair.getPublic()));
    assertEquals(expectedSize, Util.getApproximateSignatureSize(keyPair.getPrivate()));

    Random random = new SecureRandom();
    byte[] dataToBeSigned = new byte[8];
    random.nextBytes(dataToBeSigned);
    Signature sig = Signature.getInstance(sigAlg, Util.getBouncyCastleProvider());
    sig.initSign(keyPair.getPrivate());
    sig.update(new byte[8]);
    int sigSize = 8 * sig.sign().length;
    assertTrue(expectedSize <= sigSize && sigSize <= expectedSize + (expectedSize / 2));
  }

  @Test
  public void testPartition() {
    for (int dataSize = 23; dataSize < 987; dataSize++) {
      for (int segmentSize = 13; segmentSize < 63; segmentSize ++) {
        testPartition(dataSize, segmentSize);
      }
    }
  }

  public void testPartition(int dataSize, int segmentSize) {
    Random random = new Random();
    byte[] data = new byte[dataSize];
    random.nextBytes(data);
    List<byte[]> segments = Util.partition(segmentSize, data);

    /* This should be approximately true. */
    assertTrue(segmentSize * (segments.size() - 1) <= dataSize);
    assertTrue(segmentSize * segments.size() >= dataSize);

    List<Boolean> isLasts = new ArrayList<Boolean>(segments.size());
    int index = 0;
    for (byte[] segment: segments) {
      boolean isLast = ++index >= segments.size();
      isLasts.add(isLast);
    }
    for (int i = 0; i < segments.size() - 1; i++) {
      assertFalse(isLasts.get(i));
    }
    assertTrue(isLasts.get(segments.size() - 1));
  }

  @Test
  public void testStripLeadingZeroes() {
    byte[] example = { 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04 };
    byte[] stripped = Util.stripLeadingZeroes(example);
    assertTrue(stripped[0] != 0x00);
    assertTrue(Arrays.equals(new byte[] { 0x01, 0x02, 0x03, 0x04 }, stripped));
  }

  @Test
  public void testBigIntegerI2OSStripLeadingZeroes() {
    for (long i = 0; i < 66666; i++) {
      BigInteger bigInteger = BigInteger.valueOf(i);
      byte[] bigIBytes = bigInteger.toByteArray();
      byte[] os = Util.i2os(bigInteger);
      assertTrue(i  + ": " +  Hex.bytesToHexString(bigIBytes) + ", " + Hex.bytesToHexString(os), Arrays.equals(os, Util.stripLeadingZeroes(bigIBytes)));
    }
  }

  @Test
  public void testECPointSerDeser() {

    BigInteger x = new BigInteger("1711296670204813060243268632676822234344359677243986977215350947079259342020");
    BigInteger y = new BigInteger("136486234017883437884169815369656174240202926550835833245936368423753881551");
    ECPoint point = new ECPoint(x, y);

    byte[] bytes = Util.ecPoint2OS(point, 256);
    assertTrue(bytes.length == 65); // 1 byte prefix + twice the size of p (as described in BSI TR03111 3.2.1
    ECPoint deserializedPoint = Util.os2ECPoint(bytes);

    assertTrue(point.equals(deserializedPoint));
  }

  private static boolean isPrefixOf(byte[] bytes, byte[] paddedBytes) {
    if (bytes == null || paddedBytes == null) {
      throw new IllegalArgumentException();
    }

    if (bytes.length > paddedBytes.length) {
      return false;
    }

    for (int i = 0; i < bytes.length; i++) {
      if (paddedBytes[i] != bytes[i]) {
        return false;
      }
    }

    return true;
  }

  /**
   * https://sourceforge.net/p/jmrtd/bugs/57/
   */
  @Test
  public void testECPointLeadingZeroes() {
    BigInteger x = new BigInteger(Hex.hexStringToBytes("13426B4FE5577053F0374CF79ACFA6F7750B8E0D60DCA9FE627AB49A21D2C4C4"));
    BigInteger y = new BigInteger(Hex.hexStringToBytes("004D3F9BC97AFDF8ABD9B561E63C0239763976A9FEB1EFFD816A140D791217CF"));
    ECPoint point = new ECPoint(x, y);
    byte[] os = Util.ecPoint2OS(point, 256);

    ECPoint p = Util.os2ECPoint(os);

    byte[] os2 = Util.ecPoint2OS(p, 256);
    assertTrue(Arrays.equals(os, os2));
  }

  @Test
  public void testToOIDBytes() {
    byte[] oidBytes = Util.toOIDBytes("1.2.840.113549.1.1.1");
    assertNotNull(oidBytes);
    assertEquals((byte)0x80, oidBytes[0]);
    assertEquals(9, oidBytes[1]);

    // malformed OID should throw IllegalArgumentException
    try {
      Util.toOIDBytes("invalid-oid");
      fail("Should have thrown IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      // Expected
    }

    try {
      Util.toOIDBytes(null);
      fail("Should have thrown NullPointerException");
    } catch (NullPointerException e) {
      // Expected
    }
  }

  @Test
  public void testAlignKeyDataToSize() {
    byte[] original = new byte[] { 0x01, 0x02, 0x03 };

    // Case 1: original is smaller than target size (padding with leading zeros)
    byte[] padded = Util.alignKeyDataToSize(original, 5);
    assertTrue(Arrays.equals(new byte[] { 0x00, 0x00, 0x01, 0x02, 0x03 }, padded));

    // Case 2: original size matches target size
    byte[] matched = Util.alignKeyDataToSize(original, 3);
    assertTrue(Arrays.equals(new byte[] { 0x01, 0x02, 0x03 }, matched));

    // Case 3: original is larger than target size (trim leading bytes, keep last 'size' bytes)
    byte[] trimmed = Util.alignKeyDataToSize(original, 2);
    assertTrue(Arrays.equals(new byte[] { 0x02, 0x03 }, trimmed));
  }
}
