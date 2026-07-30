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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.fail;

import java.io.ByteArrayOutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.jmrtd.PassportService;
import org.jmrtd.Util;
import org.jmrtd.protocol.DESedeSecureMessagingWrapper;
import org.jmrtd.protocol.SecureMessagingWrapper;
import org.junit.Test;

import net.sf.scuba.smartcards.CommandAPDU;
import net.sf.scuba.smartcards.ResponseAPDU;
import net.sf.scuba.util.Hex;

public class DESedeSecureMessagingWrapperTest {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  private static final Provider BC_PROVIDER = Util.getBouncyCastleProvider();

  @Test
  public void testDESedeSecureMessagingWrapper() {
    try {
      SecretKey encKey = getRandomDESedeKey();
      SecretKey macKey = getRandomDESedeKey();
      SecureMessagingWrapper wrapper = new DESedeSecureMessagingWrapper(encKey, macKey, PassportService.NORMAL_MAX_TRANCEIVE_LENGTH, true, 0L);

      assertEquals(encKey, wrapper.getEncryptionKey());
      assertEquals(macKey, wrapper.getMACKey());
    } catch (Exception e) {
      fail(e.getMessage());
    }
  }

  @Test
  public void testDESedeSecureMessagingWrapperEquals() {
    try {
      SecretKey encKey = getRandomDESedeKey();
      SecretKey macKey = getRandomDESedeKey();
      SecureMessagingWrapper wrapper = new DESedeSecureMessagingWrapper(encKey, macKey, PassportService.NORMAL_MAX_TRANCEIVE_LENGTH, true, 0L);
      SecureMessagingWrapper anotherWrapper = new DESedeSecureMessagingWrapper(encKey, macKey, PassportService.NORMAL_MAX_TRANCEIVE_LENGTH, true, 0L);
      assertEquals(wrapper.hashCode(), anotherWrapper.hashCode());
      assertEquals(wrapper, anotherWrapper);
      assertEquals(wrapper.toString(), anotherWrapper.toString());
    } catch (Exception e) {
      fail(e.getMessage());
    }
  }

  @Test
  public void testDESedeSecureMessagingWrapperWrapUnwrap() {
    try {
      SecretKey encKey = getRandomDESedeKey();
      SecretKey macKey = getRandomDESedeKey();
      SecureMessagingWrapper wrapper = new DESedeSecureMessagingWrapper(encKey, macKey, PassportService.NORMAL_MAX_TRANCEIVE_LENGTH, true, 0L);

      CommandAPDU commandAPDU = new CommandAPDU(0x00, 0xA4, 0x00, 0x00, new byte[] { 0x3F, 0x00 }, 0x00);
      CommandAPDU wrappedCommandAPDU = wrapper.wrap(commandAPDU);

      assertNotNull(wrappedCommandAPDU);
      assertEquals(0x0C, wrappedCommandAPDU.getCLA());
      assertEquals(commandAPDU.getINS(), wrappedCommandAPDU.getINS());
      assertEquals(commandAPDU.getP1(), wrappedCommandAPDU.getP1());
      assertEquals(commandAPDU.getP2(), wrappedCommandAPDU.getP2());
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Unexpected exception", e);
      fail(e.getMessage());
    }
  }

  /*
   * See https://stackoverflow.com/q/47307716/27190.
   */
  @Test
  public void testStackOverflowTim() {
    try {
      Security.addProvider(BC_PROVIDER);
      SecretKey encKey = new SecretKeySpec(Hex.hexStringToBytes("3DE649F8AEA41C04FB6D4CD9043757AD"), "DESede");

      SecretKey macKey = new SecretKeySpec(Hex.hexStringToBytes("8C34AD61974F68CEBA3E0EAEA1456476"), "DESede");
      SecureMessagingWrapper wrapper = new DESedeSecureMessagingWrapper(encKey, macKey, 0x00AB1D2F337FD997D6L);

      CommandAPDU protectedCommandAPDU = wrapper.wrap(new CommandAPDU(Hex.hexStringToBytes("00 A4 02 0C 02 01 1E")));
      assertEquals("0CA4020C15870901FF0E241E2F94B5088E0822FF803EC310433600", Hex.bytesToHexString(protectedCommandAPDU.getBytes()));

      CommandAPDU protectedReadBinaryCommandAPDU = wrapper.wrap(new CommandAPDU(Hex.hexStringToBytes("00 B0 00 00 04")));
      assertEquals("0CB000000D9701048E0868DD9FD88472834A00", Hex.bytesToHexString(protectedReadBinaryCommandAPDU.getBytes()));
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Unexpected exception", e);
      fail(e.getMessage());
    }
  }

  @Test
  public void testUnwrapValidProtectedResponse() throws Exception {
    SecretKey encKey = new SecretKeySpec(
        Hex.hexStringToBytes("00112233445566778899AABBCCDDEEFF0011223344556677"), "DESede");
    SecretKey macKey = new SecretKeySpec(
        Hex.hexStringToBytes("1032547698BADCFE0123456789ABCDEF1032547698BADCFE"), "DESede");
    DESedeSecureMessagingWrapper wrapper =
        new DESedeSecureMessagingWrapper(encKey, macKey, 256, true, 0L);
    ResponseAPDU protectedResponse =
        createProtectedResponse(encKey, macKey, 1L, new byte[] { 1, 2, 3 }, (short)0x9000);

    ResponseAPDU response = wrapper.unwrap(protectedResponse);

    assertArrayEquals(new byte[] { 1, 2, 3 }, response.getData());
    assertEquals(0x9000, response.getSW());
    assertEquals(1L, wrapper.getSendSequenceCounter());
  }

  @Test
  public void testUnwrapRejectsTamperedMac() throws Exception {
    SecretKey encKey = new SecretKeySpec(
        Hex.hexStringToBytes("00112233445566778899AABBCCDDEEFF0011223344556677"), "DESede");
    SecretKey macKey = new SecretKeySpec(
        Hex.hexStringToBytes("1032547698BADCFE0123456789ABCDEF1032547698BADCFE"), "DESede");
    final DESedeSecureMessagingWrapper wrapper =
        new DESedeSecureMessagingWrapper(encKey, macKey, 256, true, 0L);
    byte[] bytes = createProtectedResponse(
        encKey, macKey, 1L, new byte[] { 1, 2, 3 }, (short)0x9000).getBytes();
    bytes[bytes.length - 3] ^= 0x01;
    final ResponseAPDU tamperedResponse = new ResponseAPDU(bytes);

    assertThrows(IllegalStateException.class, () -> wrapper.unwrap(tamperedResponse));
  }

  private static ResponseAPDU createProtectedResponse(SecretKey encKey, SecretKey macKey,
      long ssc, byte[] data, short sw) throws Exception {
    Cipher cipher = Util.getCipher("DESede/CBC/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, encKey, DESedeSecureMessagingWrapper.ZERO_IV_PARAM_SPEC);
    byte[] encryptedData = cipher.doFinal(Util.pad(data, 8));

    ByteArrayOutputStream responseData = new ByteArrayOutputStream();
    responseData.write(0x87);
    responseData.write(encryptedData.length + 1);
    responseData.write(0x01);
    responseData.write(encryptedData);
    responseData.write(0x99);
    responseData.write(0x02);
    responseData.write((byte)(sw >> 8));
    responseData.write((byte)sw);
    byte[] dataObjects = responseData.toByteArray();

    ByteArrayOutputStream macInput = new ByteArrayOutputStream();
    for (int i = 7; i >= 0; i--) {
      macInput.write((byte)(ssc >> (8 * i)));
    }
    macInput.write(Util.pad(dataObjects, 8));
    Mac mac = Mac.getInstance("ISO9797Alg3Mac", BC_PROVIDER);
    mac.init(macKey);
    byte[] checksum = mac.doFinal(macInput.toByteArray());

    responseData.write(0x8E);
    responseData.write(0x08);
    responseData.write(checksum, 0, 8);
    responseData.write(0x90);
    responseData.write(0x00);
    return new ResponseAPDU(responseData.toByteArray());
  }

  private static SecretKey getRandomDESedeKey() throws NoSuchAlgorithmException {
    KeyGenerator keyFactory = KeyGenerator.getInstance("DESede");
    return keyFactory.generateKey();
  }
}
