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

package org.jmrtd.test;

import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jmrtd.AESSecureMessagingWrapper;
import org.jmrtd.ReverseAESSecureMessagingWrapper;
import org.jmrtd.SecureMessagingWrapper;

import junit.framework.TestCase;
import net.sf.scuba.smartcards.CommandAPDU;
import net.sf.scuba.smartcards.ResponseAPDU;
import net.sf.scuba.util.Hex;

/**
 * Tests for AES secure messaging wrapper (with the help of reverse wrapper).
 * 
 * @author The JMRTD team
 *
 * @version $Revision$
 */
public class AESSecureMessagingWrapperTest extends TestCase {
  
  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");
  
  /** For generating random keys. */
  private static final KeyGenerator KEY_GENERATOR; // NOTE: Instantiated during static initialization.
    
  /* STATIC INITIALIZATION */
  
  static {
    Security.addProvider(new BouncyCastleProvider());
    
    KeyGenerator keyGenerator = null;
    try {
      keyGenerator = KeyGenerator.getInstance("AES");
//      keyGenerator.init(192);
      keyGenerator.init(128);
    } catch (NoSuchAlgorithmException nsae) {
      keyGenerator = null;
      LOGGER.log(Level.SEVERE, "Could not instantiate key generator for AES", nsae);
    }
    KEY_GENERATOR = keyGenerator;
    
  }
  
  /* TESTS */
  
  public void testWrapResponseAPDU() {
    try {
      SecretKey ksEnc = new SecretKeySpec(Hex.hexStringToBytes("B18F124C36C97075C18E787984CF187D26A04A708AE15C07"), "AES");
      SecretKey ksMac = new SecretKeySpec(Hex.hexStringToBytes("F2C4B468739FB6D74F9BCA1B467DD2535B4D7C6D72D95DBF"), "AES");
      testWrapResponseAPDU(ksEnc, ksMac);
    } catch (Exception e) {
      e.printStackTrace();
      fail(e.getMessage());
    }    
  }
  
  public void testWrapResponseAPDURandomKeysMultipleTimes() {
    testWrapResponseAPDURandomKeysMultipleTimes(100);
  }
  
  public void testWrapResponseAPDURandomKeys() {
    try {
      testWrapResponseAPDU(KEY_GENERATOR.generateKey(), KEY_GENERATOR.generateKey());
    } catch (Exception e) {
      fail(e.getMessage());
    }
  }
  
  public void testUnwrapCommandAPDU() {
    try {
      SecretKey ksEnc = new SecretKeySpec(Hex.hexStringToBytes("22170DC35F4EFD0FF88E846ECA335932F2070A211F67C5DF"), "AES");
      SecretKey ksMac = new SecretKeySpec(Hex.hexStringToBytes("30FC32D59DF9FE5ADF9A2429AD79D1E866D08971A036E9FC"), "AES");
      
      testUnwrapCommandAPDU(ksEnc, ksMac);
    } catch (Exception e) {
      e.printStackTrace();
      fail(e.getMessage());
    }
  }
  
  public void testUnwrapCommandAPDURandomKeysMultipleTimes() {
    testUnwrapCommandAPDURandomKeysMultipleTimes(100);
  }
  
  public void testUnwrapCommandAPDURandomKeys() {
    try {
      testUnwrapCommandAPDU(KEY_GENERATOR.generateKey(), KEY_GENERATOR.generateKey());
    } catch (Exception e) {
      fail(e.getMessage());
    }
  }
  
  /* HELPER METHODS FOR TESTS */
  
  public void testWrapResponseAPDURandomKeysMultipleTimes(int count) {
    try {
      for (int i = 0; i < count; i++) {
        testWrapResponseAPDURandomKeys();
      }
    } catch (Exception e) {
      e.printStackTrace();
      fail(e.getMessage());
    }
  }
  
  public void testWrapResponseAPDU(SecretKey ksEnc, SecretKey ksMac) {
    byte[] data = { 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10,
        (byte)0xC1, (byte)0xC2, (byte)0xC3, (byte)0xFF, (byte)0xEE,
        (byte)0x90, 0x00 };
    testWrapResponseAPDU(ksEnc, ksMac, new ResponseAPDU(data));
  }
  
  public void testWrapResponseAPDU(SecretKey ksEnc, SecretKey ksMac, ResponseAPDU responseAPDU) {
    try {
      ReverseAESSecureMessagingWrapper reverseWrapper = new ReverseAESSecureMessagingWrapper(ksEnc, ksMac, 0);
      ResponseAPDU wrappedResponseAPDU = reverseWrapper.wrap(responseAPDU);
      assertNotNull(wrappedResponseAPDU);
      
      SecureMessagingWrapper wrapper = new AESSecureMessagingWrapper(ksEnc, ksMac, 0);
      ResponseAPDU unwrappedWrappedResponseAPDU = wrapper.unwrap(wrappedResponseAPDU);
      assertNotNull(unwrappedWrappedResponseAPDU);
      assertEquals(responseAPDU, unwrappedWrappedResponseAPDU);
    } catch (Exception e) {
      e.printStackTrace();
      fail(e.getMessage());
    }
  }
  
  public void testUnwrapCommandAPDURandomKeysMultipleTimes(int count) {
    try {
      for (int i = 0; i < count; i++) {
        testUnwrapCommandAPDURandomKeys();
      }
    } catch (Exception e) {
      e.printStackTrace();
      fail(e.getMessage());
    }
  }
  
  public void testUnwrapCommandAPDU(SecretKey ksEnc, SecretKey ksMac) {
    byte cla = 0x00;
    byte ins = (byte)0xA4;
    byte p1 = 0x0C;
    byte p2 = 0x02;
    int ne = 40;
    byte[] data = { 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10,
        (byte)0xC1, (byte)0xC2, (byte)0xC3, (byte)0xFF, (byte)0xEE };
    testUnwrapCommandAPDU(ksEnc, ksMac, new CommandAPDU(cla, ins, p1, p2, data, ne));
  }
  
  public void testUnwrapCommandAPDU(SecretKey ksEnc, SecretKey ksMac, CommandAPDU commandAPDU) {
    try {
      SecureMessagingWrapper wrapper = new AESSecureMessagingWrapper(ksEnc, ksMac, 0);
      
      CommandAPDU wrappedCommandAPDU = wrapper.wrap(commandAPDU);
      assertNotNull(wrappedCommandAPDU);
      
      ReverseAESSecureMessagingWrapper reverseWrapper = new ReverseAESSecureMessagingWrapper(ksEnc, ksMac, 0);
      CommandAPDU unwrappedWrappedCommandAPDU = reverseWrapper.unwrap(wrappedCommandAPDU);
      
      assertEquals(commandAPDU, unwrappedWrappedCommandAPDU);
    } catch (Exception e) {
      e.printStackTrace();
      fail(e.getMessage());
    }
  }
}
