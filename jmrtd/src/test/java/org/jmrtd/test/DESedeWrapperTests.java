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
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jmrtd.DESedeSecureMessagingWrapper;
import org.jmrtd.ReverseDESedeWrapper;
import org.jmrtd.SecureMessagingWrapper;

import junit.framework.TestCase;
import net.sf.scuba.smartcards.CommandAPDU;
import net.sf.scuba.smartcards.ResponseAPDU;
import net.sf.scuba.util.Hex;

/**
 * Tests for DESede wrapper (with the help of reverse wrapper).
 * 
 * @author The JMRTD team
 *
 * @version $Revision$
 */
public class DESedeWrapperTests extends TestCase {
  
  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");
  
  /** For generating random keys. */
  private static final KeyGenerator KEY_GENERATOR; // NOTE: Instantiated during static initialization.
  
  /** For constructing keys from key specifications. */
  private static final SecretKeyFactory KEY_FACTORY; // NOTE: Instantiated during static initialization.

  /* STATIC INITIALIZATION */
  
  static {
    Security.addProvider(new BouncyCastleProvider());
    
    KeyGenerator keyGenerator = null;
    try {
      keyGenerator = KeyGenerator.getInstance("DESede");
    } catch (NoSuchAlgorithmException nsae) {
      keyGenerator = null;
      LOGGER.log(Level.SEVERE, "Could not instantiate key generator for DESede", nsae);
    }
    KEY_GENERATOR = keyGenerator;
    
    SecretKeyFactory keyFactory = null;
    try {
      keyFactory = SecretKeyFactory.getInstance("DESede");
    } catch (NoSuchAlgorithmException nsae) {
      LOGGER.log(Level.SEVERE, "Could not instantiate key generator for DESede", nsae);
    }
    KEY_FACTORY = keyFactory;
  }
  
  /* TESTS */
  
  public void testWrapResponseAPDU() {
    try {
      SecretKey ksEnc = KEY_FACTORY.generateSecret(new DESedeKeySpec(Hex.hexStringToBytes("F84CCE37CDC829767568E62385293BECD9897C31B940235D")));
      SecretKey ksMac = KEY_FACTORY.generateSecret(new DESedeKeySpec(Hex.hexStringToBytes("7F2C26FD16C48086AD7373860E64DC8075FE79A18368CB20")));
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
      SecretKey ksEnc = KEY_FACTORY.generateSecret(new DESedeKeySpec(Hex.hexStringToBytes("F84CCE37CDC829767568E62385293BECD9897C31B940235D")));
      SecretKey ksMac = KEY_FACTORY.generateSecret(new DESedeKeySpec(Hex.hexStringToBytes("7F2C26FD16C48086AD7373860E64DC8075FE79A18368CB20")));
      
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
      ReverseDESedeWrapper reverseWrapper = new ReverseDESedeWrapper(ksEnc, ksMac);
      ResponseAPDU wrappedResponseAPDU = reverseWrapper.wrap(responseAPDU);
      assertNotNull(wrappedResponseAPDU);

      SecureMessagingWrapper wrapper = new DESedeSecureMessagingWrapper(ksEnc, ksMac);
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
      SecureMessagingWrapper wrapper = new DESedeSecureMessagingWrapper(ksEnc, ksMac);
      
      CommandAPDU wrappedCommandAPDU = wrapper.wrap(commandAPDU);
      assertNotNull(wrappedCommandAPDU);
      
      ReverseDESedeWrapper reverseWrapper = new ReverseDESedeWrapper(ksEnc, ksMac);
      CommandAPDU unwrappedWrappedCommandAPDU = reverseWrapper.unwrap(wrappedCommandAPDU);
      
      assertEquals(commandAPDU, unwrappedWrappedCommandAPDU);
    } catch (Exception e) {
      e.printStackTrace();
      fail(e.getMessage());
    }
  }
}
