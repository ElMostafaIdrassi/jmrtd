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

package org.jmrtd.test;

import java.util.Arrays;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jmrtd.Util;

import junit.framework.TestCase;

/**
 * Tests some of the utility functions.
 * 
 * @author The JMRTD team (info@jmrtd.org)
 * 
 * @version $Revision$
 * 
 * @since 0.6.2
 */
public class UtilTest extends TestCase {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

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
}
