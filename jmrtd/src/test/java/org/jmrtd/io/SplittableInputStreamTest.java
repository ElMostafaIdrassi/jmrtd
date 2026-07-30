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

package org.jmrtd.io;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.jmrtd.io.SplittableInputStream;
import org.junit.Test;

public class SplittableInputStreamTest {

  @Test
  public void testBasicSplitReading() throws IOException {
    byte[] data = new byte[20];
    for (int i = 0; i < data.length; i++) {
      data[i] = (byte) i;
    }

    ByteArrayInputStream bais = new ByteArrayInputStream(data);
    SplittableInputStream sis = new SplittableInputStream(bais, data.length);

    assertEquals(0, sis.getPosition());

    // Read 5 bytes
    for (int i = 0; i < 5; i++) {
      assertEquals(i, sis.read());
    }
    assertEquals(5, sis.getPosition());

    // Split off a copy stream at position 2
    InputStream copyStream = sis.getInputStream(2);
    assertNotNull(copyStream);

    // Copy stream should yield bytes from index 2 onwards
    assertEquals(2, copyStream.read());
    assertEquals(3, copyStream.read());
    assertEquals(4, copyStream.read());

    // Main stream should continue from index 5
    assertEquals(5, sis.read());
    assertEquals(6, sis.getPosition());

    // Copy stream again at position 0
    InputStream copyStreamFromStart = sis.getInputStream(0);
    assertEquals(0, copyStreamFromStart.read());
    assertEquals(1, copyStreamFromStart.read());
  }

  @Test
  public void testSkipAndAvailable() throws IOException {
    byte[] data = { 10, 20, 30, 40, 50 };
    ByteArrayInputStream bais = new ByteArrayInputStream(data);
    SplittableInputStream sis = new SplittableInputStream(bais, data.length);

    assertTrue(sis.available() >= 0);

    long skipped = sis.skip(2);
    assertEquals(2L, skipped);
    assertEquals(2, sis.getPosition());
    assertEquals(30, sis.read());
  }
}
