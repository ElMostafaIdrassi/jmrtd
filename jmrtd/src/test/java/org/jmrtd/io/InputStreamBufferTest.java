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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.jmrtd.io.InputStreamBuffer;
import org.jmrtd.io.InputStreamBuffer.SubInputStream;
import org.junit.Test;

/**
 * Tests the functionality of InputStreamBuffer and its SubInputStream.
 *
 * @author The JMRTD team (info@jmrtd.org)
 */
public class InputStreamBufferTest {

  @Test
  public void testBasicRead() throws IOException {
    byte[] data = { 10, 20, 30, 40, 50, 60, 70, 80, 90, 100 };
    InputStream bais = new ByteArrayInputStream(data);
    InputStreamBuffer isb = new InputStreamBuffer(bais, data.length);

    assertEquals(data.length, isb.getLength());
    assertEquals(0, isb.getPosition());
    assertEquals(0, isb.getBytesBuffered());

    SubInputStream sis = isb.getInputStream();
    assertNotNull(sis);
    assertTrue(sis.markSupported());
    assertEquals(0, sis.getPosition());
    assertEquals(0, sis.available());

    // Read first byte
    assertEquals(10, sis.read());
    assertEquals(1, sis.getPosition());
    assertEquals(1, isb.getBytesBuffered());
    assertEquals(0, sis.available()); // Available tells how many are buffered after the current position

    // Read next two bytes
    assertEquals(20, sis.read());
    assertEquals(30, sis.read());
    assertEquals(3, sis.getPosition());
    assertEquals(3, isb.getBytesBuffered());

    // Read using block
    byte[] buffer = new byte[3];
    int read = sis.read(buffer);
    assertEquals(3, read);
    assertEquals(40, buffer[0]);
    assertEquals(50, buffer[1]);
    assertEquals(60, buffer[2]);
    assertEquals(6, sis.getPosition());
    assertEquals(6, isb.getBytesBuffered());

    // Read remaining bytes
    assertEquals(70, sis.read());
    assertEquals(80, sis.read());
    assertEquals(90, sis.read());
    assertEquals(100, sis.read());
    assertEquals(10, sis.getPosition());
    assertEquals(10, isb.getBytesBuffered());

    // EOF
    assertEquals(-1, sis.read());
    assertEquals(10, sis.getPosition());
  }

  @Test
  public void testMultipleInterleavedSubstreams() throws IOException {
    byte[] data = new byte[100];
    for (int i = 0; i < data.length; i++) {
      data[i] = (byte) i;
    }

    InputStream bais = new ByteArrayInputStream(data);
    InputStreamBuffer isb = new InputStreamBuffer(bais, data.length);

    SubInputStream sis1 = isb.getInputStream();
    SubInputStream sis2 = isb.getInputStream();

    // Read 5 bytes from sis1
    for (int i = 0; i < 5; i++) {
      assertEquals(i, sis1.read());
    }
    assertEquals(5, sis1.getPosition());
    assertEquals(5, isb.getBytesBuffered());

    // Available for sis2 should be 0 because it's at position 0, but 5 bytes are buffered from pos 0 to 5
    assertEquals(5, sis2.available());

    // Read 10 bytes from sis2. It should serve 0-4 from the buffer and 5-9 from the carrier
    for (int i = 0; i < 10; i++) {
      assertEquals(i, sis2.read());
    }
    assertEquals(10, sis2.getPosition());
    assertEquals(10, isb.getBytesBuffered());

    // sis1 is at pos 5. Since sis2 read up to 10, sis1 should have 5 bytes available in the buffer
    assertEquals(5, sis1.available());

    // Read the remaining bytes from sis1 using block read
    byte[] buf = new byte[95];
    int read = sis1.read(buf);
    assertEquals(95, read);
    assertEquals(5, buf[0]);
    assertEquals(99, buf[94]);
    assertEquals(100, sis1.getPosition());
    assertEquals(100, isb.getBytesBuffered());

    // sis2 should now see remaining 90 bytes available in the buffer
    assertEquals(90, sis2.available());
    int read2 = sis2.read(buf, 0, 90);
    assertEquals(90, read2);
    assertEquals(10, buf[0]);
    assertEquals(99, buf[89]);
    assertEquals(100, sis2.getPosition());
  }

  @Test
  public void testSkipAndMarkReset() throws IOException {
    byte[] data = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    InputStream bais = new ByteArrayInputStream(data);
    InputStreamBuffer isb = new InputStreamBuffer(bais, data.length);

    SubInputStream sis = isb.getInputStream();

    assertEquals(0, sis.read());
    assertEquals(1, sis.read());

    // Mark at position 2
    sis.mark(10);

    assertEquals(2, sis.read());
    assertEquals(3, sis.read());
    assertEquals(4, sis.read());
    assertEquals(5, sis.getPosition());

    // Reset to position 2
    sis.reset();
    assertEquals(2, sis.getPosition());
    assertEquals(2, sis.read());

    // Skip forward
    long skipped = sis.skip(3); // Should skip 3, 4, 5 -> land at 6
    assertEquals(3L, skipped);
    assertEquals(6, sis.getPosition());
    assertEquals(6, sis.read());

    // Skip beyond end of stream
    long skippedBeyond = sis.skip(20);
    assertEquals(3L, skippedBeyond); // Only 3 bytes left (7, 8, 9)
    assertEquals(10, sis.getPosition());
    assertEquals(-1, sis.read());
  }

  @Test
  public void testUpdateFrom() throws IOException {
    byte[] data = { 1, 2, 3, 4, 5 };
    InputStreamBuffer isb1 = new InputStreamBuffer(new ByteArrayInputStream(data), data.length);
    InputStreamBuffer isb2 = new InputStreamBuffer(new ByteArrayInputStream(data), data.length);

    SubInputStream sis1 = isb1.getInputStream();
    assertEquals(1, sis1.read());
    assertEquals(2, sis1.read());
    assertEquals(2, isb1.getBytesBuffered());
    assertEquals(0, isb2.getBytesBuffered());

    // Update isb2 from isb1
    isb2.updateFrom(isb1);
    assertEquals(2, isb2.getBytesBuffered());

    SubInputStream sis2 = isb2.getInputStream();
    assertEquals(2, sis2.available());
    assertEquals(1, sis2.read());
    assertEquals(2, sis2.read());
  }

  @Test
  public void testReadWithOffsetsAndBounds() throws IOException {
    byte[] data = { 100, 101, 102, 103, 104 };
    InputStreamBuffer isb = new InputStreamBuffer(new ByteArrayInputStream(data), data.length);
    SubInputStream sis = isb.getInputStream();

    byte[] target = new byte[10];

    // Exception for null array
    try {
      sis.read(null, 0, 1);
      fail("Expected NullPointerException");
    } catch (NullPointerException e) {
      // expected
    }

    // Exception for index out of bounds
    try {
      sis.read(target, -1, 5);
      fail("Expected IndexOutOfBoundsException");
    } catch (IndexOutOfBoundsException e) {
      // expected
    }

    try {
      sis.read(target, 0, -1);
      fail("Expected IndexOutOfBoundsException");
    } catch (IndexOutOfBoundsException e) {
      // expected
    }

    try {
      sis.read(target, 8, 5);
      fail("Expected IndexOutOfBoundsException");
    } catch (IndexOutOfBoundsException e) {
      // expected
    }

    // Valid zero length read
    assertEquals(0, sis.read(target, 0, 0));

    // Valid block read into offset
    int read = sis.read(target, 2, 3);
    assertEquals(3, read);
    assertEquals(0, target[0]);
    assertEquals(0, target[1]);
    assertEquals(100, target[2]);
    assertEquals(101, target[3]);
    assertEquals(102, target[4]);
    assertEquals(0, target[5]);
  }

  @Test
  public void testResetWithoutMark() throws IOException {
    byte[] data = { 1, 2, 3 };
    InputStreamBuffer isb = new InputStreamBuffer(new ByteArrayInputStream(data), data.length);
    SubInputStream sis = isb.getInputStream();

    try {
      sis.reset();
      fail("Expected IOException when resetting without mark");
    } catch (IOException e) {
      // expected
    }
  }

  @Test
  public void testEmptyStream() throws IOException {
    byte[] data = {};
    InputStreamBuffer isb = new InputStreamBuffer(new ByteArrayInputStream(data), data.length);
    SubInputStream sis = isb.getInputStream();

    assertEquals(0, isb.getLength());
    assertEquals(-1, sis.read());

    byte[] target = new byte[5];
    assertEquals(-1, sis.read(target));
  }
}
