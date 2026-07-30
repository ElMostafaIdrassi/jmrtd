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
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import org.jmrtd.io.PositionInputStream;
import org.junit.Test;

public class PositionInputStreamTest {

  @Test
  public void testBasicReadingAndPosition() throws IOException {
    byte[] data = { 0x10, 0x20, 0x30, 0x40, 0x50 };
    ByteArrayInputStream bais = new ByteArrayInputStream(data);
    PositionInputStream pis = new PositionInputStream(bais);

    assertEquals(0L, pis.getPosition());

    assertEquals(0x10, pis.read());
    assertEquals(1L, pis.getPosition());

    byte[] buf = new byte[2];
    int read = pis.read(buf);
    assertEquals(2, read);
    assertEquals(0x20, buf[0]);
    assertEquals(0x30, buf[1]);
    assertEquals(3L, pis.getPosition());

    long skipped = pis.skip(1);
    assertEquals(1L, skipped);
    assertEquals(4L, pis.getPosition());

    assertEquals(0x50, pis.read());
    assertEquals(5L, pis.getPosition());

    // EOF reads should not decrement the position!
    assertEquals(-1, pis.read());
    assertEquals(5L, pis.getPosition());

    read = pis.read(buf);
    assertEquals(-1, read);
    assertEquals(5L, pis.getPosition());

    read = pis.read(buf, 0, 1);
    assertEquals(-1, read);
    assertEquals(5L, pis.getPosition());
  }

  @Test
  public void testMarkAndReset() throws IOException {
    byte[] data = { 1, 2, 3, 4, 5 };
    ByteArrayInputStream bais = new ByteArrayInputStream(data);
    PositionInputStream pis = new PositionInputStream(bais);

    assertTrue(pis.markSupported());

    pis.read(); // pos 1
    pis.read(); // pos 2
    assertEquals(2L, pis.getPosition());

    pis.mark(10);
    pis.read(); // pos 3
    pis.read(); // pos 4
    assertEquals(4L, pis.getPosition());

    pis.reset();
    assertEquals(2L, pis.getPosition());
    assertEquals(3, pis.read());
    assertEquals(3L, pis.getPosition());
  }
}
