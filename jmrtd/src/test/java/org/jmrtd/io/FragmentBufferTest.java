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

import org.jmrtd.io.FragmentBuffer.Fragment;
import org.junit.Test;

public class FragmentBufferTest {

  @Test
  public void testBasicAddAndCoverage() {
    FragmentBuffer fb = new FragmentBuffer(50);
    assertEquals(50, fb.getLength());
    assertEquals(0, fb.getPosition());
    assertEquals(0, fb.getBytesBuffered());

    fb.addFragment(10, (byte) 0xAA);
    assertTrue(fb.isCoveredByFragment(10));
    assertFalse(fb.isCoveredByFragment(9));
    assertFalse(fb.isCoveredByFragment(11));
    assertEquals(11, fb.getPosition());
    assertEquals(1, fb.getBytesBuffered());
  }

  @Test
  public void testMultipleFragmentsAndMerging() {
    FragmentBuffer fb = new FragmentBuffer(100);
    byte[] data1 = { 1, 2, 3, 4, 5 };
    byte[] data2 = { 6, 7, 8, 9, 10 };

    fb.addFragment(10, data1);
    fb.addFragment(15, data2);

    // [10..14] and [15..19] are contiguous, so they should cover [10..19]
    assertTrue(fb.isCoveredByFragment(10, 10));
    assertEquals(20, fb.getPosition());
    assertEquals(10, fb.getBytesBuffered());
    assertEquals(10, fb.getBufferedLength(10));
  }

  @Test
  public void testOverlapScenarios() {
    FragmentBuffer fb = new FragmentBuffer(100);
    fb.addFragment(10, new byte[] { 1, 2, 3, 4, 5 }); // covers [10..14]

    // Add completely contained fragment
    fb.addFragment(11, new byte[] { 99 });
    assertEquals(5, fb.getBytesBuffered());

    // Add overlapping left fragment
    fb.addFragment(8, new byte[] { 10, 11, 12, 13 }); // covers [8..11]
    assertEquals(7, fb.getBytesBuffered()); // [8..14]
    assertTrue(fb.isCoveredByFragment(8, 7));
  }

  @Test
  public void testDynamicGrowth() {
    FragmentBuffer fb = new FragmentBuffer(10);
    byte[] data = new byte[20];
    fb.addFragment(5, data);

    assertTrue(fb.getLength() >= 25);
    assertTrue(fb.isCoveredByFragment(5, 20));
    assertEquals(25, fb.getPosition());
  }

  @Test
  public void testGetSmallestUnbufferedFragment() {
    FragmentBuffer fb = new FragmentBuffer(100);
    fb.addFragment(10, new byte[] { 1, 2, 3, 4, 5 }); // covers [10..14]

    // Asking for a completely unbuffered section
    Fragment unbuffered1 = fb.getSmallestUnbufferedFragment(20, 10);
    assertNotNull(unbuffered1);
    assertEquals(20, unbuffered1.getOffset());
    assertEquals(10, unbuffered1.getLength());

    // Asking for a section that overlaps a buffered section at the start
    Fragment unbuffered2 = fb.getSmallestUnbufferedFragment(10, 10); // requested [10..19], [10..14] is covered
    assertNotNull(unbuffered2);
    assertEquals(15, unbuffered2.getOffset());
    assertEquals(5, unbuffered2.getLength());
  }

  @Test
  public void testUpdateFrom() {
    FragmentBuffer fb1 = new FragmentBuffer(100);
    FragmentBuffer fb2 = new FragmentBuffer(100);

    fb1.addFragment(10, new byte[] { 1, 2, 3 });
    fb2.addFragment(20, new byte[] { 4, 5, 6 });

    fb1.updateFrom(fb2);

    assertTrue(fb1.isCoveredByFragment(10, 3));
    assertTrue(fb1.isCoveredByFragment(20, 3));
    assertEquals(6, fb1.getBytesBuffered());
  }
}
