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

package org.jmrtd.test.lds;

import java.util.Arrays;
import java.util.List;

import org.jmrtd.lds.LDSFileUtil;
import org.jmrtd.lds.SODFile;
import org.jmrtd.lds.icao.COMFile;

import junit.framework.TestCase;

/**
 * Tests some of the functionality provided by the {@code LDSFileUtil} class.
 * 
 * @author The JMRTD team (info@jmrtd.org)
 * 
 * @version $Revision$
 */
public class LDSFileUtilTest extends TestCase {

  public void testCompatibility() {
    for (int dgNumber = 1; dgNumber <= 16; dgNumber++) {
      testCompatibilityDataGroups(dgNumber);
    }
  }

  public void testCompatibilityDataGroups(int dgNumber) {
    int tag = LDSFileUtil.lookupTagByDataGroupNumber(dgNumber);
    int otherDGNumber = LDSFileUtil.lookupDataGroupNumberByTag(tag);
    assertEquals(dgNumber, otherDGNumber);

    int otherTag = LDSFileUtil.lookupTagByDataGroupNumber(dgNumber);
    assertEquals(tag, otherTag);

    short fidByDGNumber = LDSFileUtil.lookupFIDByDataGroupNumber(dgNumber);
    short fidByTag = LDSFileUtil.lookupFIDByTag(tag);
    assertEquals(fidByDGNumber, fidByTag);

    int tagByFID = LDSFileUtil.lookupTagByFID(fidByDGNumber);
    assertEquals(tag, tagByFID);

    int dgNumberByFID = LDSFileUtil.lookupDataGroupNumberByFID(fidByDGNumber);
    assertEquals(dgNumber, dgNumberByFID);

    int sfi = LDSFileUtil.lookupSFIByFID(fidByDGNumber);
    int fidBySFI = LDSFileUtil.lookupFIDBySFI((byte)sfi);
    assertEquals(fidByDGNumber, fidBySFI);
  }

  public void testDGNumbers() {
    COMFile comFile = COMFileTest.createTestObject();
    List<Integer> dgNumbersFromCOM = LDSFileUtil.getDataGroupNumbers(comFile);
    assertEquals(Arrays.asList(new Integer[] { 1, 2, 15 }), dgNumbersFromCOM);
    
    SODFile sodFile = SODFileTest.createTestObject("SHA-256", "SHA256WithRSA");
    List<Integer> dgNumbersFromSOd = LDSFileUtil.getDataGroupNumbers(sodFile);
    assertEquals(Arrays.asList(new Integer[] { 1, 2 }), dgNumbersFromSOd);
  }
}
