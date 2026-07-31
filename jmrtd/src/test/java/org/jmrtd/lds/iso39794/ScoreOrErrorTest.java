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
 *
 * $Id$
 */

package org.jmrtd.lds.iso39794;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import org.jmrtd.lds.iso39794.ScoreOrError.ScoringErrorCode;
import org.junit.Test;

public class ScoreOrErrorTest {

  @Test
  public void testScore() {
    ScoreOrError scoreOrError = new ScoreOrError(99);

    assertTrue(scoreOrError.isScore());
    assertFalse(scoreOrError.isError());
    assertEquals(Integer.valueOf(99), scoreOrError.getScore());
    assertNull(scoreOrError.getErrorCode());
    assertEquals(scoreOrError, new ScoreOrError(scoreOrError.getASN1Object()));
  }

  @Test
  public void testFailureToAssessUsingBaseEncoding() {
    ScoreOrError scoreOrError = new ScoreOrError(ScoringErrorCode.FAILURE_TO_ASSESS);

    assertFalse(scoreOrError.isScore());
    assertTrue(scoreOrError.isError());
    assertNull(scoreOrError.getScore());
    assertEquals(ScoringErrorCode.FAILURE_TO_ASSESS, scoreOrError.getErrorCode());
    assertEquals(scoreOrError, new ScoreOrError(scoreOrError.getASN1Object()));
  }

  @Test
  public void testFailureToAssessUsingExtensionFallbackEncoding() throws Exception {
    ScoreOrError scoreOrError = new ScoreOrError(ScoringErrorCode.FAILURE_TO_ASSESS);

    assertEquals(scoreOrError, new ScoreOrError(scoreOrError.getASN1Object(true)));
    assertFalse(Arrays.equals(scoreOrError.getASN1Object().toASN1Primitive().getEncoded(),
        scoreOrError.getASN1Object(true).toASN1Primitive().getEncoded()));
  }

  @Test
  public void testLegacyQualityBlockErrorValue() {
    QualityBlock qualityBlock = new QualityBlock(new RegistryIdBlock(1, 1), -1);
    QualityBlock reconstructed = new QualityBlock(qualityBlock.getASN1Object());

    assertEquals(qualityBlock, reconstructed);
    assertEquals(-1, reconstructed.getScore());
    assertEquals(ScoringErrorCode.FAILURE_TO_ASSESS, reconstructed.getScoreOrError().getErrorCode());
  }

  @Test
  public void testLegacyPADScoreBlockErrorValue() {
    PADScoreBlock scoreBlock = new PADScoreBlock(new RegistryIdBlock(1, 1), -1);
    PADScoreBlock reconstructed = new PADScoreBlock(scoreBlock.getASN1Object());

    assertEquals(scoreBlock, reconstructed);
    assertEquals(-1, reconstructed.getScore());
    assertEquals(ScoringErrorCode.FAILURE_TO_ASSESS, reconstructed.getScoreOrError().getErrorCode());
  }

  @Test
  public void testFingerSegmentFailureToAssessIsNotAbsent() {
    FingerImageSegmentBlock segmentBlock = new FingerImageSegmentBlock(
        FingerImagePositionCode.RIGHT_INDEX_FINGER,
        Arrays.asList(new CoordinateCartesian2DUnsignedShortBlock(0, 0),
            new CoordinateCartesian2DUnsignedShortBlock(1, 1)),
        null, null, new ScoreOrError(ScoringErrorCode.FAILURE_TO_ASSESS));
    FingerImageSegmentBlock reconstructed = new FingerImageSegmentBlock(segmentBlock.getASN1Object());

    assertEquals(segmentBlock, reconstructed);
    assertTrue(reconstructed.getConfidenceScoreOrError().isError());
    assertEquals(ScoringErrorCode.FAILURE_TO_ASSESS,
        reconstructed.getConfidenceScoreOrError().getErrorCode());
  }
}
