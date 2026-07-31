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
 *
 * Based on ISO-IEC-39794-1-ed-1-v1.
 */

package org.jmrtd.lds.iso39794;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import org.bouncycastle.asn1.ASN1Encodable;
import org.jmrtd.ASN1Util;

/**
 * A biometric sample quality score or an error indicating that no score could be determined.
 */
public final class ScoreOrError extends Block {

  private static final long serialVersionUID = 3747186221873548390L;

  /** The errors defined by ISO/IEC 39794-1. */
  public enum ScoringErrorCode implements EncodableEnum<ScoringErrorCode> {
    FAILURE_TO_ASSESS(0);

    private final int code;

    ScoringErrorCode(int code) {
      this.code = code;
    }

    @Override
    public int getCode() {
      return code;
    }

    static ScoringErrorCode fromCode(int code) {
      return EncodableEnum.fromCode(code, ScoringErrorCode.class);
    }
  }

  private final Integer score;
  private final ScoringErrorCode errorCode;

  /**
   * Constructs a score.
   *
   * @param score a value in the inclusive range 0 through 100
   */
  public ScoreOrError(int score) {
    if (score < 0 || score > 100) {
      throw new IllegalArgumentException("Score must be in range 0 through 100");
    }
    this.score = score;
    this.errorCode = null;
  }

  /**
   * Constructs a scoring error.
   *
   * @param errorCode the scoring error
   */
  public ScoreOrError(ScoringErrorCode errorCode) {
    if (errorCode == null) {
      throw new IllegalArgumentException("Null scoring error code");
    }
    this.score = null;
    this.errorCode = errorCode;
  }

  ScoreOrError(ASN1Encodable asn1Encodable) {
    Map<Integer, ASN1Encodable> taggedObjects = ASN1Util.decodeTaggedObjects(asn1Encodable);
    if (taggedObjects.containsKey(0)) {
      int decodedScore = ASN1Util.decodeInt(taggedObjects.get(0));
      if (decodedScore < 0 || decodedScore > 100) {
        throw new IllegalArgumentException("Score must be in range 0 through 100");
      }
      score = decodedScore;
      errorCode = null;
      return;
    }

    if (taggedObjects.containsKey(1)) {
      score = null;
      errorCode = decodeScoringError(taggedObjects.get(1));
      return;
    }

    throw new IllegalArgumentException("Expected score or scoring error");
  }

  public boolean isScore() {
    return score != null;
  }

  public boolean isError() {
    return errorCode != null;
  }

  public Integer getScore() {
    return score;
  }

  public ScoringErrorCode getErrorCode() {
    return errorCode;
  }

  @Override
  public int hashCode() {
    return Objects.hash(errorCode, score);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null || getClass() != obj.getClass()) {
      return false;
    }
    ScoreOrError other = (ScoreOrError)obj;
    return errorCode == other.errorCode && Objects.equals(score, other.score);
  }

  @Override
  public String toString() {
    return score != null ? "ScoreOrError [score: " + score + "]" : "ScoreOrError [error: " + errorCode + "]";
  }

  @Override
  ASN1Encodable getASN1Object() {
    return getASN1Object(false);
  }

  /**
   * Encodes this value, optionally using an extension block with a fallback error code.
   * The latter form is required by some application profiles.
   */
  ASN1Encodable getASN1Object(boolean useErrorExtensionBlock) {
    Map<Integer, ASN1Encodable> taggedObjects = new HashMap<Integer, ASN1Encodable>();
    if (score != null) {
      taggedObjects.put(0, ASN1Util.encodeInt(score));
    } else {
      taggedObjects.put(1, encodeScoringError(useErrorExtensionBlock));
    }
    return ASN1Util.encodeTaggedObjects(taggedObjects);
  }

  private static ScoringErrorCode decodeScoringError(ASN1Encodable asn1Encodable) {
    Map<Integer, ASN1Encodable> taggedObjects = ASN1Util.decodeTaggedObjects(asn1Encodable);
    int code;
    if (taggedObjects.containsKey(0)) {
      code = ASN1Util.decodeInt(taggedObjects.get(0));
    } else if (taggedObjects.containsKey(1)) {
      Map<Integer, ASN1Encodable> extensionBlock = ASN1Util.decodeTaggedObjects(taggedObjects.get(1));
      code = ASN1Util.decodeInt(extensionBlock.get(0));
    } else {
      throw new IllegalArgumentException("Expected scoring error code or extension block");
    }

    ScoringErrorCode result = ScoringErrorCode.fromCode(code);
    if (result == null) {
      throw new IllegalArgumentException("Unknown scoring error code " + code);
    }
    return result;
  }

  private ASN1Encodable encodeScoringError(boolean useErrorExtensionBlock) {
    Map<Integer, ASN1Encodable> scoringError = new HashMap<Integer, ASN1Encodable>();
    if (useErrorExtensionBlock) {
      Map<Integer, ASN1Encodable> extensionBlock = new HashMap<Integer, ASN1Encodable>();
      extensionBlock.put(0, ASN1Util.encodeInt(errorCode.getCode()));
      scoringError.put(1, ASN1Util.encodeTaggedObjects(extensionBlock));
    } else {
      scoringError.put(0, ASN1Util.encodeInt(errorCode.getCode()));
    }
    return ASN1Util.encodeTaggedObjects(scoringError);
  }
}
