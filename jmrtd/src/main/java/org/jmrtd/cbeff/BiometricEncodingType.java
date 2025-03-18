/*
 * JMRTD - A Java API for accessing machine readable travel documents.
 *
 * Copyright (C) 2006 - 2025  The JMRTD team
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

package org.jmrtd.cbeff;

/**
 * Specifies what encoding (ISO/IEC-19794 or ISO/IEC-39794)
 * was used for biometric data blocks.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision$
 */
public enum BiometricEncodingType {

  /** Unknown encoding. */
  UNKNOWN,

  /** Uses FaceInfo records BDB. */
  ISO_19794,

  /** Used FaceImageDataBlock BDB. */
  ISO_39794;

  /**
   * Maps tag to encoding type.
   *
   * @param bioDataBlockTag either {@code 0x5F2E} or {@code 0x7F2E}
   *
   * @return the corresponding type
   */
  public static BiometricEncodingType fromBDBTag(int bioDataBlockTag) {
    switch (bioDataBlockTag) {
    case ISO781611.BIOMETRIC_DATA_BLOCK_TAG:
      /* 5F2E */
      return ISO_19794;
    case ISO781611.BIOMETRIC_DATA_BLOCK_CONSTRUCTED_TAG:
      /* 7F2E */
      return ISO_39794;
    default:
      return UNKNOWN;
    }
  }
}