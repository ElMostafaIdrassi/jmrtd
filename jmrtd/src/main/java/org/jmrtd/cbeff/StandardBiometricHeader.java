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

import java.io.Serializable;
import java.util.Arrays;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;

import net.sf.scuba.util.Hex;

/**
 * A Standard Biometric Header preceeds a Biometric Data Block.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision$
 *
 * @since 0.4.7
 */
public class StandardBiometricHeader implements Serializable {

  private static final long serialVersionUID = 4113147521594478513L;

  /**
   * Format owner identifier of ISO/IEC JTC1/SC37. See:
   * https://www.ibia.org/cbeff/iso/bdb-format-identifiers.
   */
  public static final int JTC1_SC37_FORMAT_OWNER_VALUE = 0x0101;

  /**
   * ISO/IEC JTC1/SC37 uses 0x0007. See:
   * https://www.ibia.org/cbeff/iso/bdb-format-identifiers.
   * (ISO FCD 19794-4 specified this as 0x0401).
   */
  public static final int ISO_19794_FINGER_IMAGE_FORMAT_TYPE_VALUE = 0x0007;

  /**
   * ISO/IEC JTC1/SC37 uses 0x0008. See:
   * https://www.ibia.org/cbeff/iso/bdb-format-identifiers.
   * Also see supplement to Doc 9303: R3-p1_v2_sII_0001.
   * (ISO FCD 19794-5 specified this as 0x0501).
   */
  public static final int ISO_19794_FACE_IMAGE_FORMAT_TYPE_VALUE = 0x0008;

  /**
   * ISO/IEC JTC1/SC37 uses 0x0009. See:
   * https://www.ibia.org/cbeff/iso/bdb-format-identifiers.
   * (ISO FCD 19794-6 specified this as 0x0601).
   */
  public static final int ISO_19794_IRIS_IMAGE_FORMAT_TYPE_VALUE = 0x0009;

  /**
   * Corresponds to {@code g3-binary-finger-image}. See:
   * https://www.ibia.org/cbeff/iso/bdb-format-identifiers.
   */
  public static final int ISO_39794_FINGER_IMAGE_FORMAT_TYPE_VALUE = 0x0028;

  /**
   * Corresponds to {@code g3-binary-face-image}. See:
   * https://www.ibia.org/cbeff/iso/bdb-format-identifiers.
   */
  public static final int ISO_39794_FACE_IMAGE_FORMAT_TYPE_VALUE = 0x002A;

  /**
   * Corresponds to {@code g3-binary-iris-image}. See:
   * https://www.ibia.org/cbeff/iso/bdb-format-identifiers.
   */
  public static final int ISO_39794_IRIS_IMAGE_FORMAT_TYPE_VALUE = 0x002C;

  private SortedMap<Integer, byte[]> elements;

  /**
   * Constructs a standard biometric header.
   *
   * @param elements the elements, consisting of a tag and value
   */
  public StandardBiometricHeader(Map<Integer, byte[]> elements) {
    this.elements = new TreeMap<Integer, byte[]>(elements);
  }

  /**
   * Returns the elements of this standard biometric header.
   *
   * @return the elements, each consisting of a tag and value
   */
  public SortedMap<Integer, byte[]> getElements() {
    return new TreeMap<Integer, byte[]>(elements);
  }

  /**
   * Checks whether the format type is present and equals to the given value.
   *
   * @param formatTypeValue a format type (short) value
   *
   * @return a boolean indicating the format type is present and equal to the given value
   */
  public boolean hasFormatType(int formatTypeValue) {
    byte[] actualFormatTypeValue = elements.get(ISO781611.FORMAT_TYPE_TAG);
    if (actualFormatTypeValue == null) {
      return false;
    }
    if (actualFormatTypeValue.length != 2) {
      return false;
    }

    int actualFormatTypeInt = ((actualFormatTypeValue[0] & 0xFF) << 8) | (actualFormatTypeValue[1] & 0xFF);
    return actualFormatTypeInt == formatTypeValue;
  }

  @Override
  public String toString() {
    StringBuilder result = new StringBuilder();
    result.append("StandardBiometricHeader [");
    boolean isFirst = true;
    for (Map.Entry<Integer, byte[]> entry: elements.entrySet()) {
      if (isFirst) {
        isFirst = false;
      } else {
        result.append(", ");
      }
      result.append(Integer.toHexString(entry.getKey())).append(" -> ").append(Hex.bytesToHexString(entry.getValue()));
    }
    result.append("]");
    return result.toString();
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((elements == null) ? 0 : elements.hashCode());
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null) {
      return false;
    }
    if (getClass() != obj.getClass()) {
      return false;
    }

    StandardBiometricHeader other = (StandardBiometricHeader)obj;
    return equals(elements, other.elements);
  }

  /**
   * Determines whether the two maps have equal entry sets.
   *
   * @param elements1 the first map
   * @param elements2 the second map
   *
   * @return a boolean indicating equality
   */
  private static boolean equals(Map<Integer, byte[]> elements1, Map<Integer, byte[]> elements2) {
    if (elements1 == null && elements2 != null) {
      return false;
    }
    if (elements1 != null && elements2 == null) {
      return false;
    }

    if (elements1 == elements2) {
      return true;
    }

    if (!elements1.keySet().equals(elements2.keySet())) {
      return false;
    }

    for (Map.Entry<Integer, byte[]> entry: elements1.entrySet()) {
      int key = entry.getKey();
      byte[] bytes = entry.getValue();
      byte[] otherBytes = elements2.get(key);
      if (!Arrays.equals(bytes, otherBytes)) {
        return false;
      }
    }

    return true;
  }
}
