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

package org.jmrtd;

import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * A BAC key.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision$
 */
public class BACKey implements BACKeySpec {

  private static final long serialVersionUID = -1059774581180524710L;

  private static final String SDF = "yyMMdd";

  private String documentNumber;
  private String dateOfBirth;
  private String dateOfExpiry;

  /**
   * Creates an empty BAC key entry.
   */
  protected BACKey() {
  }

  /**
   * Creates a BAC key.
   *
   * @param documentNumber the document number string, cannot be <code>null</code>
   * @param dateOfBirth the date of birth, cannot be <code>null</code>
   * @param dateOfExpiry the date of expiry, cannot be <code>null</code>
   */
  public BACKey(String documentNumber, Date dateOfBirth, Date dateOfExpiry) {
    this(documentNumber, toString(dateOfBirth), toString(dateOfExpiry));
  }
  
  /**
   * Creates a BAC key.
   *
   * @param documentNumber the document number string, cannot be <code>null</code>
   * @param dateOfBirth the date of birth string in <i>yymmdd</i> format, cannot be <code>null</code>
   * @param dateOfExpiry the date of expiry string in <i>yymmdd</i> format, cannot be <code>null</code>
   */
  public BACKey(String documentNumber, String dateOfBirth, String dateOfExpiry) {
    if (documentNumber == null) {
      throw new IllegalArgumentException("Illegal document number");
    }
    if (dateOfBirth == null || dateOfBirth.length() != 6) {
      throw new IllegalArgumentException("Illegal date: " + dateOfBirth);
    }
    if (dateOfExpiry == null || dateOfExpiry.length() != 6) {
      throw new IllegalArgumentException("Illegal date: " + dateOfExpiry);
    }
    
    StringBuilder documentNumberBuilder = new StringBuilder(documentNumber);
    while (documentNumberBuilder.length() < 9) {
      documentNumberBuilder.append('<');
    }
    this.documentNumber = documentNumberBuilder.toString().trim();
    this.dateOfBirth = dateOfBirth;
    this.dateOfExpiry = dateOfExpiry;
  }

  /**
   * Gets the document number string.
   *
   * @return the document number string
   */
  public String getDocumentNumber() {
    return documentNumber;
  }

  /**
   * Gets the date of birth string.
   *
   * @return a date in <i>yymmdd</i> format
   */
  public String getDateOfBirth() {
    return dateOfBirth;
  }

  /**
   * Gets the date of expiry string.
   *
   * @return a date in <i>yymmdd</i> format
   */
  public String getDateOfExpiry() {
    return dateOfExpiry;
  }

  /**
   * Gets a textual representation of this BAC key.
   *
   * @return a textual representation of this BAC key
   */
  @Override
  public String toString() {
    return documentNumber + ", " + dateOfBirth + ", " + dateOfExpiry;
  }

  /**
   * Gets the hash code of this BAC key.
   * Document number, date of birth, and date of expiry (with year in <i>yy</i> precision) are taken into account.
   *
   * @return a hash code
   */
  @Override
  public int hashCode() {
    int result = 5;
    result = 61 * result + (documentNumber == null ? 0 : documentNumber.hashCode());
    result = 61 * result + (dateOfBirth == null ? 0 : dateOfBirth.hashCode());
    result = 61 * result + (dateOfExpiry == null ? 0: dateOfExpiry.hashCode());
    return result;
  }

  /**
   * Tests equality of this BAC key with respect to another object.
   *
   * @param o another object
   *
   * @return whether this BAC key equals another object
   */
  @Override
  public boolean equals(Object o) {
    if (o == null) {
      return false;
    }
    if (!o.getClass().equals(this.getClass())) {
      return false;
    }
    if (o == this) {
      return true;
    }
    BACKey previous = (BACKey)o;
    return documentNumber.equals(previous.documentNumber) &&
        dateOfBirth.equals(previous.dateOfBirth) &&
        dateOfExpiry.equals(previous.dateOfExpiry);
  }

  /**
   * The algorithm of this key specification.
   *
   * @return constant &quot;BAC&quot;
   */
  public String getAlgorithm() {
    return "BAC";
  }

  protected void setDocumentNumber(String documentNumber) {
    this.documentNumber = documentNumber;
  }

  protected void setDateOfBirth(String dateOfBirth) {
    this.dateOfBirth = dateOfBirth;
  }

  protected void setDateOfExpiry(String dateOfExpiry) {
    this.dateOfExpiry = dateOfExpiry;
  }

  private static synchronized String toString(Date date) {
    return new SimpleDateFormat(SDF).format(date);
  }
}
