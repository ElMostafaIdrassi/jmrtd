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

package org.jmrtd.lds.icao;

import java.io.IOException;
import java.io.InputStream;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Objects;

import net.sf.scuba.tlv.TLVInputStream;
import net.sf.scuba.tlv.TLVOutputStream;

/**
 * File structure for the EF_DG12 file.
 * Datagroup 12 contains additional document detail(s).
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision$
 */
public class DG12File extends AdditionalDetailDataGroup {

  private static final long serialVersionUID = -1979367459379125674L;

  public static final int ISSUING_AUTHORITY_TAG = 0x5F19;
  public static final int DATE_OF_ISSUE_TAG = 0x5F26;  // yyyymmdd
  public static final int NAME_OF_OTHER_PERSON_TAG = 0x5F1A; // formatted per ICAO 9303 rules
  public static final int ENDORSEMENTS_AND_OBSERVATIONS_TAG = 0x5F1B;
  public static final int TAX_OR_EXIT_REQUIREMENTS_TAG = 0x5F1C;
  public static final int IMAGE_OF_FRONT_TAG = 0x5F1D; // Image per ISO/IEC 10918
  public static final int IMAGE_OF_REAR_TAG = 0x5F1E; // Image per ISO/IEC 10918
  public static final int DATE_AND_TIME_OF_PERSONALIZATION_TAG = 0x5F55; // yyyymmddhhmmss
  public static final int PERSONALIZATION_SYSTEM_SERIAL_NUMBER_TAG = 0x5F56;
  public static final int CONTENT_SPECIFIC_CONSTRUCTED_TAG = 0xA0; // 5F1A is always used inside A0 constructed object
  public static final int COUNT_TAG = 0x02; // Used in A0 constructed object to indicate single byte count of simple objects

  private static final String SDF = "yyyyMMdd";
  private static final String SDTF = "yyyyMMddhhmmss";

  private String issuingAuthority;
  private String dateOfIssue;
  private List<String> namesOfOtherPersons;
  private String endorsementsAndObservations;
  private String taxOrExitRequirements;
  private byte[] imageOfFront;
  private byte[] imageOfRear;
  private String dateAndTimeOfPersonalization;
  private String personalizationSystemSerialNumber;

  private List<Integer> tagPresenceList;

  /**
   * Constructs a new file.
   *
   * @param issuingAuthority the issuing authority
   * @param dateOfIssue the date of issue
   * @param namesOfOtherPersons names of other persons
   * @param endorsementsAndObservations endorsements and observations
   * @param taxOrExitRequirements tax or exit requirements
   * @param imageOfFront image of front
   * @param imageOfRear image of rear
   * @param dateAndTimeOfPersonalization date and time of personalization
   * @param personalizationSystemSerialNumber personalization system serial number
   */
  public DG12File(String issuingAuthority, Date dateOfIssue,
      List<String> namesOfOtherPersons, String endorsementsAndObservations,
      String taxOrExitRequirements, byte[] imageOfFront,
      byte[] imageOfRear, Date dateAndTimeOfPersonalization,
      String personalizationSystemSerialNumber) {
    this(issuingAuthority,
        dateOfIssue == null ? null : new SimpleDateFormat(SDF).format(dateOfIssue),
        namesOfOtherPersons, endorsementsAndObservations,
        taxOrExitRequirements, imageOfFront,
        imageOfRear,
        dateAndTimeOfPersonalization == null ? null : new SimpleDateFormat(SDTF).format(dateAndTimeOfPersonalization),
        personalizationSystemSerialNumber);
  }

  /**
   * Constructs a new file.
   *
   * @param issuingAuthority the issuing authority
   * @param dateOfIssue the date of issue
   * @param namesOfOtherPersons names of other persons
   * @param endorsementsAndObservations endorsements and observations
   * @param taxOrExitRequirements tax or exit requirements
   * @param imageOfFront image of front
   * @param imageOfRear image of rear
   * @param dateAndTimeOfPersonalization date and time of personalization
   * @param personalizationSystemSerialNumber personalization system serial number
   */
  public DG12File(String issuingAuthority, String dateOfIssue,
      List<String> namesOfOtherPersons, String endorsementsAndObservations,
      String taxOrExitRequirements, byte[] imageOfFront,
      byte[] imageOfRear, String dateAndTimeOfPersonalization,
      String personalizationSystemSerialNumber) {
    super(EF_DG12_TAG);
    this.issuingAuthority = issuingAuthority;
    this.dateOfIssue = dateOfIssue;
    this.namesOfOtherPersons = namesOfOtherPersons == null ? null : new ArrayList<String>(namesOfOtherPersons);
    this.endorsementsAndObservations = endorsementsAndObservations;
    this.taxOrExitRequirements = taxOrExitRequirements;
    this.imageOfFront = imageOfFront;
    this.imageOfRear = imageOfRear;
    this.dateAndTimeOfPersonalization = dateAndTimeOfPersonalization;
    this.personalizationSystemSerialNumber = personalizationSystemSerialNumber;
  }

  /**
   * Constructs a new file.
   *
   * @param inputStream an input stream
   *
   * @throws IOException on error reading from input stream
   */
  public DG12File(InputStream inputStream) throws IOException {
    super(EF_DG12_TAG, inputStream);
  }

  /**
   * Returns the tags of fields actually present in this file.
   *
   * @return a list of tags
   */
  @Override
  public List<Integer> getTagPresenceList() {
    if (tagPresenceList != null) {
      return tagPresenceList;
    }
    tagPresenceList = new ArrayList<Integer>(10);
    if (issuingAuthority != null) {
      tagPresenceList.add(ISSUING_AUTHORITY_TAG);
    }
    if (dateOfIssue != null) {
      tagPresenceList.add(DATE_OF_ISSUE_TAG);
    }
    if (namesOfOtherPersons != null) {
      tagPresenceList.add(NAME_OF_OTHER_PERSON_TAG);
    }
    if (endorsementsAndObservations != null) {
      tagPresenceList.add(ENDORSEMENTS_AND_OBSERVATIONS_TAG);
    }
    if (taxOrExitRequirements != null) {
      tagPresenceList.add(TAX_OR_EXIT_REQUIREMENTS_TAG);
    }
    if (imageOfFront != null) {
      tagPresenceList.add(IMAGE_OF_FRONT_TAG);
    }
    if (imageOfRear != null) {
      tagPresenceList.add(IMAGE_OF_REAR_TAG);
    }
    if (dateAndTimeOfPersonalization != null) {
      tagPresenceList.add(DATE_AND_TIME_OF_PERSONALIZATION_TAG);
    }
    if (personalizationSystemSerialNumber != null) {
      tagPresenceList.add(PERSONALIZATION_SYSTEM_SERIAL_NUMBER_TAG);
    }
    return tagPresenceList;
  }

  /**
   * Returns the issuing authority.
   *
   * @return the issuingAuthority
   */
  public String getIssuingAuthority() {
    return issuingAuthority;
  }

  /**
   * Returns the date of issuance.
   *
   * @return the dateOfIssue
   */
  public String getDateOfIssue() {
    return dateOfIssue;
  }

  /**
   * Returns name of other person.
   *
   * @return the nameOfOtherPerson
   */
  public List<String> getNamesOfOtherPersons() {
    return namesOfOtherPersons;
  }

  /**
   * Returns endorsements and observations.
   *
   * @return the endorsementsAndObservations
   */
  public String getEndorsementsAndObservations() {
    return endorsementsAndObservations;
  }

  /**
   * Returns tax or exit requirements.
   *
   * @return the taxOrExitRequirements
   */
  public String getTaxOrExitRequirements() {
    return taxOrExitRequirements;
  }

  /**
   * Returns image of front.
   *
   * @return the imageOfFront
   */
  public byte[] getImageOfFront() {
    return imageOfFront;
  }

  /**
   * Returns image of rear.
   *
   * @return the imageOfRear
   */
  public byte[] getImageOfRear() {
    return imageOfRear;
  }

  /**
   * Returns the date and time of personalization.
   *
   * @return the dateAndTimeOfPersonalization
   */
  public String getDateAndTimeOfPersonalization() {
    return dateAndTimeOfPersonalization;
  }

  /**
   * Returns the personalization system serial number.
   *
   * @return the personalizationSystemSerialNumber
   */
  public String getPersonalizationSystemSerialNumber() {
    return personalizationSystemSerialNumber;
  }

  @Override
  public int getTag() {
    return EF_DG12_TAG;
  }

  /**
   * Returns a textual representation of this file.
   *
   * @return a textual representation of this file
   */
  @Override
  public String toString() {
    return new StringBuilder()
        .append("DG12File [")
        .append(issuingAuthority == null ? "" : issuingAuthority).append(", ")
        .append(dateOfIssue == null ? "" : dateOfIssue).append(", ")
        .append(namesOfOtherPersons == null || namesOfOtherPersons.isEmpty() ? "[]" : namesOfOtherPersons).append(", ")
        .append(endorsementsAndObservations == null ? "" : endorsementsAndObservations).append(", ")
        .append(taxOrExitRequirements == null ? "" : taxOrExitRequirements).append(", ")
        .append(imageOfFront == null ? "" : "image (" + imageOfFront.length + ")").append(", ")
        .append(imageOfRear == null ? "" : "image (" + imageOfRear.length + ")").append(", ")
        .append(dateAndTimeOfPersonalization == null ? "" : dateAndTimeOfPersonalization).append(", ")
        .append(personalizationSystemSerialNumber== null ? "" : personalizationSystemSerialNumber)
        .append("]")
        .toString();
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + Arrays.hashCode(imageOfFront);
    result = prime * result + Arrays.hashCode(imageOfRear);
    result = prime * result
        + Objects.hash(dateAndTimeOfPersonalization, dateOfIssue, endorsementsAndObservations, issuingAuthority,
            namesOfOtherPersons, personalizationSystemSerialNumber, taxOrExitRequirements);
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    DG12File other = (DG12File) obj;
    return Objects.equals(dateAndTimeOfPersonalization, other.dateAndTimeOfPersonalization)
        && Objects.equals(dateOfIssue, other.dateOfIssue)
        && Objects.equals(endorsementsAndObservations, other.endorsementsAndObservations)
        && Arrays.equals(imageOfFront, other.imageOfFront) && Arrays.equals(imageOfRear, other.imageOfRear)
        && Objects.equals(issuingAuthority, other.issuingAuthority)
        && Objects.equals(namesOfOtherPersons, other.namesOfOtherPersons)
        && Objects.equals(personalizationSystemSerialNumber, other.personalizationSystemSerialNumber)
        && Objects.equals(taxOrExitRequirements, other.taxOrExitRequirements);
  }

  @Override
  protected void readField(int expectedTag, TLVInputStream tlvInputStream) throws IOException {
    int tag = tlvInputStream.readTag();
    if (tag != CONTENT_SPECIFIC_CONSTRUCTED_TAG && tag != expectedTag) {
      throw new IllegalArgumentException("Expected " + Integer.toHexString(expectedTag) + ", but found " + Integer.toHexString(tag));
    }
    tlvInputStream.readLength();
    switch (tag) {
    case ISSUING_AUTHORITY_TAG:
      issuingAuthority = readString(tlvInputStream);
      break;
    case DATE_OF_ISSUE_TAG:
      dateOfIssue = readFullDate(tlvInputStream);
      break;
    case CONTENT_SPECIFIC_CONSTRUCTED_TAG:
      namesOfOtherPersons = readContentSpecificFieldsList(tlvInputStream);
      break;
    case NAME_OF_OTHER_PERSON_TAG:
      /* Work around non-compliant early samples. */
      namesOfOtherPersons = Collections.singletonList(readString(tlvInputStream));
      break;
    case ENDORSEMENTS_AND_OBSERVATIONS_TAG:
      endorsementsAndObservations = readString(tlvInputStream);
      break;
    case TAX_OR_EXIT_REQUIREMENTS_TAG:
      taxOrExitRequirements = readString(tlvInputStream);
      break;
    case IMAGE_OF_FRONT_TAG:
      imageOfFront = readBytes(tlvInputStream);
      break;
    case IMAGE_OF_REAR_TAG:
      imageOfRear = readBytes(tlvInputStream);
      break;
    case DATE_AND_TIME_OF_PERSONALIZATION_TAG:
      dateAndTimeOfPersonalization = readString(tlvInputStream);
      break;
    case PERSONALIZATION_SYSTEM_SERIAL_NUMBER_TAG:
      personalizationSystemSerialNumber = readString(tlvInputStream);
      break;
    default:
      throw new IllegalArgumentException("Unknown field tag in DG12: " + Integer.toHexString(tag));
    }
  }

  @Override
  protected void writeField(int tag, TLVOutputStream tlvOut) throws IOException {
    switch (tag) {
    case ISSUING_AUTHORITY_TAG:;
    writeString(tag, issuingAuthority, tlvOut);
    break;
    case DATE_OF_ISSUE_TAG:
      writeString(tag, dateOfIssue, tlvOut);
      break;
    case NAME_OF_OTHER_PERSON_TAG:
      writeContentSpecificFieldsList(tag, namesOfOtherPersons, tlvOut);
      break;
    case ENDORSEMENTS_AND_OBSERVATIONS_TAG:
      writeString(tag, endorsementsAndObservations, tlvOut);
      break;
    case TAX_OR_EXIT_REQUIREMENTS_TAG:
      writeString(tag, taxOrExitRequirements, tlvOut);
      break;
    case IMAGE_OF_FRONT_TAG:
      writeBytes(tag, imageOfFront, tlvOut);
      break;
    case IMAGE_OF_REAR_TAG:
      writeBytes(tag, imageOfRear, tlvOut);
      break;
    case DATE_AND_TIME_OF_PERSONALIZATION_TAG:
      writeString(tag, dateAndTimeOfPersonalization, tlvOut);
      break;
    case PERSONALIZATION_SYSTEM_SERIAL_NUMBER_TAG:
      writeString(tag, personalizationSystemSerialNumber, tlvOut);
      break;
    default:
      throw new IllegalArgumentException("Unknown field tag in DG12: " + Integer.toHexString(tag));
    }
  }
}
