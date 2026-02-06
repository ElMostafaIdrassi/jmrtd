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
 * File structure for the EF_DG11 file.
 * Datagroup 11 contains additional personal detail(s).
 *
 * All fields are optional. See Section 16 of LDS-TR.
 * <ol>
 * <li>Name of Holder (Primary and Secondary Identifiers, in full)</li>
 * <li>Other Name(s)</li>
 * <li>Personal Number</li>
 * <li>Place of Birth</li>
 * <li>Date of Birth (in full)</li>
 * <li>Address</li>
 * <li>Telephone Number(s)</li>
 * <li>Profession</li>
 * <li>Title</li>
 * <li>Personal Summary</li>
 * <li>Proof of Citizenship [see 14.5.1]</li>
 * <li>Number of Other Valid Travel Documents</li>
 * <li>Other Travel Document Numbers</li>
 * <li>Custody Information</li>
 * </ol>
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision$
 */
public class DG11File extends AdditionalDetailDataGroup {

  private static final long serialVersionUID = 8566312538928662937L;

  public static final int TAG_LIST_TAG = 0x5C;

  public static final int FULL_NAME_TAG = 0x5F0E;
  public static final int OTHER_NAME_TAG = 0x5F0F;
  public static final int PERSONAL_NUMBER_TAG = 0x5F10;
  public static final int FULL_DATE_OF_BIRTH_TAG = 0x5F2B; // In 'CCYYMMDD' format.
  public static final int PLACE_OF_BIRTH_TAG = 0x5F11; // Fields separated by '<'
  public static final int PERMANENT_ADDRESS_TAG = 0x5F42; // Fields separated by '<'
  public static final int TELEPHONE_TAG = 0x5F12;
  public static final int PROFESSION_TAG = 0x5F13;
  public static final int TITLE_TAG = 0x5F14;
  public static final int PERSONAL_SUMMARY_TAG = 0x5F15;
  public static final int PROOF_OF_CITIZENSHIP_TAG = 0x5F16; // Compressed image per ISO/IEC 10918
  public static final int OTHER_VALID_TD_NUMBERS_TAG = 0x5F17; // Separated by '<'
  public static final int CUSTODY_INFORMATION_TAG = 0x5F18;

  private static final String SDF = "yyyyMMdd";

  private String nameOfHolder;
  private List<String> otherNames;
  private String personalNumber;
  private String fullDateOfBirth;
  private List<String> placeOfBirth;
  private List<String> permanentAddress;
  private String telephone;
  private String profession;
  private String title;
  private String personalSummary;
  private byte[] proofOfCitizenship;
  private List<String> otherValidTDNumbers;
  private String custodyInformation;

  private List<Integer> tagPresenceList;

  /**
   * Constructs a file from binary representation.
   *
   * @param inputStream an input stream
   *
   * @throws IOException if reading fails
   */
  public DG11File(InputStream inputStream) throws IOException {
    super(EF_DG11_TAG, inputStream);
  }

  /**
   * Constructs a new file. Use <code>null</code> if data element is not present.
   * Use <code>&#39;&lt;&#39;</code> as separator.
   *
   * @param nameOfHolder data element
   * @param otherNames data element
   * @param personalNumber data element
   * @param fullDateOfBirth data element
   * @param placeOfBirth data element
   * @param permanentAddress data element
   * @param telephone data element
   * @param profession data element
   * @param title data element
   * @param personalSummary data element
   * @param proofOfCitizenship data element
   * @param otherValidTDNumbers data element
   * @param custodyInformation data element
   */
  public DG11File(String nameOfHolder,
      List<String> otherNames, String personalNumber,
      Date fullDateOfBirth, List<String> placeOfBirth, List<String> permanentAddress,
      String telephone, String profession, String title,
      String personalSummary, byte[] proofOfCitizenship,
      List<String> otherValidTDNumbers, String custodyInformation) {
    this(nameOfHolder,
        otherNames, personalNumber,
        fullDateOfBirth == null ? null: new SimpleDateFormat(SDF).format(fullDateOfBirth),
        placeOfBirth, permanentAddress,
        telephone, profession, title,
        personalSummary, proofOfCitizenship,
        otherValidTDNumbers, custodyInformation);
  }

  /**
   * Constructs a new file. Use <code>null</code> if data element is not present.
   * Use <code>&#39;&lt;&#39;</code> as separator.
   *
   * @param nameOfHolder data element
   * @param otherNames data element
   * @param personalNumber data element
   * @param fullDateOfBirth data element
   * @param placeOfBirth data element
   * @param permanentAddress data element
   * @param telephone data element
   * @param profession data element
   * @param title data element
   * @param personalSummary data element
   * @param proofOfCitizenship data element
   * @param otherValidTDNumbers data element
   * @param custodyInformation data element
   */
  public DG11File(String nameOfHolder,
      List<String> otherNames, String personalNumber,
      String fullDateOfBirth, List<String> placeOfBirth, List<String> permanentAddress,
      String telephone, String profession, String title,
      String personalSummary, byte[] proofOfCitizenship,
      List<String> otherValidTDNumbers, String custodyInformation) {
    super(EF_DG11_TAG);
    this.nameOfHolder = nameOfHolder;
    this.otherNames = otherNames == null ? null : new ArrayList<String>(otherNames);
    this.personalNumber = personalNumber;
    this.fullDateOfBirth = fullDateOfBirth;
    if (placeOfBirth == null) {
      this.placeOfBirth = null;
    } else if (placeOfBirth.isEmpty()) {
      this.placeOfBirth = Collections.singletonList("");
    } else {
      this.placeOfBirth = new ArrayList<String>(placeOfBirth);
    }
    if (permanentAddress == null) {
      this.permanentAddress = null;
    } else if (permanentAddress.isEmpty()) {
      this.permanentAddress = Collections.singletonList("");
    } else {
      this.permanentAddress = new ArrayList<String>(permanentAddress);
    }
    this.telephone = telephone;
    this.profession = profession;
    this.title = title;
    this.personalSummary = personalSummary;
    this.proofOfCitizenship = proofOfCitizenship;
    if (otherValidTDNumbers == null) {
      this.otherValidTDNumbers = null;
    } else if (otherValidTDNumbers.isEmpty()) {
      this.otherValidTDNumbers = Collections.singletonList("");
    } else {
      this.otherValidTDNumbers = new ArrayList<String>(otherValidTDNumbers);
    }
    this.custodyInformation = custodyInformation;
  }

  /* Accessors below. */

  @Override
  public int getTag() {
    return EF_DG11_TAG;
  }

  /**
   * Returns the list of tags of fields actually present.
   *
   * @return list of tags
   */
  public List<Integer> getTagPresenceList() {
    if (tagPresenceList != null) {
      return tagPresenceList;
    }
    tagPresenceList = new ArrayList<Integer>(12);
    if (nameOfHolder != null) {
      tagPresenceList.add(FULL_NAME_TAG);
    }
    if (otherNames != null) {
      tagPresenceList.add(OTHER_NAME_TAG);
    }
    if (personalNumber != null) {
      tagPresenceList.add(PERSONAL_NUMBER_TAG);
    }
    if (fullDateOfBirth != null) {
      tagPresenceList.add(FULL_DATE_OF_BIRTH_TAG);
    }
    if (placeOfBirth != null) {
      tagPresenceList.add(PLACE_OF_BIRTH_TAG);
    }
    if (permanentAddress != null) {
      tagPresenceList.add(PERMANENT_ADDRESS_TAG);
    }
    if (telephone != null) {
      tagPresenceList.add(TELEPHONE_TAG);
    }
    if (profession != null) {
      tagPresenceList.add(PROFESSION_TAG);
    }
    if (title != null) {
      tagPresenceList.add(TITLE_TAG);
    }
    if (personalSummary != null) {
      tagPresenceList.add(PERSONAL_SUMMARY_TAG);
    }
    if (proofOfCitizenship != null) {
      tagPresenceList.add(PROOF_OF_CITIZENSHIP_TAG);
    }
    if (otherValidTDNumbers != null) {
      tagPresenceList.add(OTHER_VALID_TD_NUMBERS_TAG);
    }
    if (custodyInformation != null) {
      tagPresenceList.add(CUSTODY_INFORMATION_TAG);
    }
    return tagPresenceList;
  }

  /**
   * Returns the full name of the holder (primary and secondary identifiers).
   *
   * @return the name of holder
   */
  public String getNameOfHolder() {
    return nameOfHolder;
  }

  /**
   * Returns the other names.
   *
   * @return the other names, or empty list when not present
   */
  public List<String> getOtherNames() {
    return otherNames == null ? null : new ArrayList<String>(otherNames);
  }

  /**
   * Returns the personal number.
   *
   * @return the personal number
   */
  public String getPersonalNumber() {
    return personalNumber;
  }

  /**
   * Returns the full date of birth.
   *
   * @return the full date of birth
   */
  public String getFullDateOfBirth() {
    return fullDateOfBirth;
  }

  /**
   * Returns the place of birth.
   *
   * @return the place of birth
   */
  public List<String> getPlaceOfBirth() {
    return placeOfBirth;
  }

  /**
   * Returns the permanent address.
   *
   * @return the permanent address
   */
  public List<String> getPermanentAddress() {
    return permanentAddress;
  }

  /**
   * Returns the telephone number.
   *
   * @return the telephone
   */
  public String getTelephone() {
    return telephone;
  }

  /**
   * Returns the holder's profession.
   *
   * @return the profession
   */
  public String getProfession() {
    return profession;
  }

  /**
   * Returns the holder's title.
   *
   * @return the title
   */
  public String getTitle() {
    return title;
  }

  /**
   * Returns the personal summary.
   *
   * @return the personal summary
   */
  public String getPersonalSummary() {
    return personalSummary;
  }

  /**
   * Returns the proof of citizenship.
   *
   * @return the proof of citizenship
   */
  public byte[] getProofOfCitizenship() {
    return proofOfCitizenship;
  }

  /**
   * Returns the other valid travel document numbers.
   *
   * @return the other valid travel document numbers
   */
  public List<String> getOtherValidTDNumbers() {
    return otherValidTDNumbers;
  }

  /**
   * Returns the custody information.
   *
   * @return the custody information
   */
  public String getCustodyInformation() {
    return custodyInformation;
  }

  /**
   * Returns a textual representation of this file.
   *
   * @return a textual representation of this file
   */
  @Override
  public String toString() {
    return new StringBuilder()
        .append("DG11File [")
        .append(nameOfHolder == null ? "" : nameOfHolder).append(", ")
        .append(otherNames == null || otherNames.isEmpty() ? "[]" : otherNames).append(", ")
        .append(personalNumber == null ? "" : personalNumber).append(", ")
        .append(fullDateOfBirth == null ? "" : fullDateOfBirth).append(", ")
        .append(placeOfBirth == null || placeOfBirth.isEmpty() ? "[]" : placeOfBirth.toString()).append(", ")
        .append(permanentAddress == null || permanentAddress.isEmpty() ? "[]" : permanentAddress.toString()).append(", ")
        .append(telephone == null ? "" : telephone).append(", ")
        .append(profession == null ? "" : profession).append(", ")
        .append(title == null ? "" : title).append(", ")
        .append(personalSummary == null ? "" : personalSummary).append(", ")
        .append(proofOfCitizenship == null ? "" : "image (" + proofOfCitizenship.length + ")").append(", ")
        .append(otherValidTDNumbers == null || otherValidTDNumbers.isEmpty() ? "[]" : otherValidTDNumbers.toString()).append(", ")
        .append(custodyInformation == null ? "" : custodyInformation)
        .append("]")
        .toString();
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + Arrays.hashCode(proofOfCitizenship);
    result = prime * result + Objects.hash(custodyInformation, fullDateOfBirth, nameOfHolder, otherNames,
        otherValidTDNumbers, permanentAddress, personalNumber, personalSummary, placeOfBirth, profession,
        telephone, title);
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

    DG11File other = (DG11File) obj;
    return Objects.equals(custodyInformation, other.custodyInformation)
        && Objects.equals(fullDateOfBirth, other.fullDateOfBirth)
        && Objects.equals(nameOfHolder, other.nameOfHolder)
        && Objects.equals(otherNames, other.otherNames)
        && Objects.equals(otherValidTDNumbers, other.otherValidTDNumbers)
        && Objects.equals(permanentAddress, other.permanentAddress)
        && Objects.equals(personalNumber, other.personalNumber)
        && Objects.equals(personalSummary, other.personalSummary)
        && Objects.equals(placeOfBirth, other.placeOfBirth)
        && Objects.equals(profession, other.profession)
        && Arrays.equals(proofOfCitizenship, other.proofOfCitizenship)
        && Objects.equals(getTagPresenceList(), other.getTagPresenceList())
        && Objects.equals(telephone, other.telephone)
        && Objects.equals(title, other.title);
  }

  /**
   * Reads a field from a stream.
   *
   * @param expectedTag the tag to expect
   * @param tlvInputStream the stream to read from
   *
   * @throws IOException on error reading from the stream
   */
  @Override
  protected void readField(int expectedTag, TLVInputStream tlvInputStream) throws IOException {
    int tag = tlvInputStream.readTag();
    if (tag != CONTENT_SPECIFIC_CONSTRUCTED_TAG && tag != expectedTag) {
      throw new IllegalArgumentException("Expected " + Integer.toHexString(expectedTag) + ", but found " + Integer.toHexString(tag));
    }
    tlvInputStream.readLength();
    switch (tag) {
    case FULL_NAME_TAG:
      nameOfHolder = readString(tlvInputStream);
      break;
    case CONTENT_SPECIFIC_CONSTRUCTED_TAG:
      otherNames = readContentSpecificFieldsList(tlvInputStream);
      break;
    case OTHER_NAME_TAG:
      /* Work around non-compliant early samples. */
      otherNames = Collections.singletonList(readString(tlvInputStream));
      break;
    case PERSONAL_NUMBER_TAG:
      personalNumber = readString(tlvInputStream);
      break;
    case FULL_DATE_OF_BIRTH_TAG:
      fullDateOfBirth = readFullDate(tlvInputStream);
      break;
    case PLACE_OF_BIRTH_TAG:
      placeOfBirth = readList(tlvInputStream);
      break;
    case PERMANENT_ADDRESS_TAG:
      permanentAddress = readList(tlvInputStream);
      break;
    case TELEPHONE_TAG:
      telephone = readString(tlvInputStream);
      break;
    case PROFESSION_TAG:
      profession = readString(tlvInputStream);
      break;
    case TITLE_TAG:
      title = readString(tlvInputStream);
      break;
    case PERSONAL_SUMMARY_TAG:
      personalSummary = readString(tlvInputStream);
      break;
    case PROOF_OF_CITIZENSHIP_TAG:
      proofOfCitizenship = readBytes(tlvInputStream);
      break;
    case OTHER_VALID_TD_NUMBERS_TAG:
      otherValidTDNumbers = readList(tlvInputStream);
      break;
    case CUSTODY_INFORMATION_TAG:
      custodyInformation = readString(tlvInputStream);
      break;
    default:
      throw new IllegalArgumentException("Unknown field tag in DG11: " + Integer.toHexString(tag));
    }
  }

  @Override
  protected void writeField(int tag, TLVOutputStream tlvOut) throws IOException {
    switch (tag) {
    case FULL_NAME_TAG:
      writeString(tag, nameOfHolder, tlvOut);
      break;
    case OTHER_NAME_TAG:
      writeContentSpecificFieldsList(OTHER_NAME_TAG, otherNames, tlvOut);
      break;
    case PERSONAL_NUMBER_TAG:
      writeString(tag, personalNumber, tlvOut);
      break;
    case FULL_DATE_OF_BIRTH_TAG:
      writeString(tag, fullDateOfBirth, tlvOut);
      break;
    case PLACE_OF_BIRTH_TAG:
      writeList(tag, placeOfBirth, tlvOut);
      break;
    case PERMANENT_ADDRESS_TAG:
      writeList(tag, permanentAddress, tlvOut);
      break;
    case TELEPHONE_TAG:
      writeString(tag, telephone, tlvOut);
      break;
    case PROFESSION_TAG:
      writeString(tag, profession, tlvOut);
      break;
    case TITLE_TAG:
      writeString(tag, title, tlvOut);
      break;
    case PERSONAL_SUMMARY_TAG:
      writeString(tag, personalSummary, tlvOut);
      break;
    case PROOF_OF_CITIZENSHIP_TAG:
      tlvOut.writeTag(tag);
      tlvOut.writeValue(proofOfCitizenship);
      break;
    case OTHER_VALID_TD_NUMBERS_TAG:
      writeList(tag, otherValidTDNumbers, tlvOut);
      break;
    case CUSTODY_INFORMATION_TAG:
      writeString(tag, custodyInformation, tlvOut);
      break;
    default:
      throw new IllegalStateException("Unknown tag in DG11: " + Integer.toHexString(tag));
    }
  }
}
