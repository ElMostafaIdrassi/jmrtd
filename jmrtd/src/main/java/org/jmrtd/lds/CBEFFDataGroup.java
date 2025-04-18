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

package org.jmrtd.lds;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jmrtd.cbeff.BiometricDataBlock;
import org.jmrtd.cbeff.BiometricEncodingType;
import org.jmrtd.cbeff.CBEFFInfo;
import org.jmrtd.cbeff.ComplexCBEFFInfo;
import org.jmrtd.cbeff.ISO781611;
import org.jmrtd.cbeff.ISO781611Decoder;
import org.jmrtd.cbeff.ISO781611Encoder;
import org.jmrtd.cbeff.SimpleCBEFFInfo;

import net.sf.scuba.tlv.TLVOutputStream;

/**
 * Datagroup containing a list of biometric information templates (BITs).
 * The {@code DG2File}, {@code DG3File}, and {@code DG4File} datagroups
 * are based on this type.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision$
 */
public abstract class CBEFFDataGroup extends DataGroup {

  private static final long serialVersionUID = 2702959939408371946L;

  protected static final Logger LOGGER = Logger.getLogger("org.jmrtd.lds");

  /** For writing the optional random data block. */
  private Random random;

  /** Records in the BIT group. Each record represents a single BIT. */
  private List<BiometricDataBlock> subRecords;

  protected boolean shouldAddRandomDataIfEmpty;

  protected BiometricEncodingType encodingType;

  /**
   * Creates a CBEFF data group.
   *
   * @param dataGroupTag the data group tag
   * @param encodingType encoding type, either ISO19794 or ISO39794
   * @param subRecords the sub-records contained in this data group
   * @param shouldAddRandomDataIfEmpty whether to include random data if there are no records
   */
  protected CBEFFDataGroup(int dataGroupTag, BiometricEncodingType encodingType,
      List<? extends BiometricDataBlock> subRecords, boolean shouldAddRandomDataIfEmpty) {
    super(dataGroupTag);
    addAll(subRecords);
    this.encodingType = encodingType;
    this.shouldAddRandomDataIfEmpty = shouldAddRandomDataIfEmpty;
    this.random = new SecureRandom();
  }

  /**
   * Constructs an instance.
   *
   * @param dataGroupTag the datagroup tag to use
   * @param inputStream an input stream
   * @param shouldAddRandomDataIfEmpty whether to include random data if there are no records
   *
   * @throws IOException on error
   */
  protected CBEFFDataGroup(int dataGroupTag, InputStream inputStream, boolean shouldAddRandomDataIfEmpty) throws IOException {
    super(dataGroupTag, inputStream);
    this.shouldAddRandomDataIfEmpty = shouldAddRandomDataIfEmpty;
    this.random = new Random();
  }

  public abstract ISO781611Decoder<BiometricDataBlock> getDecoder();

  public abstract ISO781611Encoder<BiometricDataBlock> getEncoder();

  public BiometricEncodingType getEncodingType() {
    return encodingType;
  }

  @Override
  protected void readContent(InputStream inputStream) throws IOException {
    ISO781611Decoder<BiometricDataBlock> decoder = getDecoder();
    this.encodingType = decoder.getEncodingType();
    ComplexCBEFFInfo<BiometricDataBlock> complexCBEFFInfo = decoder.decode(inputStream);
    List<CBEFFInfo<BiometricDataBlock>> records = complexCBEFFInfo.getSubRecords();
    for (CBEFFInfo<BiometricDataBlock> cbeffInfo: records) {
      if (!(cbeffInfo instanceof SimpleCBEFFInfo<?>)) {
        throw new IOException("Was expecting a SimpleCBEFFInfo, found " + cbeffInfo.getClass().getSimpleName());
      }
      SimpleCBEFFInfo<?> simpleCBEFFInfo = (SimpleCBEFFInfo<?>)cbeffInfo;
      BiometricDataBlock bdb = simpleCBEFFInfo.getBiometricDataBlock();
      add(bdb);
    }
    encodingType = decoder.getEncodingType();

    /* FIXME: by symmetry, shouldn't there be a readOptionalRandomData here? */
  }

  @Override
  protected void writeContent(OutputStream outputStream) throws IOException {
    ISO781611Encoder<BiometricDataBlock> encoder = getEncoder();
    ComplexCBEFFInfo<BiometricDataBlock> cbeffInfo = new ComplexCBEFFInfo<BiometricDataBlock>();
    List<BiometricDataBlock> records = getSubRecords();
    for (BiometricDataBlock record: records) {
      SimpleCBEFFInfo<BiometricDataBlock> simpleCBEFFInfo = new SimpleCBEFFInfo<BiometricDataBlock>(record);
      cbeffInfo.add(simpleCBEFFInfo);
    }
    encoder.encode(cbeffInfo, outputStream);

    /* NOTE: Supplement to ICAO Doc 9303 R7-p1_v2_sIII_0057. */
    if (shouldAddRandomDataIfEmpty) {
      writeOptionalRandomData(outputStream);
    }
  }

  /**
   * Returns a textual representation of this data group.
   *
   * @return a textual representation of this data group
   */
  @Override
  public String toString() {
    StringBuilder result = new StringBuilder();
    result.append("CBEFFDataGroup [");
    if (subRecords == null) {
      result.append("null");
    } else {
      boolean isFirst = true;
      for (BiometricDataBlock subRecord: subRecords) {
        if (!isFirst) {
          result.append(", ");
        } else {
          isFirst = false;
        }
        result.append(subRecord == null ? "null" : subRecord.toString());
      }
    }
    result.append(']');
    return result.toString();
  }

  /**
   * Returns the records in this data group.
   *
   * @return the records in this data group
   */
  public List<BiometricDataBlock> getSubRecords() {
    if (subRecords == null) {
      subRecords = new ArrayList<BiometricDataBlock>();
    }
    return new ArrayList<BiometricDataBlock>(subRecords);
  }

  @Override
  public boolean equals(Object other) {
    if (other == null) {
      return false;
    }
    if (other == this) {
      return true;
    }
    if (!(other instanceof CBEFFDataGroup)) {
      return false;
    }

    try {
      CBEFFDataGroup otherDG = (CBEFFDataGroup)other;
      List<BiometricDataBlock> subRecords = getSubRecords();
      List<BiometricDataBlock> otherSubRecords = otherDG.getSubRecords();
      int subRecordCount = subRecords.size();
      if (subRecordCount != otherSubRecords.size()) {
        return false;
      }

      for (int i = 0; i < subRecordCount; i++) {
        BiometricDataBlock subRecord = subRecords.get(i);
        BiometricDataBlock otherSubRecord = otherSubRecords.get(i);
        if (subRecord == null) {
          if (otherSubRecord != null) {
            return false;
          }
        } else if (!subRecord.equals(otherSubRecord)) {
          return false;
        }
      }

      return true;
    } catch (ClassCastException cce) {
      LOGGER.log(Level.WARNING, "Wrong class", cce);
      return false;
    }
  }

  @Override
  public int hashCode() {
    int result = 1234567891;
    List<BiometricDataBlock> subRecords = getSubRecords();
    for (BiometricDataBlock record: subRecords) {
      if (record == null) {
        result = 3 * result + 5;
      } else {
        result = 5 * (result + record.hashCode()) + 7;
      }
    }
    result = shouldAddRandomDataIfEmpty ? 13 * result + 111 : 17 * result + 123;
    return 7 * result + 11;
  }

  /**
   * Concrete implementations of EAC protected CBEFF DataGroups should call this
   * method at the end of their {@link #writeContent(OutputStream)} method to add
   * some random data if the record contains zero biometric templates.
   * See supplement to ICAO Doc 9303 R7-p1_v2_sIII_0057.
   *
   * @param outputStream the outputstream
   *
   * @throws IOException on I/O errors
   */
  protected void writeOptionalRandomData(OutputStream outputStream) throws IOException {
    if (!subRecords.isEmpty()) {
      return;
    }

    TLVOutputStream tlvOut = outputStream instanceof TLVOutputStream ? (TLVOutputStream)outputStream : new TLVOutputStream(outputStream);
    tlvOut.writeTag(ISO781611.DISCRETIONARY_DATA_FOR_PAYLOAD_TAG);
    byte[] value = new byte[8];
    random.nextBytes(value);
    tlvOut.writeValue(value);
  }

  /**
   * Adds a record to this data group.
   *
   * @param record the record to add
   */
  private void add(BiometricDataBlock record) {
    if (subRecords == null) {
      subRecords = new ArrayList<BiometricDataBlock>();
    }
    subRecords.add(record);
  }

  /**
   * Adds all records in a list to this data group.
   *
   * @param records the records to add
   */
  private void addAll(List<? extends BiometricDataBlock> records) {
    if (subRecords == null) {
      subRecords = new ArrayList<BiometricDataBlock>();
    }
    subRecords.addAll(records);
  }
}
