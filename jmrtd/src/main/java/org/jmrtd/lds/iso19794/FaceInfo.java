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

package org.jmrtd.lds.iso19794;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jmrtd.cbeff.BiometricDataBlock;
import org.jmrtd.cbeff.CBEFFInfo;
import org.jmrtd.cbeff.ISO781611;
import org.jmrtd.cbeff.StandardBiometricHeader;
import org.jmrtd.lds.AbstractListInfo;
import org.jmrtd.lds.iso19794.FaceImageInfo.EyeColor;
import org.jmrtd.lds.iso19794.FaceImageInfo.FeaturePoint;

import net.sf.scuba.data.Gender;

/**
 * A facial record consists of a facial record header and one or more facial record datas.
 * See 5.1 of ISO 19794-5.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision$
 */
public class FaceInfo extends AbstractListInfo<FaceImageInfo> implements BiometricDataBlock {

  private static final long serialVersionUID = -6053206262773400725L;

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  /** Facial Record Header 'F', 'A', 'C', 0x00. Section 5.4, Table 2 of ISO/IEC 19794-5. */
  private static final int FORMAT_IDENTIFIER = 0x46414300;

  /** Version number '0', '1', '0', 0x00. Section 5.4, Table 2 of ISO/IEC 19794-5. */
  private static final int VERSION_NUMBER = 0x30313000;

  private StandardBiometricHeader sbh;

  /**
   * Constructs a face info from a list of face image infos.
   *
   * @param faceImageInfos face image infos
   */
  public FaceInfo(List<FaceImageInfo> faceImageInfos) {
    this(null, faceImageInfos);
  }

  /**
   * Constructs a face info from a list of face image infos.
   *
   * @param sbh the standard biometric header to use
   * @param faceImageInfos face image infos
   */
  public FaceInfo(StandardBiometricHeader sbh, List<FaceImageInfo> faceImageInfos) {
    this.sbh = sbh;
    addAll(faceImageInfos);
  }

  /**
   * Constructs a face info from binary encoding.
   *
   * @param inputStream an input stream
   *
   * @throws IOException when decoding fails
   */
  public FaceInfo(InputStream inputStream) throws IOException {
    this(null, inputStream);
  }

  /**
   * Constructs a face info from binary encoding.
   *
   * @param sbh the standard biometric header to use
   * @param inputStream an input stream
   *
   * @throws IOException when decoding fails
   */
  public FaceInfo(StandardBiometricHeader sbh, InputStream inputStream) throws IOException {
    this.sbh = sbh;
    readObject(inputStream);
  }

  /**
   * Reads the facial record from an input stream. Note that the standard biometric header
   * has already been read.
   *
   * @param inputStream the input stream
   */
  @Override
  public void readObject(InputStream inputStream) throws IOException {
    DataInputStream dataInputStream = inputStream instanceof DataInputStream ? (DataInputStream)inputStream : new DataInputStream(inputStream);

    /* Facial Record Header (14) */

    int fac0 = dataInputStream.readInt(); // header (e.g. "FAC", 0x00)						/* 4 */
    if (fac0 != FORMAT_IDENTIFIER) {
      LOGGER.log(Level.WARNING, "'FAC' marker expected! Found " + Integer.toHexString(fac0));

      if (fac0 == 0x0000000C) {

        /* Magic JP2 header. Best effort, assume this is a single image. */

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DataOutputStream dataOutputStream = new DataOutputStream(bOut);
        dataOutputStream.writeInt(fac0);

        int imageLength = (int)dataInputStream.readShort();

        dataOutputStream.writeShort(imageLength);

        int totalBytesRead = 0;
        while (totalBytesRead < imageLength) {
          byte[] buffer = new byte[2048];
          int chunkSize = dataInputStream.read(buffer);
          if (chunkSize < 0) {
            break;
          }
          bOut.write(buffer);
          totalBytesRead += chunkSize;
        }

        /* Construct header with default values. */
        FaceImageInfo imageInfo = new FaceImageInfo(
            Gender.UNKNOWN,
            EyeColor.UNSPECIFIED,
            0x00,
            FaceImageInfo.HAIR_COLOR_UNSPECIFIED,
            FaceImageInfo.EXPRESSION_UNSPECIFIED,
            new int[] { 0, 0, 0}, new int[] {0, 0, 0},
            FaceImageInfo.IMAGE_DATA_TYPE_JPEG2000,
            FaceImageInfo.IMAGE_COLOR_SPACE_UNSPECIFIED,
            FaceImageInfo.SOURCE_TYPE_UNSPECIFIED,
            0x00,
            0,
            new FeaturePoint[] { },
            0, 0,
            new ByteArrayInputStream(bOut.toByteArray()), imageLength, FaceImageInfo.IMAGE_DATA_TYPE_JPEG2000);
        add(imageInfo);
        return;
      }
    }

    int version = dataInputStream.readInt(); // version in ASCII (e.g. "010" 0x00)			/* + 4 = 8 */
    if (version != VERSION_NUMBER) {
      throw new IllegalArgumentException("'010' version number expected! Found " + Integer.toHexString(version));
    }

    long recordLength = dataInputStream.readInt() & 0xFFFFFFFFL;	 						/* + 4 = 12 */
    long headerLength = 14; /* 4 + 4 + 4 + 2 */
    long dataLength = recordLength - headerLength;

    long constructedDataLength = 0L;

    int count = dataInputStream.readUnsignedShort();										/* + 2 = 14 */

    for (int i = 0; i < count; i++) {
      FaceImageInfo imageInfo = new FaceImageInfo(inputStream);
      constructedDataLength += imageInfo.getRecordLength();
      add(imageInfo);
    }
    if (dataLength != constructedDataLength) {
      LOGGER.warning("ConstructedDataLength and dataLength differ: "
          + "dataLength = " + dataLength
          + ", constructedDataLength = " + constructedDataLength);
    }
  }

  /**
   * Writes the facial record to an output stream. Note that the standard biometric header
   * (part of CBEFF structure) is not written here.
   *
   * @param outputStream an output stream
   */
  @Override
  public void writeObject(OutputStream outputStream) throws IOException {

    int headerLength = 14; /* 4 + 4 + 4 + 2 (Section 5.4 of ISO/IEC 19794-5) */

    long dataLength = 0;
    List<FaceImageInfo> faceImageInfos = getSubRecords();
    for (FaceImageInfo faceImageInfo: faceImageInfos) {
      dataLength += faceImageInfo.getRecordLength();
    }

    long recordLength = headerLength + dataLength;

    DataOutputStream dataOut = outputStream instanceof DataOutputStream ? (DataOutputStream)outputStream : new DataOutputStream(outputStream);

    dataOut.writeInt(FORMAT_IDENTIFIER);											    /* 4 */
    dataOut.writeInt(VERSION_NUMBER);														  /* + 4 = 8 */

    /*
     * The (4 byte) Length of Record field shall
     * be the combined length in bytes for the record.
     * This is the entire length of the record including
     * the Facial Record Header and Facial Record Data.
     */
    dataOut.writeInt((int)(recordLength & 0x00000000FFFFFFFFL));	/* + 4 = 12 */

    /* Number of facial record data blocks. */
    dataOut.writeShort(faceImageInfos.size());                   	/* + 2 = 14 */

    for (FaceImageInfo faceImageInfo: faceImageInfos) {
      faceImageInfo.writeObject(dataOut);
    }
  }

  /**
   * Returns the standard biometric header of this biometric data block.
   *
   * @return the standard biometric header
   */
  public StandardBiometricHeader getStandardBiometricHeader() {
    if (sbh == null) {
      byte[] biometricType = { (byte)CBEFFInfo.BIOMETRIC_TYPE_FACIAL_FEATURES };
      byte[] biometricSubtype = { (byte)CBEFFInfo.BIOMETRIC_SUBTYPE_NONE };
      byte[] formatOwner = { (byte)((StandardBiometricHeader.JTC1_SC37_FORMAT_OWNER_VALUE & 0xFF00) >> 8), (byte)(StandardBiometricHeader.JTC1_SC37_FORMAT_OWNER_VALUE & 0xFF) };
      byte[] formatType = { (byte)((StandardBiometricHeader.ISO_19794_FACE_IMAGE_FORMAT_TYPE_VALUE & 0xFF00) >> 8), (byte)(StandardBiometricHeader.ISO_19794_FACE_IMAGE_FORMAT_TYPE_VALUE & 0xFF) };

      SortedMap<Integer, byte[]> elements = new TreeMap<Integer, byte[]>();
      elements.put(ISO781611.BIOMETRIC_TYPE_TAG, biometricType);
      elements.put(ISO781611.BIOMETRIC_SUBTYPE_TAG, biometricSubtype);
      elements.put(ISO781611.FORMAT_OWNER_TAG, formatOwner);
      elements.put(ISO781611.FORMAT_TYPE_TAG, formatType);
      sbh = new StandardBiometricHeader(elements);
    }
    return sbh;
  }

  /**
   * Returns the face image infos embedded in this face info.
   *
   * @return the embedded face image infos
   */
  public List<FaceImageInfo> getFaceImageInfos() {
    return getSubRecords();
  }

  /**
   * Adds a face image info to this face info.
   *
   * @param faceImageInfo the face image info to add
   */
  public void addFaceImageInfo(FaceImageInfo faceImageInfo) {
    add(faceImageInfo);
  }

  /**
   * Removes a face image info from this face info.
   *
   * @param index the index of the face image info to remove
   */
  public void removeFaceImageInfo(int index) {
    remove(index);
  }

  @Override
  public String toString() {
    StringBuilder result = new StringBuilder();
    result.append("FaceInfo [");
    List<FaceImageInfo> records = getSubRecords();
    for (FaceImageInfo record: records) {
      result.append(record.toString());
    }
    result.append("]");
    return result.toString();
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = super.hashCode();
    result = prime * result + ((sbh == null) ? 0 : sbh.hashCode());
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (!super.equals(obj)) {
      return false;
    }
    if (getClass() != obj.getClass()) {
      return false;
    }

    FaceInfo other = (FaceInfo)obj;
    if (sbh == null) {
      return other.sbh == null;
    }

    return sbh == other.sbh || sbh.equals(other.sbh);
  }
}
