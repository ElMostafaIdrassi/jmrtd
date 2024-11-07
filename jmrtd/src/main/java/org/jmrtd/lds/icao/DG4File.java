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
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

import org.jmrtd.cbeff.BiometricDataBlock;
import org.jmrtd.cbeff.BiometricDataBlockDecoder;
import org.jmrtd.cbeff.BiometricDataBlockEncoder;
import org.jmrtd.cbeff.ISO781611Decoder;
import org.jmrtd.cbeff.ISO781611Encoder;
import org.jmrtd.cbeff.StandardBiometricHeader;
import org.jmrtd.lds.CBEFFDataGroup;
import org.jmrtd.lds.iso19794.IrisInfo;

/**
 * File structure for the EF_DG4 file.
 * Based on ISO/IEC 19794-6.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision$
 */
public class DG4File extends CBEFFDataGroup {

  private static final long serialVersionUID = -1290365855823447586L;

  private static final ISO781611Decoder<BiometricDataBlock> DECODER = new ISO781611Decoder<BiometricDataBlock>(new BiometricDataBlockDecoder<BiometricDataBlock>() {
    public BiometricDataBlock decode(InputStream inputStream, StandardBiometricHeader sbh, int index, int length) throws IOException {
      return new IrisInfo(sbh, inputStream);
    }
  });

  private static final ISO781611Encoder<BiometricDataBlock> ENCODER = new ISO781611Encoder<BiometricDataBlock>(new BiometricDataBlockEncoder<BiometricDataBlock>() {
    public void encode(BiometricDataBlock info, OutputStream outputStream) throws IOException {
      if (info instanceof IrisInfo) {
        ((IrisInfo)info).writeObject(outputStream);
      }
    }
  });

  /**
   * Creates a new file with the specified records.
   *
   * @param irisInfos records
   */
  public DG4File(List<IrisInfo> irisInfos) {
    this(irisInfos, true);
  }

  /**
   * Creates a new file with the specified records.
   *
   * @param irisInfos records
   * @param shouldAddRandomDataIfEmpty indicates whether the encoder should add random data when no templates are present
   */
  public DG4File(List<IrisInfo> irisInfos, boolean shouldAddRandomDataIfEmpty) {
    super(EF_DG4_TAG, fromIrisInfos(irisInfos), shouldAddRandomDataIfEmpty);
    this.shouldAddRandomDataIfEmpty = shouldAddRandomDataIfEmpty;
  }

  /**
   * Constructs a new file based on an input stream.
   *
   * @param inputStream an input stream
   *
   * @throws IOException on error reading from input stream
   */
  public DG4File(InputStream inputStream) throws IOException {
    super(EF_DG4_TAG, inputStream, false);
  }

  @Override
  public ISO781611Decoder<BiometricDataBlock> getDecoder() {
    return DECODER;
  }

  @Override
  public ISO781611Encoder<BiometricDataBlock> getEncoder() {
    return ENCODER;
  }

  /**
   * Returns a textual representation of this file.
   *
   * @return a textual representation of this file
   */
  @Override
  public String toString() {
    return "DG4File [" + super.toString() + "]";
  }

  /**
   * Returns the embedded iris infos in this file.
   *
   * @return iris infos
   */
  public List<IrisInfo> getIrisInfos() {
    return toIrisInfos(getSubRecords());
  }

  /**
   * Adds an iris info to this file.
   *
   * @param irisInfo an iris info
   */
  public void addIrisInfo(IrisInfo irisInfo) {
    add(irisInfo);
  }

  /**
   * Removes an iris info from this file.
   *
   * @param index the index of the iris info to remove
   */
  public void removeIrisInfo(int index) {
    remove(index);
  }

  @Override
  public int hashCode() {
    int result = super.hashCode();
    result = 31 * result + (shouldAddRandomDataIfEmpty ? 1231 : 1237);
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

    DG4File other = (DG4File)obj;
    return shouldAddRandomDataIfEmpty == other.shouldAddRandomDataIfEmpty;
  }

  private static List<BiometricDataBlock> fromIrisInfos(List<IrisInfo> irisInfos) {
    if (irisInfos == null) {
      return null;
    }

    List<BiometricDataBlock> records = new ArrayList<BiometricDataBlock>(irisInfos.size());
    for (IrisInfo irisInfo: irisInfos) {
      records.add(irisInfo);
    }

    return records;
  }

  private static List<IrisInfo> toIrisInfos(List<BiometricDataBlock> records) {
    if (records == null) {
      return null;
    }

    List<IrisInfo> irisInfos = new ArrayList<IrisInfo>(records.size());
    for (BiometricDataBlock record: records) {
      if (record instanceof IrisInfo) {
        irisInfos.add((IrisInfo)record);
      }
    }
    return irisInfos;
  }
}
