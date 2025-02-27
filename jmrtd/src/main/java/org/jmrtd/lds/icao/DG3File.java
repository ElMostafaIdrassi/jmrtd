/*
 * JMRTD - A Java API for accessing machine readable travel documents.
 *
 * Copyright (C) 2006 - 2017  The JMRTD team
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jmrtd.cbeff.BiometricDataBlock;
import org.jmrtd.cbeff.BiometricDataBlockDecoder;
import org.jmrtd.cbeff.BiometricDataBlockEncoder;
import org.jmrtd.cbeff.ISO781611;
import org.jmrtd.cbeff.ISO781611Decoder;
import org.jmrtd.cbeff.ISO781611Encoder;
import org.jmrtd.cbeff.StandardBiometricHeader;
import org.jmrtd.lds.CBEFFDataGroup;
import org.jmrtd.lds.iso19794.FingerInfo;
import org.jmrtd.lds.iso39794.FingerImageDataBlock;

import net.sf.scuba.tlv.TLVInputStream;

/**
 * File structure for the EF_DG3 file.
 * Partially specified in ISO/IEC FCD 19794-4 aka Annex F.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision$
 */
public class DG3File extends CBEFFDataGroup {

  private static final long serialVersionUID = -1037522331623814528L;

  private static final ISO781611Decoder<BiometricDataBlock> DECODER = new ISO781611Decoder<BiometricDataBlock>(getDecoderMap());

  private static Map<Integer, BiometricDataBlockDecoder<BiometricDataBlock>> getDecoderMap() {
    Map<Integer, BiometricDataBlockDecoder<BiometricDataBlock>> decoders = new HashMap<Integer, BiometricDataBlockDecoder<BiometricDataBlock>>();

    /* 5F2E */
    decoders.put(ISO781611.BIOMETRIC_DATA_BLOCK_TAG, new BiometricDataBlockDecoder<BiometricDataBlock>() {
      public BiometricDataBlock decode(InputStream inputStream, StandardBiometricHeader sbh, int index, int length) throws IOException {
        return new FingerInfo(sbh, inputStream);
      }
    });

    /* 7F2E */
    decoders.put(ISO781611.BIOMETRIC_DATA_BLOCK_CONSTRUCTED_TAG, new BiometricDataBlockDecoder<BiometricDataBlock>() {
      public BiometricDataBlock decode(InputStream inputStream, StandardBiometricHeader sbh, int index, int length) throws IOException {
        TLVInputStream tlvInputStream = inputStream instanceof TLVInputStream ? (TLVInputStream)inputStream : new TLVInputStream(inputStream);
        int tag = tlvInputStream.readTag(); // 0xA1
        if (tag != 0xA1) {
          /* ISO/IEC 39794-5 Application Profile for eMRTDs Version – 1.00: Table 2: Data Structure under DO7F2E. */
          LOGGER.warning("Expected tag A1, found " + Integer.toHexString(tag));
        }
        tlvInputStream.readLength();
        return new FingerImageDataBlock(sbh, inputStream);
      }
    });
    return decoders;
  }

  private static final ISO781611Encoder<BiometricDataBlock> ISO_19794_ENCODER = new ISO781611Encoder<BiometricDataBlock>(new BiometricDataBlockEncoder<BiometricDataBlock>() {
    public void encode(BiometricDataBlock info, OutputStream outputStream) throws IOException {
      if (info instanceof FingerInfo) {
        ((FingerInfo)info).writeObject(outputStream);
      }
    }
  });

  /**
   * Creates a new file with the specified records.
   *
   * @param fingerInfos records
   */
  public DG3File(List<FingerInfo> fingerInfos) {
    this(fingerInfos, true);
  }

  /**
   * Creates a new file with the specified records.
   *
   * @param fingerInfos records
   * @param shouldAddRandomDataIfEmpty whether to add random data when there are no records to encode
   */
  public DG3File(List<FingerInfo> fingerInfos, boolean shouldAddRandomDataIfEmpty) {
    super(EF_DG3_TAG, fromFingerInfos(fingerInfos), shouldAddRandomDataIfEmpty);
  }

  /**
   * Creates a new file based on an input stream.
   *
   * @param inputStream an input stream
   *
   * @throws IOException on error reading from input stream
   */
  public DG3File(InputStream inputStream) throws IOException {
    super(EF_DG3_TAG, inputStream, false);
  }

  @Override
  public ISO781611Decoder<BiometricDataBlock> getDecoder() {
    return DECODER;
  }

  @Override
  public ISO781611Encoder<BiometricDataBlock> getEncoder() {
    return ISO_19794_ENCODER;
  }

  /**
   * Returns a textual representation of this file.
   *
   * @return a textual representation of this file
   */
  @Override
  public String toString() {
    return "DG3File [" + super.toString() + "]";
  }

  /**
   * Returns the finger infos embedded in this file.
   *
   * @return finger infos
   */
  public List<FingerInfo> getFingerInfos() {
    return toFingerInfos(getSubRecords());
  }

  /**
   * Adds a finger info to this file.
   *
   * @param fingerInfo the finger info to add
   *
   * @deprecated Will be removed.
   */
  @Deprecated
   public void addFingerInfo(FingerInfo fingerInfo) {
    add(fingerInfo);
  }

  /**
   * Removes a finger info from this file.
   *
   * @param index the index of the finger info to remove
   *
   * @deprecated Will be removed.
   */
  @Deprecated
  public void removeFingerInfo(int index) {
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

    DG3File other = (DG3File)obj;
    return shouldAddRandomDataIfEmpty == other.shouldAddRandomDataIfEmpty;
  }

  private static List<BiometricDataBlock> fromFingerInfos(List<FingerInfo> fingerInfos) {
    if (fingerInfos == null) {
      return null;
    }

    List<BiometricDataBlock> records = new ArrayList<BiometricDataBlock>(fingerInfos.size());
    for (FingerInfo fingerInfo: fingerInfos) {
      records.add(fingerInfo);
    }

    return records;
  }

  private static List<FingerInfo> toFingerInfos(List<BiometricDataBlock> records) {
    if (records == null) {
      return null;
    }

    List<FingerInfo> FingerInfos = new ArrayList<FingerInfo>(records.size());
    for (BiometricDataBlock record: records) {
      if (record instanceof FingerInfo) {
        FingerInfos.add((FingerInfo)record);
      }
    }
    return FingerInfos;
  }
}
