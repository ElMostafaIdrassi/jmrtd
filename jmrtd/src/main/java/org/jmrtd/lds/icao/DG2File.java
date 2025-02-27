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
import org.jmrtd.lds.iso19794.FaceInfo;
import org.jmrtd.lds.iso39794.FaceImageDataBlock;

import net.sf.scuba.tlv.TLVInputStream;

/**
 * File structure for the EF_DG2 file.
 * Datagroup 2 contains the facial features of the document holder.
 * See A 13.3 in MRTD's LDS document (or equivalent in Doc 9303).
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision$
 */
public class DG2File extends CBEFFDataGroup {

  private static final long serialVersionUID = 414300652684010416L;

  private static final ISO781611Decoder<BiometricDataBlock> DECODER = new ISO781611Decoder<BiometricDataBlock>(getDecoderMap());

  private static Map<Integer, BiometricDataBlockDecoder<BiometricDataBlock>> getDecoderMap() {
    Map<Integer, BiometricDataBlockDecoder<BiometricDataBlock>> decoders = new HashMap<Integer, BiometricDataBlockDecoder<BiometricDataBlock>>();

    /* 5F2E */
    decoders.put(ISO781611.BIOMETRIC_DATA_BLOCK_TAG, new BiometricDataBlockDecoder<BiometricDataBlock>() {
      public BiometricDataBlock decode(InputStream inputStream, StandardBiometricHeader sbh, int index, int length) throws IOException {
        return new FaceInfo(sbh, inputStream);
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
        return new FaceImageDataBlock(sbh, inputStream);
      }
    });
    return decoders;
  }

  private static final ISO781611Encoder<BiometricDataBlock> ISO_19794_ENCODER = new ISO781611Encoder<BiometricDataBlock>(new BiometricDataBlockEncoder<BiometricDataBlock>() {
    public void encode(BiometricDataBlock info, OutputStream outputStream) throws IOException {
      if (info instanceof FaceInfo) {
        ((FaceInfo)info).writeObject(outputStream);
      }
    }
  });

  /**
   * Creates a new file with the specified records.
   *
   * @param faceInfos records
   */
  public DG2File(List<FaceInfo> faceInfos) {
    super(EF_DG2_TAG, fromFaceInfos(faceInfos), false);
  }

  /**
   * Creates a new file based on an input stream.
   *
   * @param inputStream an input stream
   *
   * @throws IOException on error reading from input stream
   */
  public DG2File(InputStream inputStream) throws IOException {
    super(EF_DG2_TAG, inputStream, false);
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
    return "DG2File [" + super.toString() + "]";
  }

  /**
   * Returns the face infos embedded in this file.
   *
   * @return face infos
   */
  public List<FaceInfo> getFaceInfos() {
    return toFaceInfos(getSubRecords());
  }

  /**
   * Adds a face info to this file.
   *
   * @param faceInfo the face info to add
   *
   * @deprecated Will be removed.
   */
  @Deprecated
  public void addFaceInfo(FaceInfo faceInfo) {
    add(faceInfo);
  }

  /**
   * Removes a face info from this file.
   *
   * @param index the index of the face info to remove
   *
   * @deprecated Will be removed.
   */
  @Deprecated
  public void removeFaceInfo(int index) {
    remove(index);
  }

  private static List<BiometricDataBlock> fromFaceInfos(List<FaceInfo> faceInfos) {
    if (faceInfos == null) {
      return null;
    }

    List<BiometricDataBlock> records = new ArrayList<BiometricDataBlock>(faceInfos.size());
    for (FaceInfo faceInfo: faceInfos) {
      records.add(faceInfo);
    }

    return records;
  }

  private static List<FaceInfo> toFaceInfos(List<BiometricDataBlock> records) {
    if (records == null) {
      return null;
    }

    List<FaceInfo> faceInfos = new ArrayList<FaceInfo>(records.size());
    for (BiometricDataBlock record: records) {
      if (record instanceof FaceInfo) {
        faceInfos.add((FaceInfo)record);
      }
    }
    return faceInfos;
  }
}
