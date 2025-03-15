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
import org.jmrtd.cbeff.BiometricEncodingType;
import org.jmrtd.cbeff.ISO781611;
import org.jmrtd.cbeff.ISO781611Decoder;
import org.jmrtd.cbeff.ISO781611Encoder;
import org.jmrtd.cbeff.StandardBiometricHeader;
import org.jmrtd.lds.CBEFFDataGroup;
import org.jmrtd.lds.iso19794.FaceInfo;
import org.jmrtd.lds.iso39794.FaceImageDataBlock;

import net.sf.scuba.tlv.TLVInputStream;
import net.sf.scuba.tlv.TLVOutputStream;

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

  private static final ISO781611Encoder<BiometricDataBlock> ISO_39794_ENCODER = new ISO781611Encoder<BiometricDataBlock>(new BiometricDataBlockEncoder<BiometricDataBlock>() {
    public void encode(BiometricDataBlock info, OutputStream outputStream) throws IOException {
      if (info instanceof FaceImageDataBlock) {
        TLVOutputStream tlvOutputStream = outputStream instanceof TLVOutputStream ? (TLVOutputStream)outputStream : new TLVOutputStream(outputStream);
        tlvOutputStream.writeTag(0xA1);
        tlvOutputStream.writeValue(((FaceImageDataBlock)info).getEncoded());
      }
    }
  });

  /**
   * Creates a new file with the specified records.
   *
   * @param faceInfos records
   *
   * @deprecated Use the corresponding factory method for ISO19794 instead
   */
  @Deprecated
  public DG2File(List<FaceInfo> faceInfos) {
    this(BiometricEncodingType.ISO_19794, faceInfos);
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

  private DG2File(BiometricEncodingType encodingType, List<? extends BiometricDataBlock> biometricDataBlocks) {
    super(EF_DG2_TAG, encodingType, biometricDataBlocks, false);
  }

  public static DG2File createISO19794DG2File(List<FaceInfo> faceInfos) {
    return new DG2File(BiometricEncodingType.ISO_19794, faceInfos);
  }

  public static DG2File createISO39794DG2File(List<FaceImageDataBlock> faceImageDataBlocks) {
    return new DG2File(BiometricEncodingType.ISO_39794, faceImageDataBlocks);
  }

  @Override
  public ISO781611Decoder<BiometricDataBlock> getDecoder() {
    return DECODER;
  }

  @Override
  public ISO781611Encoder<BiometricDataBlock> getEncoder() {
    if (encodingType == null) {
      return ISO_19794_ENCODER;
    }
    switch (encodingType) {
    case ISO_19794:
      return ISO_19794_ENCODER;
    case ISO_39794:
      return ISO_39794_ENCODER;
    default:
      return ISO_19794_ENCODER;
    }
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
   *
   * @deprecated Use {@link #getSubRecords()} and check with {@code instanceof} instead
   */
  @Deprecated
  public List<FaceInfo> getFaceInfos() {
    return toFaceInfos(getSubRecords());
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
