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
import org.jmrtd.lds.iso19794.FingerInfo;
import org.jmrtd.lds.iso19794.IrisInfo;
import org.jmrtd.lds.iso39794.FingerImageDataBlock;
import org.jmrtd.lds.iso39794.IrisImageDataBlock;

import net.sf.scuba.tlv.TLVInputStream;
import net.sf.scuba.tlv.TLVOutputStream;

/**
 * File structure for the EF_DG4 file.
 * Based on ISO/IEC 19794-6 and ISO/IEC 39794-6.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision$
 */
public class DG4File extends CBEFFDataGroup {

  private static final long serialVersionUID = -1290365855823447586L;

  private static final ISO781611Decoder<BiometricDataBlock> DECODER = new ISO781611Decoder<BiometricDataBlock>(getDecoderMap());

  private static Map<Integer, BiometricDataBlockDecoder<BiometricDataBlock>> getDecoderMap() {
    Map<Integer, BiometricDataBlockDecoder<BiometricDataBlock>> decoders = new HashMap<Integer, BiometricDataBlockDecoder<BiometricDataBlock>>();

    /* 5F2E */
    decoders.put(ISO781611.BIOMETRIC_DATA_BLOCK_TAG, new BiometricDataBlockDecoder<BiometricDataBlock>() {
      public BiometricDataBlock decode(InputStream inputStream, StandardBiometricHeader sbh, int index, int length) throws IOException {
        return new IrisInfo(sbh, inputStream);
      }
    });

    /* 7F2E */
    decoders.put(ISO781611.BIOMETRIC_DATA_BLOCK_CONSTRUCTED_TAG, new BiometricDataBlockDecoder<BiometricDataBlock>() {
      public BiometricDataBlock decode(InputStream inputStream, StandardBiometricHeader sbh, int index, int length) throws IOException {
        if (sbh != null && sbh.hasFormatType(StandardBiometricHeader.ISO_19794_IRIS_IMAGE_FORMAT_TYPE_VALUE)) {
          return new IrisInfo(sbh, inputStream);
        }
        if (sbh != null && sbh.hasFormatType(StandardBiometricHeader.ISO_39794_IRIS_IMAGE_FORMAT_TYPE_VALUE)) {
          LOGGER.warning("Unexpected format type in standard biometric header, assuming ISO 39794 encoding");
        }
        TLVInputStream tlvInputStream = inputStream instanceof TLVInputStream ? (TLVInputStream)inputStream : new TLVInputStream(inputStream);
        int tag = tlvInputStream.readTag(); // 0xA1
        if (tag != ISO781611.BIOMETRIC_HEADER_TEMPLATE_BASE_TAG) {
          /* ISO/IEC 39794-5 Application Profile for eMRTDs Version – 1.00: Table 2: Data Structure under DO7F2E. */
          LOGGER.warning("Expected tag A1, found " + Integer.toHexString(tag));
        }
        tlvInputStream.readLength();
        return new IrisImageDataBlock(sbh, inputStream);
      }
    });

    return decoders;
  }

  private static final ISO781611Encoder<BiometricDataBlock> ISO_19794_ENCODER = new ISO781611Encoder<BiometricDataBlock>(new BiometricDataBlockEncoder<BiometricDataBlock>() {
    public void encode(BiometricDataBlock info, OutputStream outputStream) throws IOException {
      if (info instanceof IrisInfo) {
        ((IrisInfo)info).writeObject(outputStream);
      }
    }
  });

  private static final ISO781611Encoder<BiometricDataBlock> ISO_39794_ENCODER = new ISO781611Encoder<BiometricDataBlock>(new BiometricDataBlockEncoder<BiometricDataBlock>() {
    public void encode(BiometricDataBlock info, OutputStream outputStream) throws IOException {
      if (info instanceof IrisImageDataBlock) {
        TLVOutputStream tlvOutputStream = outputStream instanceof TLVOutputStream ? (TLVOutputStream)outputStream : new TLVOutputStream(outputStream);
        tlvOutputStream.writeTag(0xA1);
        tlvOutputStream.writeValue(((IrisImageDataBlock)info).getEncoded());
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
   *
   * @deprecated Use the corresponding factory method for ISO19794 instead
   */
  @Deprecated
  public DG4File(List<IrisInfo> irisInfos, boolean shouldAddRandomDataIfEmpty) {
    super(EF_DG4_TAG, BiometricEncodingType.ISO_19794, irisInfos, shouldAddRandomDataIfEmpty);
    this.shouldAddRandomDataIfEmpty = shouldAddRandomDataIfEmpty;
  }

  private DG4File(BiometricEncodingType encodingType, List<? extends BiometricDataBlock> dataBlocks, boolean shouldAddRandomDataIfEmpty) {
    super(EF_DG4_TAG, encodingType, dataBlocks, shouldAddRandomDataIfEmpty);
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

  public static DG4File createISO19794DG4File(List<IrisInfo> irisInfos) {
    return new DG4File(BiometricEncodingType.ISO_19794, irisInfos, false);
  }

  public static DG4File createISO39794DG4File(List<IrisImageDataBlock> irisImageDataBlocks) {
    return new DG4File(BiometricEncodingType.ISO_39794, irisImageDataBlocks, false);
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
    return "DG4File [" + super.toString() + "]";
  }

  /**
   * Returns the embedded iris infos in this file.
   *
   * @return iris infos
   *
   * @deprecated Use {@link #getSubRecords()} and check with {@code instanceof} instead
   */
  @Deprecated
  public List<IrisInfo> getIrisInfos() {
    return toIrisInfos(getSubRecords());
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
