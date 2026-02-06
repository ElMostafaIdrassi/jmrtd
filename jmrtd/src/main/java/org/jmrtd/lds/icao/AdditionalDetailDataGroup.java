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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jmrtd.lds.DataGroup;

import net.sf.scuba.tlv.TLVInputStream;
import net.sf.scuba.tlv.TLVOutputStream;
import net.sf.scuba.tlv.TLVUtil;
import net.sf.scuba.util.Hex;

/**
 * Abstract superclass for DG11 and DG12.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision$
 */
abstract class AdditionalDetailDataGroup extends DataGroup {

  private static final long serialVersionUID = 8566312538928662931L;

  public static final int TAG_LIST_TAG = 0x5C;

  public static final int CONTENT_SPECIFIC_CONSTRUCTED_TAG = 0xA0; // 5F0F is always used inside A0 constructed object
  public static final int COUNT_TAG = 0x02; // Used in A0 constructed object to indicate single byte count of simple objects

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  public AdditionalDetailDataGroup(int tag) {
    super(EF_DG11_TAG);
  }

  /**
   * Constructs a file from binary representation.
   *
   * @param tag the datagroup tag
   * @param inputStream an input stream
   *
   * @throws IOException if reading fails
   */
  public AdditionalDetailDataGroup(int tag, InputStream inputStream) throws IOException {
    super(tag, inputStream);
  }

  /**
   * Returns the list of tags of fields actually present.
   *
   * @return list of tags
   */
  public abstract List<Integer> getTagPresenceList();

  protected abstract void readField(int expectedTag, TLVInputStream tlvInputStream) throws IOException;

  protected abstract void writeField(int tag, TLVOutputStream tlvOut) throws IOException;

  @Override
  protected void readContent(InputStream inputStream) throws IOException {
    TLVInputStream tlvInputStream = inputStream instanceof TLVInputStream ? (TLVInputStream)inputStream : new TLVInputStream(inputStream);
    List<Integer> tagList = readTagList(tlvInputStream);
    /* Now read the fields in order. */
    for (int t: tagList) {
      readField(t, tlvInputStream);
    }
  }


  @Override
  protected void writeContent(OutputStream out) throws IOException {
    TLVOutputStream tlvOut = out instanceof TLVOutputStream ? (TLVOutputStream)out : new TLVOutputStream(out);
    List<Integer> tagList = getTagPresenceList();
    writeTagList(tagList, tlvOut);
    for (int tag: tagList) {
      writeField(tag, tlvOut);
    }
  }

  protected static List<Integer> readTagList(TLVInputStream tlvInputStream) throws IOException {
    int tagListTag = tlvInputStream.readTag();
    if (tagListTag != TAG_LIST_TAG) {
      throw new IllegalArgumentException("Expected tag list in DG11");
    }

    int tagListLength = tlvInputStream.readLength();
    int tagListBytesRead = 0;

    byte[] tagListBytes = tlvInputStream.readValue();
    ByteArrayInputStream tagListBytesInputStream = new ByteArrayInputStream(tagListBytes);
    try {
      /* Find out which tags are present. */
      List<Integer> tagList = new ArrayList<Integer>();
      while (tagListBytesRead < tagListLength) {
        /* We're using another TLV inputstream every time to read each tag. */
        TLVInputStream anotherTLVInputStream = new TLVInputStream(tagListBytesInputStream);
        int tag = anotherTLVInputStream.readTag();
        tagListBytesRead += TLVUtil.getTagLength(tag);
        tagList.add(tag);
      }
      return tagList;
    } finally {
      tagListBytesInputStream.close();
    }
  }

  protected static void writeTagList(List<Integer> tags, TLVOutputStream tlvOut) throws IOException {
    tlvOut.writeTag(TAG_LIST_TAG);
    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
    for (int tag: tags) {
      TLVOutputStream anotherTLVOutputStream = new TLVOutputStream(byteArrayOutputStream);
      anotherTLVOutputStream.writeTag(tag);
    }
    tlvOut.writeValue(byteArrayOutputStream.toByteArray());
    tlvOut.writeValueEnd(); /* TAG_LIST_TAG */
  }

  protected static byte[] readBytes(TLVInputStream tlvInputStream) throws IOException {
    return tlvInputStream.readValue();
  }

  protected static void writeBytes(int tag, byte[] value, TLVOutputStream tlvOut) throws IOException {
    tlvOut.writeTag(tag);;
    if (value == null) {
      tlvOut.writeValue(new byte[] { });
    } else {
      tlvOut.writeValue(value);
    }
  }

  protected static String readString(TLVInputStream tlvIn) throws IOException {
    byte[] value = tlvIn.readValue();
    try {
      String field = new String(value, "UTF-8");
      return field.trim();
    } catch (UnsupportedEncodingException uee) {
      LOGGER.log(Level.WARNING, "Exception", uee);
      return new String(value).trim();
    }
  }

  protected static void writeString(int tag, String value, TLVOutputStream tlvOut) throws IOException {
    writeBytes(tag, value == null ? null : value.trim().getBytes("UTF-8"), tlvOut);
  }

  protected static String readFullDate(TLVInputStream tlvInputStream) throws IOException {
    byte[] value = tlvInputStream.readValue();
    String field = null;
    if (value.length == 4) {
      /* Either France or Belgium uses this encoding for dates. */
      field = Hex.bytesToHexString(value);
    } else {
      /* Assume length 8 yyyMMdd as per spec, or whatever was put in. */
      field = new String(value);
      try {
        field = new String(value, "UTF-8");
      } catch (UnsupportedEncodingException usee) {
        LOGGER.log(Level.WARNING, "Exception", usee);
      }
    }
    return field;
  }

  protected static List<String> readContentSpecificFieldsList(TLVInputStream tlvInputStream) throws IOException {
    int countTag = tlvInputStream.readTag();
    if (countTag != COUNT_TAG) {
      throw new IllegalArgumentException("Expected " + Integer.toHexString(COUNT_TAG) + ", found " + Integer.toHexString(countTag));
    }
    int countLength = tlvInputStream.readLength();
    if (countLength != 1) {
      throw new IllegalArgumentException("Expected length 1 count length, found " + countLength);
    }
    byte[] countValue = tlvInputStream.readValue();
    if (countValue == null || countValue.length != 1) {
      throw new IllegalArgumentException("Number of content specific fields should be encoded in single byte, found " + Arrays.toString(countValue));
    }
    int count = countValue[0] & 0xFF;
    List<String> list = new ArrayList<String>(count);
    for (int i = 0; i < count; i++) {
      int tag = tlvInputStream.readTag();
      /* int length = */ tlvInputStream.readLength();
      list.add(readString(tlvInputStream));
    }
    return list;
  }

  protected static void writeContentSpecificFieldsList(int tag, List<String> list, TLVOutputStream tlvOut) throws IOException {
    tlvOut.writeTag(CONTENT_SPECIFIC_CONSTRUCTED_TAG);
    tlvOut.writeTag(COUNT_TAG);
    tlvOut.write(list.size());
    tlvOut.writeValueEnd(); /* COUNT_TAG */
    for (String otherName: list) {
      tlvOut.writeTag(tag);
      tlvOut.writeValue(otherName.trim().getBytes("UTF-8"));
    }
    tlvOut.writeValueEnd(); /* CONTENT_SPECIFIC_CONSTRUCTED_TAG */
  }

  protected static List<String> readList(TLVInputStream tlvInputStream) throws IOException {
    String field = readString(tlvInputStream);
    List<String> list = new ArrayList<String>();
    String[] tokens = field.split("<", -1);
    for (String token: tokens) {
      list.add(token.trim());
    }
    return list;
  }

  protected static void writeList(int tag, List<String> list, TLVOutputStream tlvOut) throws IOException {
    tlvOut.writeTag(tag);
    boolean isFirstOne = true;
    if (list.isEmpty()) {
      tlvOut.writeValue(new byte[] { });
    } else {
      StringBuilder encodedString = new StringBuilder();
      for (String detail: list) {
        if (isFirstOne) {
          isFirstOne = false;
        } else {
          encodedString.append('<');
        }
        encodedString.append(detail.trim());
      }
      tlvOut.writeValue(encodedString.toString().getBytes("UTF-8"));
    }
  }
}
