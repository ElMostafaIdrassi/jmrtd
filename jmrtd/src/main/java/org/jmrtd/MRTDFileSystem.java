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

package org.jmrtd;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.Serializable;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import org.jmrtd.io.FragmentBuffer;
import org.jmrtd.io.FragmentBuffer.Fragment;
import org.jmrtd.lds.CVCAFile;

import net.sf.scuba.smartcards.CardServiceException;
import net.sf.scuba.smartcards.FileInfo;
import net.sf.scuba.smartcards.FileSystemStructured;
import net.sf.scuba.tlv.TLVInputStream;

/**
 * A file system for ICAO MRTDs.
 *
 * TODO: use maxBlockSize to fetch extra bytes in APDU when space left (e.g. first APDU after length determination will be 0xD7 instead of 0xDF
 * TODO: join fragments in addFragment that are next to each other (overlap 0, currently only on positive overlap)
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision$
 */
class MRTDFileSystem implements FileSystemStructured {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  /** Number of bytes to read at start of file to determine file length. */
  private static final int READ_AHEAD_LENGTH = 8;

  /** Indicates the file that is (or should be) selected. */
  private short selectedFID;

  /** Indicates whether we actually already sent the SELECT command to select <code>selectedFID</code>. */
  private boolean isSelected;

  private PassportService service;
  private Map<Short, MRTDFileInfo> fileInfos;

  /**
   * Creates a file system.
   *
   * @param service the card service
   */
  public MRTDFileSystem(PassportService service) {
    this.service = service;
    this.fileInfos = new HashMap<Short, MRTDFileInfo>();
    this.selectedFID = 0;
    this.isSelected = false;
  }

  /**
   * Gets the selected path.
   *
   * @return the path components
   *
   * @throws CardServiceException on error
   */
  public synchronized FileInfo[] getSelectedPath() throws CardServiceException {
    MRTDFileInfo fileInfo = getFileInfo();
    if (fileInfo == null) {
      return null;
    } else {
      return new MRTDFileInfo[] { fileInfo };
    }
  }

  /**
   * Selects a file.
   *
   * @param fid indicates the file to select
   *
   * @throws CardServiceException on error communicating over the service
   */
  /*
   * NOTE: This doesn't actually send a select file command. ReadBinary will do so
   * if needed.
   */
  public synchronized void selectFile(short fid) throws CardServiceException {
    if (selectedFID == fid) {
      return;
    }

    selectedFID = fid;
    isSelected = false;
  }

  /**
   * Reads a block of bytes.
   *
   * @param offset offset index
   * @param length the number of bytes to read
   *
   * @return a copy of the bytes read
   */
  public synchronized byte[] readBinary(int offset, int length) throws CardServiceException {
    MRTDFileInfo fileInfo = null;
    try {
      if (selectedFID <= 0) {
        throw new CardServiceException("No file selected");
      }

      boolean isExtendedLength = (offset > 0x7FFF);
      if (!isSelected) {
        service.sendSelectFile(selectedFID);
        isSelected = true;
      }

      /* Check buffer to see if we already have some of the bytes. */
      fileInfo = getFileInfo();
      if (fileInfo == null) {
        throw new IllegalStateException("Could not get file info");
      }
      Fragment fragment = fileInfo.getSmallestUnbufferedFragment(offset, length);

      int responseLength = length;

      if (fragment.getLength() > 0) {
        byte[] bytes = service.sendReadBinary(fragment.getOffset(), fragment.getLength(), isExtendedLength);

        if (bytes != null && bytes.length > 0) {

          /* Update buffer with newly read bytes. */
          fileInfo.addFragment(fragment.getOffset(), bytes);

          /*
           * If we request a block of data, create the return buffer from the actual response length, not the requested Le.
           * The latter causes issues when the returned block has a one byte padding (only 0x80) which ends up being removed but
           * the length is not kept track of, leaving an unwanted 0-byte at the end of the data block, which now has a length
           * of Le, but actually contained Le - 1 data bytes.
           *
           * Bug reproduced using org.jmrtd.AESSecureMessagingWrapper with AES-256.
           */

          responseLength = bytes.length;
        }
      }
      /* Shrink wrap the bytes that are now buffered. */
      /* FIXME: that arraycopy looks costly, consider using dest array and offset params instead of byte[] result... -- MO */
      byte[] buffer = fileInfo.getBuffer();

      byte[] result = new byte[responseLength];
      System.arraycopy(buffer, offset, result, 0, responseLength);

      return result;
    } catch (CardServiceException cse) {
      throw new CardServiceException("Read binary failed on file " + (fileInfo == null ? Integer.toHexString(selectedFID) : fileInfo), cse, cse.getSW());
    } catch (Exception e) {
      throw new CardServiceException("Read binary failed on file " + (fileInfo == null ? Integer.toHexString(selectedFID) : fileInfo), e);
    }
  }

  /**
   * Gets the file info object for the currently selected file. If this
   * executes normally the result is non-null. If the file has not been
   * read before this will send a READ_BINARY to determine length.
   *
   * @return a non-null MRTDFileInfo
   *
   * @throws CardServiceException on error
   */
  private synchronized MRTDFileInfo getFileInfo() throws CardServiceException {
    if (selectedFID <= 0) {
      throw new CardServiceException("No file selected");
    }

    MRTDFileInfo fileInfo = fileInfos.get(selectedFID);

    /* If known file, use file info from cache. */
    if (fileInfo != null) {
      return fileInfo;
    }

    /* Not cached, actually read some bytes to determine file info. */
    try {
      if (!isSelected) {
        service.sendSelectFile(selectedFID);
        isSelected = true;
      }

      /*
       * Each passport file consists of a TLV structure, read ahead to determine length.
       * EF.CVCA is the exception and has a fixed length of CVCAFile.LENGTH.
       */
      byte[] prefix = service.sendReadBinary(0, READ_AHEAD_LENGTH, false);
      if (prefix == null || prefix.length != READ_AHEAD_LENGTH) {
        LOGGER.warning("Something is wrong with prefix, prefix = " + Arrays.toString(prefix));
        return null;
      }
      ByteArrayInputStream baInputStream = new ByteArrayInputStream(prefix);
      TLVInputStream tlvInputStream = new TLVInputStream(baInputStream);
      int fileLength = 0;
      int tag = tlvInputStream.readTag();
      if (tag == CVCAFile.CAR_TAG) {
        fileLength = CVCAFile.LENGTH;
      } else {
        int vLength = tlvInputStream.readLength();
        int tlLength = prefix.length - baInputStream.available(); /* NOTE: we're using a specific property of ByteArrayInputStream's available method here! */
        fileLength = tlLength + vLength;
      }
      fileInfo = new MRTDFileInfo(selectedFID, fileLength);
      fileInfo.addFragment(0, prefix);
      fileInfos.put(selectedFID, fileInfo);
      return fileInfo;
    } catch (IOException ioe) {
      throw new CardServiceException("Error getting file info for " + Integer.toHexString(selectedFID), ioe);
    }
  }

  private static class MRTDFileInfo extends FileInfo implements Serializable {

    private static final long serialVersionUID = 6727369753765119839L;

    private short fid;
    private FragmentBuffer buffer;

    /**
     * Constructs a file info.
     *
     * @param fid indicates which file
     * @param length length of the contents of the file
     */
    public MRTDFileInfo(short fid, int length) {
      this.fid = fid;
      this.buffer = new FragmentBuffer(length);
    }

    /**
     * Gets the buffer.
     *
     * @return the buffer
     */
    public byte[] getBuffer() {
      return buffer.getBuffer();
    }

    /**
     * Gets the file identifier.
     *
     * @return file identifier
     */
    @Override
    public short getFID() {
      return fid;
    }

    /**
     * Gets the length of the file.
     *
     * @return the length of the file
     */
    @Override
    public int getFileLength() {
      return buffer.getLength();
    }

    /**
     * Gets a textual representation of this file info.
     *
     * @return a textual representation of this file info
     */
    @Override
    public String toString() {
      return Integer.toHexString(fid);
    }

    /**
     * Gets the smallest unbuffered fragment included in <code>offset</code> and <code>offset + length - 1</code>.
     *
     * @param offset the offset
     * @param length the length
     *
     * @return a fragment smaller than or equal to the fragment indicated by <code>offset</code> and <code>length</code>
     */
    public Fragment getSmallestUnbufferedFragment(int offset, int length) {
      return buffer.getSmallestUnbufferedFragment(offset, length);
    }

    /**
     * Adds a fragment of bytes at a specific offset to this file.
     *
     * @param offset the offset
     * @param bytes the bytes
     */
    public void addFragment(int offset, byte[] bytes) {
      buffer.addFragment(offset, bytes);
    }
  }
}
