/*
 * JMRTD - A Java API for accessing machine readable travel documents.
 *
 * Copyright (C) 2006 - 2026  The JMRTD team
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

package org.jmrtd;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;

import net.sf.scuba.smartcards.APDUWrapper;
import net.sf.scuba.smartcards.CardServiceException;
import net.sf.scuba.smartcards.FileInfo;
import net.sf.scuba.smartcards.ISO7816;

/**
 * Tests file discovery, buffering, and APDU routing in {@link DefaultFileSystem}.
 */
public class DefaultFileSystemTest {

  @Test
  public void readsAndCachesSelectedFile() throws Exception {
    byte[] file = createTLVFile(0x61, 12);
    RecordingReadBinaryService service = new RecordingReadBinaryService();
    service.addFile(PassportService.EF_DG1, PassportService.SFI_DG1, file);
    DefaultFileSystem fileSystem = new DefaultFileSystem(service, false);

    fileSystem.selectFile(PassportService.EF_DG1);

    FileInfo[] selectedPath = fileSystem.getSelectedPath();
    assertEquals(1, selectedPath.length);
    assertEquals(PassportService.EF_DG1, selectedPath[0].getFID());
    assertEquals(file.length, selectedPath[0].getFileLength());
    assertArrayEquals(file, fileSystem.readBinary(0, file.length));
    assertEquals(1, service.selectedFIDs.size());
    assertEquals(2, service.requests.size());
    assertEquals(0, service.requests.get(0).offset);
    assertEquals(8, service.requests.get(1).offset);

    assertArrayEquals(file, fileSystem.readBinary(0, file.length));
    assertEquals("A buffered read should not result in another APDU", 2, service.requests.size());
  }

  @Test
  public void usesSFIWithoutSelectingFile() throws Exception {
    byte[] file = createTLVFile(0x61, 12);
    RecordingReadBinaryService service = new RecordingReadBinaryService();
    service.addFile(PassportService.EF_DG1, PassportService.SFI_DG1, file);
    DefaultFileSystem fileSystem = new DefaultFileSystem(service, true);

    fileSystem.selectFile(PassportService.EF_DG1);
    assertArrayEquals(file, fileSystem.readBinary(0, file.length));

    assertTrue(service.selectedFIDs.isEmpty());
    assertEquals(2, service.requests.size());
    for (ReadRequest request: service.requests) {
      assertTrue(request.isSFIEnabled);
      assertEquals(0x80 | PassportService.SFI_DG1, request.sfi);
      assertFalse(request.isTLVEncodedOffsetNeeded);
    }
  }

  @Test
  public void returnsOnlyBytesActuallyReceivedFromCard() throws Exception {
    byte[] file = createTLVFile(0x61, 12);
    RecordingReadBinaryService service = new RecordingReadBinaryService();
    service.addFile(PassportService.EF_DG1, PassportService.SFI_DG1, file);
    DefaultFileSystem fileSystem = new DefaultFileSystem(service, false);
    fileSystem.selectFile(PassportService.EF_DG1);
    service.maximumResponseLength = 3;

    assertArrayEquals(Arrays.copyOfRange(file, 8, 11), fileSystem.readBinary(8, 4));
    assertEquals(3, service.requests.get(1).responseLength);
  }

  @Test
  public void fallsBackToShortReadsAfterWrongLengthStatus() throws Exception {
    byte[] file = createTLVFile(0x61, 12);
    RecordingReadBinaryService service = new RecordingReadBinaryService();
    service.addFile(PassportService.EF_DG1, PassportService.SFI_DG1, file);
    DefaultFileSystem fileSystem = new DefaultFileSystem(service, false);
    fileSystem.selectFile(PassportService.EF_DG1);
    service.failNextReadWithWrongLength = true;

    assertArrayEquals(new byte[0], fileSystem.readBinary(8, 4));
    assertEquals(PassportService.DEFAULT_MAX_BLOCKSIZE, fileSystem.getMaxReadBinaryLength());

    assertArrayEquals(Arrays.copyOfRange(file, 8, 12), fileSystem.readBinary(8, 4));
  }

  @Test
  public void usesTLVEncodedReadForOffsetsAboveSignedShortRange() throws Exception {
    byte[] file = createTLVFile(0x61, 40006);
    RecordingReadBinaryService service = new RecordingReadBinaryService();
    service.addFile(PassportService.EF_DG1, PassportService.SFI_DG1, file);
    DefaultFileSystem fileSystem = new DefaultFileSystem(service, false);
    fileSystem.selectFile(PassportService.EF_DG1);

    assertArrayEquals(Arrays.copyOfRange(file, 33000, 33004), fileSystem.readBinary(33000, 4));
    assertTrue(service.requests.get(1).isTLVEncodedOffsetNeeded);
  }

  private static byte[] createTLVFile(int tag, int valueLength) {
    int lengthByteCount = valueLength < 128 ? 1 : valueLength < 256 ? 2 : 3;
    byte[] result = new byte[1 + lengthByteCount + valueLength];
    result[0] = (byte)tag;
    if (lengthByteCount == 1) {
      result[1] = (byte)valueLength;
    } else if (lengthByteCount == 2) {
      result[1] = (byte)0x81;
      result[2] = (byte)valueLength;
    } else {
      result[1] = (byte)0x82;
      result[2] = (byte)(valueLength >> 8);
      result[3] = (byte)valueLength;
    }
    for (int i = 1 + lengthByteCount; i < result.length; i++) {
      result[i] = (byte)i;
    }
    return result;
  }

  private static final class RecordingReadBinaryService implements APDULevelReadBinaryCapable {

    private final Map<Short, byte[]> filesByFID = new HashMap<Short, byte[]>();
    private final Map<Integer, byte[]> filesBySFI = new HashMap<Integer, byte[]>();
    private final List<Short> selectedFIDs = new ArrayList<Short>();
    private final List<ReadRequest> requests = new ArrayList<ReadRequest>();

    private short selectedFID;
    private int maximumResponseLength = Integer.MAX_VALUE;
    private boolean failNextReadWithWrongLength;

    public void addFile(short fid, byte sfi, byte[] contents) {
      filesByFID.put(fid, contents.clone());
      filesBySFI.put(0x80 | (sfi & 0xFF), contents.clone());
    }

    @Override
    public void sendSelectApplet(APDUWrapper wrapper, byte[] aid) {
      /* Not used by DefaultFileSystem. */
    }

    @Override
    public void sendSelectMF() {
      /* Not used by DefaultFileSystem. */
    }

    @Override
    public void sendSelectFile(APDUWrapper wrapper, short fid) throws CardServiceException {
      if (!filesByFID.containsKey(fid)) {
        throw new CardServiceException("Unknown FID " + Integer.toHexString(fid & 0xFFFF));
      }
      selectedFID = fid;
      selectedFIDs.add(fid);
    }

    @Override
    public byte[] sendReadBinary(APDUWrapper wrapper, int sfi, int offset, int le,
        boolean isSFIEnabled, boolean isTLVEncodedOffsetNeeded) throws CardServiceException {
      if (failNextReadWithWrongLength) {
        failNextReadWithWrongLength = false;
        throw new CardServiceException("Wrong length", ISO7816.SW_WRONG_LENGTH);
      }

      byte[] file = isSFIEnabled ? filesBySFI.get(sfi) : filesByFID.get(selectedFID);
      if (file == null) {
        throw new CardServiceException("No file selected");
      }

      int responseLength = Math.min(Math.min(le, maximumResponseLength), file.length - offset);
      ReadRequest request = new ReadRequest(
          sfi, offset, le, responseLength, isSFIEnabled, isTLVEncodedOffsetNeeded);
      requests.add(request);
      return Arrays.copyOfRange(file, offset, offset + responseLength);
    }
  }

  private static final class ReadRequest {

    private final int sfi;
    private final int offset;
    private final int responseLength;
    private final boolean isSFIEnabled;
    private final boolean isTLVEncodedOffsetNeeded;

    private ReadRequest(int sfi, int offset, int requestedLength, int responseLength,
        boolean isSFIEnabled, boolean isTLVEncodedOffsetNeeded) {
      this.sfi = sfi;
      this.offset = offset;
      this.responseLength = responseLength;
      this.isSFIEnabled = isSFIEnabled;
      this.isTLVEncodedOffsetNeeded = isTLVEncodedOffsetNeeded;
      if (requestedLength < responseLength) {
        throw new IllegalArgumentException("Response cannot exceed requested length");
      }
    }
  }
}
