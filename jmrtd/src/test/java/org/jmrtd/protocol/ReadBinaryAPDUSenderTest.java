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

package org.jmrtd.protocol;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import org.jmrtd.ScriptedCardService;
import org.junit.Test;

import net.sf.scuba.smartcards.CardServiceException;
import net.sf.scuba.smartcards.CommandAPDU;
import net.sf.scuba.smartcards.ISO7816;
import net.sf.scuba.smartcards.ResponseAPDU;

public class ReadBinaryAPDUSenderTest {

  @Test
  public void encodesStandardAndSFIReads() throws Exception {
    ScriptedCardService standardService = new ScriptedCardService(response(new byte[] { 1, 2 }, ISO7816.SW_NO_ERROR));
    ReadBinaryAPDUSender standardSender = new ReadBinaryAPDUSender(new SecureMessagingAPDUSender(standardService));
    assertArrayEquals(new byte[] { 1, 2 },
        standardSender.sendReadBinary(null, 0, 0x1234, 2, false, false));
    CommandAPDU standard = standardService.getCommands().get(0);
    assertEquals(ISO7816.INS_READ_BINARY & 0xFF, standard.getINS());
    assertEquals(0x12, standard.getP1());
    assertEquals(0x34, standard.getP2());

    ScriptedCardService sfiService = new ScriptedCardService(response(new byte[] { 3 }, ISO7816.SW_NO_ERROR));
    ReadBinaryAPDUSender sfiSender = new ReadBinaryAPDUSender(new SecureMessagingAPDUSender(sfiService));
    assertArrayEquals(new byte[] { 3 },
        sfiSender.sendReadBinary(null, 0x81, 0x44, 1, true, false));
    CommandAPDU sfi = sfiService.getCommands().get(0);
    assertEquals(0x81, sfi.getP1());
    assertEquals(0x44, sfi.getP2());
  }

  @Test
  public void encodesAndDecodesLongRead() throws Exception {
    ScriptedCardService service = new ScriptedCardService(
        response(new byte[] { 0x53, 0x03, 0x21, 0x22, 0x23 }, ISO7816.SW_NO_ERROR));
    ReadBinaryAPDUSender sender = new ReadBinaryAPDUSender(new SecureMessagingAPDUSender(service));

    assertArrayEquals(new byte[] { 0x21, 0x22, 0x23 },
        sender.sendReadBinary(null, 0, 0x8123, 3, false, true));

    CommandAPDU command = service.getCommands().get(0);
    assertEquals(ISO7816.INS_READ_BINARY2 & 0xFF, command.getINS());
    assertArrayEquals(new byte[] { 0x54, 0x02, (byte)0x81, 0x23 }, command.getData());
    assertEquals(5, command.getNe());
  }

  @Test
  public void decodesLongFormResponseLengths() throws Exception {
    byte[] value128 = new byte[128];
    byte[] value256 = new byte[256];
    for (int i = 0; i < value128.length; i++) {
      value128[i] = (byte)i;
    }
    for (int i = 0; i < value256.length; i++) {
      value256[i] = (byte)i;
    }

    ScriptedCardService length81Service = new ScriptedCardService(
        response(tlvResponse(new byte[] { (byte)0x81, (byte)0x80 }, value128),
            ISO7816.SW_NO_ERROR));
    assertArrayEquals(value128, new ReadBinaryAPDUSender(new SecureMessagingAPDUSender(length81Service))
        .sendReadBinary(null, 0, 0, value128.length, false, true));

    ScriptedCardService length82Service = new ScriptedCardService(
        response(tlvResponse(new byte[] { (byte)0x82, 0x01, 0x00 }, value256),
            ISO7816.SW_NO_ERROR));
    assertArrayEquals(value256, new ReadBinaryAPDUSender(new SecureMessagingAPDUSender(length82Service))
        .sendReadBinary(null, 0, 0, value256.length, false, true));
  }

  @Test
  public void acceptsEndOfFileOnlyWhenItCarriesData() throws Exception {
    ScriptedCardService withData = new ScriptedCardService(
        response(new byte[] { 0x55 }, ISO7816.SW_END_OF_FILE));
    assertArrayEquals(new byte[] { 0x55 },
        new ReadBinaryAPDUSender(new SecureMessagingAPDUSender(withData)).sendReadBinary(null, 0, 0, 1, false, false));

    ScriptedCardService withoutData = new ScriptedCardService(response(ISO7816.SW_END_OF_FILE));
    assertThrows(CardServiceException.class,
        () -> new ReadBinaryAPDUSender(new SecureMessagingAPDUSender(withoutData)).sendReadBinary(null, 0, 0, 1, false, false));
  }

  @Test
  public void rejectsMalformedLongReadResponses() {
    assertMalformed(new byte[0]);
    assertMalformed(new byte[] { 0x53 });
    assertMalformed(new byte[] { 0x53, (byte)0x81 });
    assertMalformed(new byte[] { 0x53, 0x02, 0x01 });
    assertMalformed(new byte[] { 0x52, 0x00 });
    assertMalformed(new byte[] { 0x53, (byte)0x81, 0x01, 0x01 });
    assertMalformed(new byte[] { 0x53, (byte)0x82, 0x00, (byte)0x80 });
    assertMalformed(new byte[] {
        0x53, (byte)0x84, (byte)0x80, 0x00, 0x00, 0x00 });
    assertMalformed(new byte[] { 0x53, 0x01, 0x01, 0x02 });
  }

  private static byte[] tlvResponse(byte[] encodedLength, byte[] value) {
    byte[] result = new byte[1 + encodedLength.length + value.length];
    result[0] = 0x53;
    System.arraycopy(encodedLength, 0, result, 1, encodedLength.length);
    System.arraycopy(value, 0, result, 1 + encodedLength.length, value.length);
    return result;
  }

  private static void assertMalformed(byte[] data) {
    final ScriptedCardService service = new ScriptedCardService(response(data, ISO7816.SW_NO_ERROR));
    assertThrows(CardServiceException.class,
        () -> new ReadBinaryAPDUSender(new SecureMessagingAPDUSender(service)).sendReadBinary(null, 0, 0, 1, false, true));
  }

  private static ResponseAPDU response(short sw) {
    return response(new byte[0], sw);
  }

  private static ResponseAPDU response(byte[] data, short sw) {
    byte[] bytes = new byte[data.length + 2];
    System.arraycopy(data, 0, bytes, 0, data.length);
    bytes[bytes.length - 2] = (byte)(sw >> 8);
    bytes[bytes.length - 1] = (byte)sw;
    return new ResponseAPDU(bytes);
  }
}
