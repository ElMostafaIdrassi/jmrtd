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

import java.util.List;

import org.jmrtd.protocol.EACCAAPDUSender;
import org.jmrtd.ScriptedCardService;
import org.junit.Test;

import net.sf.scuba.smartcards.CommandAPDU;
import net.sf.scuba.smartcards.ISO7816;
import net.sf.scuba.smartcards.ResponseAPDU;

public class EACCAAPDUSenderTest {

  @Test
  public void retriesGeneralAuthenticateWithShortLength() throws Exception {
    ScriptedCardService service = new ScriptedCardService(
        response(ISO7816.SW_WRONG_LENGTH),
        response(new byte[] { 0x7C, 0x03, 0x01, 0x02, 0x03 }, ISO7816.SW_NO_ERROR));
    EACCAAPDUSender sender = new EACCAAPDUSender(service);

    byte[] result = sender.sendGeneralAuthenticate(null, new byte[] { 0x11, 0x22 }, 65536, true);

    assertArrayEquals(new byte[] { 0x01, 0x02, 0x03 }, result);
    List<CommandAPDU> commands = service.getCommands();
    assertEquals(2, commands.size());
    assertEquals(65536, commands.get(0).getNe());
    assertEquals(256, commands.get(1).getNe());
    assertArrayEquals(commands.get(0).getData(), commands.get(1).getData());
  }

  @Test
  public void usesCommandChainingClassForNonFinalSegment() throws Exception {
    ScriptedCardService service = new ScriptedCardService(
        response(new byte[] { 0x7C, 0x00 }, ISO7816.SW_NO_ERROR));
    EACCAAPDUSender sender = new EACCAAPDUSender(service);

    assertArrayEquals(new byte[0],
        sender.sendGeneralAuthenticate(null, new byte[] { 0x01 }, 256, false));

    CommandAPDU command = service.getCommands().get(0);
    assertEquals(ISO7816.CLA_COMMAND_CHAINING & 0xFF, command.getCLA());
    assertArrayEquals(new byte[] { 0x7C, 0x01, 0x01 }, command.getData());
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
