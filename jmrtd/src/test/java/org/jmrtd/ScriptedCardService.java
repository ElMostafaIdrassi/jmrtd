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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import net.sf.scuba.smartcards.CardService;
import net.sf.scuba.smartcards.CardServiceException;
import net.sf.scuba.smartcards.CommandAPDU;
import net.sf.scuba.smartcards.ResponseAPDU;

/**
 * Minimal card service which returns a predetermined sequence of response APDUs.
 */
public class ScriptedCardService extends CardService {

  private static final long serialVersionUID = 1L;

  private final List<ResponseAPDU> responses;
  private final List<CommandAPDU> commands;
  private int responseIndex;
  private int openCount;
  private int closeCount;
  private boolean open;

  public ScriptedCardService(ResponseAPDU... responses) {
    this.responses = new ArrayList<ResponseAPDU>(Arrays.asList(responses));
    this.commands = new ArrayList<CommandAPDU>();
  }

  @Override
  public void open() {
    open = true;
    openCount++;
  }

  @Override
  public boolean isOpen() {
    return open;
  }

  @Override
  public ResponseAPDU transmit(CommandAPDU commandAPDU) throws CardServiceException {
    commands.add(commandAPDU);
    if (responseIndex >= responses.size()) {
      throw new CardServiceException("No scripted response for command " + commands.size());
    }
    return responses.get(responseIndex++);
  }

  @Override
  public byte[] getATR() {
    return new byte[] { 0x3B, 0x00 };
  }

  @Override
  public boolean isConnectionLost(Exception exception) {
    return false;
  }

  @Override
  public void close() {
    open = false;
    closeCount++;
  }

  public List<CommandAPDU> getCommands() {
    return new ArrayList<CommandAPDU>(commands);
  }

  public int getOpenCount() {
    return openCount;
  }

  public int getCloseCount() {
    return closeCount;
  }
}
