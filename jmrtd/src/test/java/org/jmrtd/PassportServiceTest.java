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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.Field;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.jmrtd.DefaultFileSystem;
import org.jmrtd.PassportService;
import org.jmrtd.protocol.DESedeSecureMessagingWrapper;
import org.jmrtd.protocol.SecureMessagingWrapper;
import org.junit.Test;

import net.sf.scuba.smartcards.ISO7816;
import net.sf.scuba.smartcards.ResponseAPDU;

public class PassportServiceTest {

  @Test
  public void openIsIdempotentAndCloseClearsSecureMessagingState() throws Exception {
    ScriptedCardService service = new ScriptedCardService();
    PassportService passportService = createPassportService(service);
    SecureMessagingWrapper wrapper = createWrapper();
    setSecureMessagingState(passportService, wrapper);

    passportService.open();
    passportService.open();
    assertTrue(passportService.isOpen());
    assertEquals(1, service.getOpenCount());
    assertSame(wrapper, passportService.getWrapper());

    passportService.close();

    assertFalse(passportService.isOpen());
    assertEquals(1, service.getCloseCount());
    assertNull(passportService.getWrapper());
    assertNull(getRootFileSystem(passportService).getWrapper());
    assertNull(getAppletFileSystem(passportService).getWrapper());
  }

  @Test
  public void selectingMasterFileClearsSecureMessagingState() throws Exception {
    ScriptedCardService service = new ScriptedCardService(
        new ResponseAPDU(new byte[] {
            (byte)(ISO7816.SW_NO_ERROR >> 8), (byte)ISO7816.SW_NO_ERROR }));
    PassportService passportService = createPassportService(service);
    setSecureMessagingState(passportService, createWrapper());

    passportService.sendSelectMF();

    assertNull(passportService.getWrapper());
    assertNull(getRootFileSystem(passportService).getWrapper());
    assertNull(getAppletFileSystem(passportService).getWrapper());
  }

  private static PassportService createPassportService(ScriptedCardService service) {
    return new PassportService(service, PassportService.NORMAL_MAX_TRANCEIVE_LENGTH,
        PassportService.DEFAULT_MAX_BLOCKSIZE, true, true);
  }

  private static SecureMessagingWrapper createWrapper() throws Exception {
    SecretKey encKey = new SecretKeySpec(
        new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
        "DESede");
    SecretKey macKey = new SecretKeySpec(
        new byte[] { 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 },
        "DESede");
    return new DESedeSecureMessagingWrapper(encKey, macKey, 256, true, 42L);
  }

  private static void setSecureMessagingState(PassportService passportService,
      SecureMessagingWrapper wrapper) throws Exception {
    Field wrapperField = PassportService.class.getDeclaredField("wrapper");
    wrapperField.setAccessible(true);
    wrapperField.set(passportService, wrapper);
    getRootFileSystem(passportService).setWrapper(wrapper);
    getAppletFileSystem(passportService).setWrapper(wrapper);
  }

  private static DefaultFileSystem getRootFileSystem(PassportService passportService)
      throws Exception {
    return getFileSystem(passportService, "rootFileSystem");
  }

  private static DefaultFileSystem getAppletFileSystem(PassportService passportService)
      throws Exception {
    return getFileSystem(passportService, "appletFileSystem");
  }

  private static DefaultFileSystem getFileSystem(PassportService passportService,
      String fieldName) throws Exception {
    Field fileSystemField = PassportService.class.getDeclaredField(fieldName);
    fileSystemField.setAccessible(true);
    return (DefaultFileSystem)fileSystemField.get(passportService);
  }
}
