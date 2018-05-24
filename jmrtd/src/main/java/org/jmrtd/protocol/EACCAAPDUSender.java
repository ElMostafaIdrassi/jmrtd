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

package org.jmrtd.protocol;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jmrtd.APDULevelEACCACapable;
import org.jmrtd.Util;

import net.sf.scuba.smartcards.APDUWrapper;
import net.sf.scuba.smartcards.CardService;
import net.sf.scuba.smartcards.CardServiceException;
import net.sf.scuba.smartcards.CommandAPDU;
import net.sf.scuba.smartcards.ISO7816;
import net.sf.scuba.smartcards.ResponseAPDU;
import net.sf.scuba.tlv.TLVUtil;

/**
 * A low-level APDU sender to support the EAC-CA protocol.
 * 
 * @author The JMRTD team
 *
 * @version $Revision$
 * 
 * @since 0.7.0
 */
public class EACCAAPDUSender implements APDULevelEACCACapable {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd.protocol");
  
  /** The general Authenticate command is used to perform the PACE protocol. See Section 3.2.2 of SAC-TR 1.01. */
  private static final byte INS_BSI_GENERAL_AUTHENTICATE = (byte)0x86;
  
  private SecureMessagingAPDUSender secureMessagingSender;
  
  public EACCAAPDUSender(CardService service) {
    this.secureMessagingSender = new SecureMessagingAPDUSender(service);
  }
  
  /**
   * Sends an {@code INTERNAL AUTHENTICATE} command to the passport.
   * This is part of AA and possibly EAC-CA.
   *
   * @param wrapper secure messaging wrapper
   * @param rndIFD the challenge to send
   *
   * @return the response from the passport (status word removed)
   *
   * @throws CardServiceException on tranceive error
   */
  public synchronized byte[] sendInternalAuthenticate(APDUWrapper wrapper, byte[] rndIFD) throws CardServiceException {
    if (rndIFD == null || rndIFD.length != 8) {
      throw new IllegalArgumentException("rndIFD wrong length");
    }
    CommandAPDU capdu = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_INTERNAL_AUTHENTICATE, 0x00, 0x00, rndIFD, 256);
    ResponseAPDU rapdu = secureMessagingSender.transmit(wrapper, capdu);
    return rapdu.getData();
  }

  /**
   * The MSE KAT APDU, see EAC 1.11 spec, Section B.1.
   *
   * @param wrapper secure messaging wrapper
   * @param keyData key data object (tag 0x91)
   * @param idData key id data object (tag 0x84), can be null
   *
   * @throws CardServiceException on error
   */
  public synchronized void sendMSEKAT(APDUWrapper wrapper, byte[] keyData, byte[] idData) throws CardServiceException {
    byte[] data = new byte[keyData.length + ((idData != null) ? idData.length : 0)];
    System.arraycopy(keyData, 0, data, 0, keyData.length);
    if (idData != null) {
      System.arraycopy(idData, 0, data, keyData.length, idData.length);
    }

    CommandAPDU capdu = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_MSE, 0x41, 0xA6, data);
    ResponseAPDU rapdu = secureMessagingSender.transmit(wrapper, capdu);
    short sw = (short)rapdu.getSW();
    if (sw != ISO7816.SW_NO_ERROR) {
      throw new CardServiceException("Sending MSE KAT failed", sw);
    }
  }

  /* For Chip Authentication. We prefix 0x80 for OID and 0x84 for keyId. */
  /**
   * The  MSE Set AT for Chip Authentication.
   *
   * @param wrapper secure messaging wrapper
   * @param oid the OID
   * @param keyId the keyId or {@code null}
   *
   * @throws CardServiceException on error
   */
  public synchronized void sendMSESetATIntAuth(APDUWrapper wrapper, String oid, BigInteger keyId) throws CardServiceException {
    int p1 = 0x41;
    int p2 = 0xA4;
    //  int p2 = 0xA6;
    ResponseAPDU rapdu = null;
    if (keyId == null || keyId.compareTo(BigInteger.ZERO) < 0) {
      CommandAPDU capdu = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_MSE, p1, p2, Util.toOIDBytes(oid));
      rapdu = secureMessagingSender.transmit(wrapper, capdu);
    } else {
      byte[] oidBytes = Util.toOIDBytes(oid);
      byte[] keyIdBytes = TLVUtil.wrapDO(0x84, Util.i2os(keyId));
      ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
      try {
        byteArrayOutputStream.write(oidBytes);
        byteArrayOutputStream.write(keyIdBytes);
        byteArrayOutputStream.close();
      } catch (IOException ioe) {
        LOGGER.log(Level.WARNING, "Exception", ioe);
      }
      CommandAPDU capdu = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_MSE, p1, p2, byteArrayOutputStream.toByteArray());
      rapdu = secureMessagingSender.transmit(wrapper, capdu);
    }
    short sw = rapdu == null ? -1 : (short)rapdu.getSW();
    if (sw != ISO7816.SW_NO_ERROR) {
      throw new CardServiceException("Sending MSE AT failed", sw);
    }
  }

  /**
   * Sends a General Authenticate command.
   *
   * @param wrapper secure messaging wrapper
   * @param data data to be sent, without the {@code 0x7C} prefix (this method will add it)
   * @param isLast indicates whether this is the last command in the chain
   *
   * @return dynamic authentication data without the {@code 0x7C} prefix (this method will remove it)
   *
   * @throws CardServiceException on error
   */
  public synchronized byte[] sendGeneralAuthenticate(APDUWrapper wrapper, byte[] data, boolean isLast) throws CardServiceException {
    /* Tranceive APDU. */
    byte[] commandData = TLVUtil.wrapDO(0x7C, data); // FIXME: constant for 0x7C
    CommandAPDU capdu = new CommandAPDU(isLast ? ISO7816.CLA_ISO7816 : ISO7816.CLA_COMMAND_CHAINING, INS_BSI_GENERAL_AUTHENTICATE, 0x00, 0x00, commandData, 256);
    ResponseAPDU rapdu = secureMessagingSender.transmit(wrapper, capdu);

    /* Handle error status word. */
    short sw = (short)rapdu.getSW();
    if (sw != ISO7816.SW_NO_ERROR) {
      throw new CardServiceException("Sending general authenticate failed", sw);
    }
    byte[] responseData = rapdu.getData();
    responseData = TLVUtil.unwrapDO(0x7C, responseData);
    return responseData;
  }
}
