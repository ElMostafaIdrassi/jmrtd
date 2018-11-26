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

import java.util.logging.Level;
import java.util.logging.Logger;

import org.jmrtd.APDULevelAACapable;

import net.sf.scuba.smartcards.APDUWrapper;
import net.sf.scuba.smartcards.CardService;
import net.sf.scuba.smartcards.CardServiceException;
import net.sf.scuba.smartcards.CommandAPDU;
import net.sf.scuba.smartcards.ISO7816;
import net.sf.scuba.smartcards.ResponseAPDU;
import net.sf.scuba.util.Hex;

/**
 * A low-level APDU sender to support the Active Authentication protocol.
 *
 * @author The JMRTD team
 *
 * @version $Revision$
 *
 * @since 0.7.0
 */
public class AAAPDUSender implements APDULevelAACapable {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd.protocol");

  private SecureMessagingAPDUSender secureMessagingSender;

  /**
   * Creates an APDU sender for tranceiving Active Authentication protocol APDUs.
   *
   * @param service the card service for tranceiving APDUs
   */
  public AAAPDUSender(CardService service) {
    this.secureMessagingSender = new SecureMessagingAPDUSender(service);
  }

  /**
   * Sends an {@code INTERNAL AUTHENTICATE} command to the passport.
   * This is part of AA.
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

    /* Make a copy of the wrapper's state. */
    APDUWrapper copyOfWrapper = wrapper;
    try {
      if (wrapper instanceof SecureMessagingWrapper) {
        copyOfWrapper = SecureMessagingWrapper.getInstance((SecureMessagingWrapper)wrapper);
      }
    } catch (Exception e) {
      /* Never happens. */
      LOGGER.log(Level.WARNING, "Exception copying wrapper", e);
    }

    ResponseAPDU rapdu = null;
    short sw = -1;
    try {
      rapdu = secureMessagingSender.transmit(wrapper, capdu);
      sw = (short)rapdu.getSW();
    } catch (CardServiceException cse) {
      LOGGER.log(Level.INFO, "Exception during transmission of capdu = " + Hex.bytesToHexString(capdu.getBytes()), cse);
      sw = (short)cse.getSW();
    }


    if (sw == ISO7816.SW_NO_ERROR && rapdu != null) {
      return rapdu.getData();
    } else if ((sw & 0xFF00) == 0x6100) {
      /* Something is wrong with that length. Try different length. */
      capdu = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_INTERNAL_AUTHENTICATE, 0x00, 0x00, rndIFD, 65536);
      rapdu = secureMessagingSender.transmit(wrapper, capdu);
      return rapdu.getData();
    } else if ((sw & 0xFF00) == 0x6700) {
      /* Something is wrong with that length. Try different length and original wrapper. */
      capdu = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_INTERNAL_AUTHENTICATE, 0x00, 0x00, rndIFD, 65536);
      rapdu = secureMessagingSender.transmit(copyOfWrapper, capdu);
      return rapdu.getData();
    }

    throw new CardServiceException("Internal Authenticate failed", sw);
  }
}
