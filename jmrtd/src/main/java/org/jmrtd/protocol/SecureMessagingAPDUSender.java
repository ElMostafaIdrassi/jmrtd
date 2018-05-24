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

import java.util.Collection;
import java.util.HashSet;

import org.jmrtd.WrappedAPDUEvent;

import net.sf.scuba.smartcards.APDUEvent;
import net.sf.scuba.smartcards.APDUListener;
import net.sf.scuba.smartcards.APDUWrapper;
import net.sf.scuba.smartcards.CardService;
import net.sf.scuba.smartcards.CardServiceException;
import net.sf.scuba.smartcards.CommandAPDU;
import net.sf.scuba.smartcards.ResponseAPDU;
import net.sf.scuba.util.Hex;

public class SecureMessagingAPDUSender {

  private CardService service;
  
  /** The apduListeners. */
  private Collection<APDUListener> apduListeners;

  private int apduCount;
  
  public SecureMessagingAPDUSender(CardService service) {
    this.service = service;
    this.apduListeners = new HashSet<APDUListener>();
    this.apduCount = 0;
  }
  
  /**
   * Transmits an APDU.
   *
   * @param wrapper the secure messaging wrapper
   * @param commandAPDU the APDU to send
   *
   * @return the APDU received from the PICC
   *
   * @throws CardServiceException if tranceiving failed
   */
  public ResponseAPDU transmit(APDUWrapper wrapper, CommandAPDU commandAPDU) throws CardServiceException {
    CommandAPDU plainCapdu = commandAPDU;
    if (wrapper != null) {
      commandAPDU = wrapper.wrap(commandAPDU);
    }
    ResponseAPDU responseAPDU = service.transmit(commandAPDU);
    ResponseAPDU rawRapdu = responseAPDU;
    short sw = (short)responseAPDU.getSW();
    if (wrapper == null) {
      notifyExchangedAPDU(new APDUEvent(this, "PLAIN", ++apduCount, commandAPDU, responseAPDU));
    } else {
      try {
        if (responseAPDU.getBytes().length <= 2) {
          throw new CardServiceException("Exception during transmission of wrapped APDU"
              + ", C=" + Hex.bytesToHexString(plainCapdu.getBytes()), sw);
        }

        responseAPDU = wrapper.unwrap(responseAPDU);
      } catch (CardServiceException cse) {
        throw cse;
      } catch (Exception e) {
        throw new CardServiceException("Exception during transmission of wrapped APDU"
            + ", C=" + Hex.bytesToHexString(plainCapdu.getBytes()), e, sw);
      } finally {
        notifyExchangedAPDU(new WrappedAPDUEvent(this, wrapper.getType(), ++apduCount, plainCapdu, responseAPDU, commandAPDU, rawRapdu));
      }
    }

    return responseAPDU;
  }
  
  /**
   * Adds a listener.
   *
   * @param l the listener to add
   */
  public void addAPDUListener(APDUListener l) {
    if (apduListeners != null && l != null) {
      apduListeners.add(l);
    }
  }

  /**
   * Removes a listener.
   * If the specified listener is not present, this method has no effect.
   *
   * @param l the listener to remove
   */
  public void removeAPDUListener(APDUListener l) {
    if (apduListeners != null) {
      apduListeners.remove(l);
    }
  }

  /**
   * Notifies listeners about APDU event.
   *
   * @param event the APDU event
   */
  protected void notifyExchangedAPDU(APDUEvent event) {
    if (apduListeners == null || apduListeners.isEmpty()) {
      return;
    }

    for (APDUListener listener: apduListeners) {
      listener.exchangedAPDU(event);
    }
  }
}
