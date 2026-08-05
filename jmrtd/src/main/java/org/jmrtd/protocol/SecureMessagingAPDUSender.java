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
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jmrtd.Util;
import org.jmrtd.WrappedAPDUEvent;

import net.sf.scuba.smartcards.APDUEvent;
import net.sf.scuba.smartcards.APDUListener;
import net.sf.scuba.smartcards.APDUWrapper;
import net.sf.scuba.smartcards.CardService;
import net.sf.scuba.smartcards.CardServiceException;
import net.sf.scuba.smartcards.CommandAPDU;
import net.sf.scuba.smartcards.ISO7816;
import net.sf.scuba.smartcards.ResponseAPDU;
import net.sf.scuba.util.Hex;

/**
 * An APDU sender for tranceiving wrapped APDUs.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision$
 *
 * @since 0.7.0
 */
public class SecureMessagingAPDUSender {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd.protocol");

  private CardService service;

  private int sequenceNumber;

  private final Collection<APDUListener> listeners = new ArrayList<APDUListener>();

  /**
   * Creates an APDU sender for tranceiving wrapped APDUs.
   *
   * <p>Callers should create a single instance per underlying card service and share it
   * (e.g. by constructor injection) between all senders wrapping that service, rather than
   * creating one instance per sender. That way there is exactly one internal listener
   * registered with the underlying service, and one sequence number / listener registry for
   * the whole session.</p>
   *
   * @param service the card service for tranceiving the APDUs
   */
  public SecureMessagingAPDUSender(final CardService service) {
    this.service = service;
    service.addAPDUListener(new APDUListener() {
      @Override
      public void exchangedAPDU(APDUEvent event) {
        /*
         * Keeps our sequence number in sync with scuba's. Never forwards to public listeners --
         * notifyExchangedAPDU is the single place that does that, exactly once per transmit(...)
         * call, so listeners never see both a raw and a wrapped notification for one exchange.
         */
        updateSequenceNumber(event.getSequenceNumber());
      }
    });
  }

  private synchronized void updateSequenceNumber(int seq) {
    if (seq > sequenceNumber) {
      sequenceNumber = seq;
    }
  }

  private synchronized int getCurrentSequenceNumber() {
    return sequenceNumber;
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

    int seq = getCurrentSequenceNumber();

    if (wrapper == null) {
      /*
       * Scuba's underlying card service already notified its own (private, internal-only)
       * listener of this exchange, to keep our sequence number in sync -- see the constructor.
       * Public listeners are only ever registered on this instance, not on the underlying
       * service, so we notify them here, using the same "RAW" type scuba itself uses.
       */
      notifyExchangedAPDU(new APDUEvent(this, "RAW", seq, commandAPDU, responseAPDU));
      return responseAPDU;
    }

    ResponseAPDU plainTextResponseAPDU = null;
    try {
      if ((sw & ISO7816.SW_WRONG_LENGTH) == ISO7816.SW_WRONG_LENGTH) {
        return responseAPDU;
      }
      if (responseAPDU.getBytes().length <= 2) {
        throw new CardServiceException("Exception during transmission of wrapped APDU"
            + ", C=" + Hex.bytesToHexString(plainCapdu.getBytes()), sw);
      }

      responseAPDU = wrapper.unwrap(responseAPDU);
      plainTextResponseAPDU = responseAPDU;
      return responseAPDU;
    } catch (CardServiceException cse) {
      throw cse;
    } catch (Exception e) {
      throw new CardServiceException("Exception during transmission of wrapped APDU"
          + ", C=" + Hex.bytesToHexString(plainCapdu.getBytes()), e, sw);
    } finally {
      /*
       * plainTextResponseAPDU is null here if wrapper.unwrap(...) was never reached
       * (SW_WRONG_LENGTH, short response, or an exception), so listeners can tell
       * "not unwrapped" apart from an actual plaintext response. -- MO
       */
      notifyExchangedAPDU(new WrappedAPDUEvent(this, wrapper.getType(), seq, plainCapdu, plainTextResponseAPDU, commandAPDU, rawRapdu));
    }
  }

  /**
   * Returns a boolean indicating whether extended length APDUs are supported.
   *
   * @return a boolean indicating whether extended length APDUs are supported
   */
  public boolean isExtendedAPDULengthSupported() {
    return service.isExtendedAPDULengthSupported();
  }

  /**
   * Determines whether an exception indicates a tag is lost event.
   *
   * @param e an exception
   *
   * @return whether the exception indicates a tag is lost event
   */
  public boolean isConnectionLost(Exception e) {
    return service.isConnectionLost(e);
  }

  /**
   * Adds a listener.
   *
   * @param l the listener to add
   */
  public synchronized void addAPDUListener(APDUListener l) {
    if (l != null && !listeners.contains(l)) {
      listeners.add(l);
    }
  }

  /**
   * Removes a listener.
   * If the specified listener is not present, this method has no effect.
   *
   * @param l the listener to remove
   */
  public synchronized void removeAPDUListener(APDUListener l) {
    listeners.remove(l);
  }

  /**
   * Returns the currently registered listeners.
   *
   * @return the currently registered listeners
   */
  public synchronized Collection<APDUListener> getAPDUListeners() {
    return new ArrayList<APDUListener>(listeners);
  }

  /**
   * Notifies listeners about APDU event.
   * Called exactly once per {@link #transmit(APDUWrapper, CommandAPDU)} call, so listeners never
   * see both a raw and a wrapped notification for the same exchange.
   *
   * @param event the APDU event
   */
  protected void notifyExchangedAPDU(APDUEvent event) {
    Collection<APDUListener> apduListeners = getAPDUListeners();
    if (apduListeners.isEmpty()) {
      return;
    }

    for (APDUListener listener: apduListeners) {
      listener.exchangedAPDU(event);
    }
  }

  /* EXPERIMENTAL CODE BELOW */

  /**
   * Sends a (lengthy) command APDU using command chaining as described in ISO 7816-4 5.3.3.
   *
   * @param commandAPDU the command APDU to send
   * @param chunkSize the maximum size of data within each APDU
   *
   * @return the resulting response APDUs that were received
   *
   * @throws CardServiceException on error while sending
   */
  private List<ResponseAPDU> sendUsingCommandChaining(CommandAPDU commandAPDU, int chunkSize) throws CardServiceException {
    byte[] data = commandAPDU.getData();
    List<byte[]> segments = Util.partition(chunkSize, data);
    List<ResponseAPDU> responseAPDUs = new ArrayList<ResponseAPDU>(segments.size());
    int index = 0;
    for (byte[] segment: segments) {
      boolean isLast = ++index >= segments.size();
      int cla = commandAPDU.getCLA();
      if (!isLast) {
        cla |= ISO7816.CLA_COMMAND_CHAINING;
      }
      CommandAPDU partialCommandAPDU = new CommandAPDU(cla, commandAPDU.getINS(), commandAPDU.getP1(), commandAPDU.getP2(), segment, commandAPDU.getNe());
      ResponseAPDU responseAPDU = service.transmit(partialCommandAPDU);
      responseAPDUs.add(responseAPDU);
    }

    return responseAPDUs;
  }

  /**
   * Response chaining as described in ISO 7816-4 Section 5.3.4.
   * This will send additional {@code GET RESPONSE} APDUs.
   *
   * @param wrapper a secure messaging wrapper
   * @param sw the status word of the first APDU, of which the first byte is {@code 0x61}
   * @param data the data of the first response APDU
   *
   * @return the total amount of data
   *
   * @throws CardServiceException on error while sending
   */
  private byte[] continueSendingUsingResponseChaining(APDUWrapper wrapper, short sw, byte[] data) throws CardServiceException {
    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
    try {
      while ((sw & 0xFF00) == 0x6100) {
        /* More bytes remaining. */
        byteArrayOutputStream.write(data);

        int remainingLength = sw & 0xFF;
        if (remainingLength <= 0) {
          break;
        }
        CommandAPDU capdu = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_GET_RESPONSE, 0x00, 0x00, remainingLength);
        ResponseAPDU rapdu = transmit(wrapper, capdu);
        data = rapdu.getData();
        sw = (short)rapdu.getSW();
      }

      return byteArrayOutputStream.toByteArray();
    } catch (IOException ioe) {
      /* NOTE: Unlikely, we can always write to in-memory stream. */
      throw new CardServiceException("Could not write to stream", ioe, sw);
    } finally {
      try {
        byteArrayOutputStream.close();
      } catch (IOException ioe) {
        LOGGER.log(Level.FINE, "Error closing stream", ioe);
      }
    }
  }
}
