/*
 * JMRTD - A Java API for accessing machine readable travel documents.
 *
 * Copyright (C) 2006 - 2016  The JMRTD team
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
 * $Id: $
 */

package org.jmrtd.protocol;

import java.security.PublicKey;
import java.util.logging.Logger;

import org.jmrtd.PassportService;
import org.jmrtd.SecureMessagingWrapper;

import net.sf.scuba.smartcards.CardServiceException;

/**
 * The Active Authentication protocol.
 * 
 * @author The JMRTD team (info@jmrtd.org)
 * 
 * @version $Revision: $
 *
 * @since 0.5.6
 */
public class AAProtocol {
  
  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");
  
  private PassportService service;
  
  private SecureMessagingWrapper wrapper;
  
  public AAProtocol(PassportService service, SecureMessagingWrapper wrapper) {
    this.service = service;
    this.wrapper = wrapper;
  }
  
  /**
   * Performs the <i>Active Authentication</i> protocol.
   *
   * @param publicKey the public key to use (usually read from the card)
   * @param digestAlgorithm the digest algorithm to use, or null
   * @param signatureAlgorithm signature algorithm
   * @param challenge challenge
   *
   * @return a boolean indicating whether the card was authenticated
   *
   * @throws CardServiceException on error
   */
  public AAResult doAA(PublicKey publicKey, String digestAlgorithm, String signatureAlgorithm, byte[] challenge) throws CardServiceException {
    try {
      if (challenge == null || challenge.length != 8) {
        throw new IllegalArgumentException("AA failed: bad challenge");
      }
      byte[] response = service.sendInternalAuthenticate(wrapper, challenge);     
      return new AAResult(publicKey, digestAlgorithm, signatureAlgorithm, challenge, response);
    } catch (IllegalArgumentException iae) {
      LOGGER.severe("Exception: " + iae.getMessage());
      throw new CardServiceException(iae.toString());
    }
  }
}
