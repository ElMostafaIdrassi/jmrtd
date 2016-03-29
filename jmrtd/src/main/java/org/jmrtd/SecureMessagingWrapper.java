/*
 * JMRTD - A Java API for accessing machine readable travel documents.
 *
 * Copyright (C) 2006 - 2015  The JMRTD team
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
 * $Id: SecureMessagingWrapper.java 1559 2014-11-14 12:46:26Z martijno $
 */

package org.jmrtd;

import javax.crypto.SecretKey;

import net.sf.scuba.smartcards.APDUWrapper;

/**
 * Secure messaging wrapper base class.
 *
 * @author The JMRTD team
 *
 * @version $Revision: $
 */
public abstract class SecureMessagingWrapper implements APDUWrapper {
  
  /**
   * Gets the send sequence counter.
   *
   * @return the send sequence counter
   */
  public abstract long getSendSequenceCounter();
  
  /**
   * Gets the shared key for encrypting APDU payloads.
   * 
   * @return the encryption key
   */
  public abstract SecretKey getEncryptionKey();

  /**
   * Get the shared key for computing message authentication codes over APDU payloads.
   * 
   * @return the MAC key
   */
  public abstract SecretKey getMACKey();
}
