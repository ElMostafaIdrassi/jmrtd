/*
 * JMRTD - A Java API for accessing machine readable travel documents.
 *
 * Copyright (C) 2006 - 2017  The JMRTD team
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
 * $Id: BACKey.java 1633 2016-09-16 14:52:25Z martijno $
 */

package org.jmrtd;

import java.security.spec.KeySpec;

/**
 * An access key specification for a card access number.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1633 $
 */
public class CANKey implements KeySpec {

  private String cardAccessNumber;

  /**
   * Constructs a key specification.
   * 
   * @param cardAccessNumber the card access number
   */
  public CANKey(String cardAccessNumber) {
    this.cardAccessNumber = cardAccessNumber;
  }

  /**
   * Gets the card access number.
   * 
   * @return the card access number
   */
  public String getCardAccessNumber() {
    return cardAccessNumber;
  }
}
