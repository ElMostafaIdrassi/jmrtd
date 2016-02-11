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
 * $Id$
 */

package org.jmrtd;

import java.io.Serializable;
import java.security.spec.KeySpec;

/**
 * A BAC key.
 * 
 * @author The JMRTD team
 * 
 * @version $Revision$
 */
public interface BACKeySpec extends KeySpec, Serializable {
  
  /**
   * Gets the document number. This does not include a check digit.
   * 
   * @return the document number
   */
  String getDocumentNumber();
  
  /**
   * Gets the date of birth string.
   * 
   * @return a <i>yymmdd</i> string
   */
  String getDateOfBirth();
  
  /**
   * Gets the date of expiry string.
   * 
   * @return a <i>yymmdd</i> string
   */
  String getDateOfExpiry();
}
