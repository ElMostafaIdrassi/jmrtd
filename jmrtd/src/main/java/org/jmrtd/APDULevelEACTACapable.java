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

package org.jmrtd;

import net.sf.scuba.smartcards.APDUWrapper;
import net.sf.scuba.smartcards.CardServiceException;

/**
 * The low-level capability of sending APDUs for the (EAC) Terminal Authentication protocol.
 * 
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision$
 */
public interface APDULevelEACTACapable {

  void sendMSESetDST(APDUWrapper wrapper, byte[] data) throws CardServiceException;
  
  void sendPSOExtendedLengthMode(APDUWrapper wrapper, byte[] certBodyData, byte[] certSignatureData) throws CardServiceException;
  
  void sendMSESetATExtAuth(APDUWrapper wrapper, byte[] data) throws CardServiceException;
  
  byte[] sendGetChallenge(APDUWrapper wrapper) throws CardServiceException;
  
  void sendMutualAuthenticate(APDUWrapper wrapper, byte[] signature) throws CardServiceException;
}
