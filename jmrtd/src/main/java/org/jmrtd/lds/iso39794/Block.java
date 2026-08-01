/*
 * JMRTD - A Java API for accessing machine readable travel documents.
 *
 * Copyright (C) 2006 - 2025  The JMRTD team
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

package org.jmrtd.lds.iso39794;

import java.io.IOException;
import java.io.Serializable;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1Encodable;

abstract class Block implements Serializable {

  private static final long serialVersionUID = -8585852930916738115L;

  protected static final Logger LOGGER = Logger.getLogger("org.jmrtd.lds.iso39794");

  abstract ASN1Encodable getASN1Object();

  ASN1Encodable getASN1Object(ISO39794EncodingProfile profile) {
    return getASN1Object();
  }

  public byte[] getEncoded() {
    return getEncoded(ISO39794EncodingProfile.BASE);
  }

  public byte[] getEncoded(ISO39794EncodingProfile profile) {
    try {
      if (profile == null) {
        throw new IllegalArgumentException("Encoding profile must not be null");
      }
      return getASN1Object(profile).toASN1Primitive().getEncoded("DER");
    } catch (IOException ioe) {
      LOGGER.log(Level.WARNING, "Error decoding", ioe);
      return null;
    }
  }

  @Override
  public abstract int hashCode();

  @Override
  public abstract boolean equals(Object other);
}
