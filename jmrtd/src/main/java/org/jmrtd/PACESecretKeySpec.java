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
 * $Id: $
 */

package org.jmrtd;

import javax.crypto.spec.SecretKeySpec;

/**
 * A key for PACE.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: $
 *
 * (Contributions by g.giorkhelidze.)
 */
public class PACESecretKeySpec extends SecretKeySpec implements AccessKeySpec {

  private static final long serialVersionUID = -5181060361947453857L;

  private byte keyReference;

  public PACESecretKeySpec(byte[] key, int offset, int len, String algorithm, byte paceKeyReference) {
    super(key, offset, len, algorithm);
    this.keyReference = paceKeyReference;
  }

  public PACESecretKeySpec(byte[] key, String algorithm, byte paceKeyReference) {
    super(key, algorithm);
    this.keyReference = paceKeyReference;
  }

  public byte getKeyReference() {
    return keyReference;
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = super.hashCode();
    result = prime * result + keyReference;
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (!super.equals(obj)) {
      return false;
    }
    if (getClass() != obj.getClass()) {
      return false;
    }

    PACESecretKeySpec other = (PACESecretKeySpec) obj;
    return keyReference == other.keyReference;
  }
}

