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

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECPoint;

public class PACEGMWithECDHMappingResult extends PACEGMMappingResult {

  private static final long serialVersionUID = -3892431861957032423L;

  private BigInteger sharedSecretPointX;
  
  private BigInteger sharedSecretPointY;

  public PACEGMWithECDHMappingResult(AlgorithmParameterSpec staticParameters,
      byte[] piccNonce, PublicKey piccMappingPublicKey, KeyPair pcdMappingKeyPair, ECPoint sharedSecretPoint,
      AlgorithmParameterSpec ephemeralParameters) {
    super(staticParameters, piccNonce, piccMappingPublicKey, pcdMappingKeyPair, ephemeralParameters);
    this.sharedSecretPointX = sharedSecretPoint.getAffineX();
    this.sharedSecretPointY = sharedSecretPoint.getAffineY();
  }

  public ECPoint getSharedSecretPoint() {
    return new ECPoint(sharedSecretPointX, sharedSecretPointY);
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = super.hashCode();
    result = prime * result
        + ((sharedSecretPointX == null) ? 0 : sharedSecretPointX.hashCode())
        + ((sharedSecretPointY == null) ? 0 : sharedSecretPointY.hashCode());

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

    PACEGMWithECDHMappingResult other = (PACEGMWithECDHMappingResult) obj;
    if (sharedSecretPointX == null) {
      if (other.sharedSecretPointX != null) {
        return false;
      }
    } else if (!sharedSecretPointX.equals(other.sharedSecretPointX)) {
      return false;
    }

    if (sharedSecretPointY == null) {
      if (other.sharedSecretPointY != null) {
        return false;
      }
    } else if (!sharedSecretPointY.equals(other.sharedSecretPointY)) {
      return false;
    }

    return true;
  }
}
