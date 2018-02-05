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

import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

public class PACEIMMappingResult extends PACEMappingResult {

  private static final long serialVersionUID = -6415752866407346050L;

  private byte[] pcdNonce;

  public PACEIMMappingResult(AlgorithmParameterSpec staticParameters, byte[] piccNonce, byte[] pcdNonce, AlgorithmParameterSpec ephemeralParameters) {
    super(staticParameters, piccNonce, ephemeralParameters);

    this.pcdNonce = null;
    if (pcdNonce != null) {
      this.pcdNonce = new byte[pcdNonce.length];
      System.arraycopy(pcdNonce, 0 , this.pcdNonce, 0, pcdNonce.length);
    }
  }

  public byte[] getPCDNonce() {
    return pcdNonce; // FIXME
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = super.hashCode();
    result = prime * result + Arrays.hashCode(pcdNonce);
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

    PACEIMMappingResult other = (PACEIMMappingResult) obj;
    return Arrays.equals(pcdNonce, other.pcdNonce);
  }
}