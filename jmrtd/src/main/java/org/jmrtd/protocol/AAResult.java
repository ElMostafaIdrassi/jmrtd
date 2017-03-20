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
 * $Id$
 */

package org.jmrtd.protocol;

import java.io.Serializable;
import java.security.PublicKey;
import java.util.Arrays;

import org.jmrtd.Util;

import net.sf.scuba.util.Hex;

/**
 * Result from Active Authentication protocol.
 * 
 * @author The JMRTD team
 *
 * @version $Revision$
 */
public class AAResult implements Serializable {

  private static final long serialVersionUID = 8800803919646625713L;

  private PublicKey publicKey;
  private String digestAlgorithm;
  private String signatureAlgorithm;
  private byte[] challenge;
  private byte[] response;

  public AAResult(PublicKey publicKey, String digestAlgorithm, String signatureAlgorithm, byte[] challenge, byte[] response) {
    this.publicKey = publicKey;
    this.digestAlgorithm = digestAlgorithm;
    this.signatureAlgorithm = signatureAlgorithm;
    this.challenge = challenge;
    this.response = response;
  }

  public byte[] getChallenge() {
    return challenge;
  }

  public byte[] getResponse() {
    return response;
  }

  public PublicKey getPublicKey() {
    return publicKey;
  }

  public String getDigestAlgorithm() {
    return digestAlgorithm;
  }

  public String getSignatureAlgorithm() {
    return signatureAlgorithm;
  }

  @Override
  public String toString() {
    return (new StringBuilder())
        .append("AAResult [")
        .append("publicKey: ").append(Util.getDetailedPublicKeyAlgorithm(publicKey))
        .append(", digestAlgorithm: ").append(digestAlgorithm)
        .append(", signatureAlgorithm: ").append(signatureAlgorithm)
        .append(", challenge: ").append(Hex.bytesToHexString(challenge))
        .append(", response: ").append(Hex.bytesToHexString(response))
        .toString();
  }

  @Override
  public int hashCode() {
    final int prime = 1991;
    int result = 1234567891;
    result = prime * result + Arrays.hashCode(challenge);
    result = prime * result + ((digestAlgorithm == null) ? 0 : digestAlgorithm.hashCode());
    result = prime * result + ((publicKey == null) ? 0 : publicKey.hashCode());
    result = prime * result + Arrays.hashCode(response);
    result = prime * result + ((signatureAlgorithm == null) ? 0 : signatureAlgorithm.hashCode());
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null) {
      return false;
    }
    if (getClass() != obj.getClass()) {
      return false;
    }

    AAResult other = (AAResult) obj;
    if (!Arrays.equals(challenge, other.challenge)) {
      return false;
    }
    if (digestAlgorithm == null) {
      if (other.digestAlgorithm != null) {
        return false;
      }
    } else if (!digestAlgorithm.equals(other.digestAlgorithm)) {
      return false;
    }
    if (publicKey == null) {
      if (other.publicKey != null) {
        return false;
      }
    } else if (!publicKey.equals(other.publicKey)) {
      return false;
    }
    if (!Arrays.equals(response, other.response)) {
      return false;
    }
    if (signatureAlgorithm == null) {
      if (other.signatureAlgorithm != null) {
        return false;
      }
    } else if (!signatureAlgorithm.equals(other.signatureAlgorithm)) {
      return false;
    }

    return true;
  }
}
