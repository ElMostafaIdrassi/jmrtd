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

import java.io.Serializable;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;

import org.jmrtd.SecureMessagingWrapper;
import org.jmrtd.Util;

import net.sf.scuba.util.Hex;

/**
 * Result of EAC Chip Authentication protocol.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: $
 */
public class CAResult implements Serializable {
  
  private static final long serialVersionUID = 4431711176589761513L;
  
  private BigInteger keyId;
  private PublicKey publicKey;
  private SecureMessagingWrapper wrapper;
  private byte[] keyHash;
  private KeyPair keyPair;
  
  /**
   * Creates a result.
   *
   * @param keyId the key identifier of the ICC's public key or -1
   * @param publicKey the ICC's public key
   * @param keyHash the hash of the key
   * @param keyPair the key pair
   * @param wrapper secure messaging wrapper
   */
  public CAResult(BigInteger keyId, PublicKey publicKey, byte[] keyHash, KeyPair keyPair, SecureMessagingWrapper wrapper) {
    this.keyId = keyId;
    this.publicKey = publicKey;
    this.keyHash = keyHash;
    this.keyPair = keyPair;
    this.wrapper = wrapper;
  }
  
  /**
   * Gets the ICC's public key identifier
   *
   * @return the key id or -1
   */
  public BigInteger getKeyId() {
    return keyId;
  }
  
  /**
   * Gets the ICC's public key that was used as input to chip authentication protocol
   *
   * @return the public key
   */
  public PublicKey getPublicKey() {
    return publicKey;
  }
  
  public SecureMessagingWrapper getWrapper() {
    return wrapper;
  }
  
  @Override
  public String toString() {
    return (new StringBuilder())
        .append("CAResult [keyId: ").append(keyId)
        .append(", publicKey: ").append(publicKey)
        .append(", wrapper: ").append(wrapper)
        .append(", keyHash: ").append(Hex.bytesToHexString(keyHash))
        .append(", keyPair: ")
        .append(Util.getDetailedPublicKeyAlgorithm(keyPair.getPublic()))
        .append("]").toString();
  }
  
  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + Arrays.hashCode(keyHash);
    result = prime * result + ((keyId == null) ? 0 : keyId.hashCode());
    result = prime * result + ((keyPair == null) ? 0 : keyPair.hashCode());
    result = prime * result + ((publicKey == null) ? 0 : publicKey.hashCode());
    result = prime * result + ((wrapper == null) ? 0 : wrapper.hashCode());
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
    CAResult other = (CAResult) obj;
    if (!Arrays.equals(keyHash, other.keyHash)) {
      return false;
    }
    if (keyId == null) {
      if (other.keyId != null) {
        return false;
      }
    } else if (!keyId.equals(other.keyId)) {
      return false;
    }
    if (keyPair == null) {
      if (other.keyPair != null) {
        return false;
      }
    } else if (!keyPair.equals(other.keyPair)) {
      return false;
    }
    if (publicKey == null) {
      if (other.publicKey != null) {
        return false;
      }
    } else if (!publicKey.equals(other.publicKey)) {
      return false;
    }
    if (wrapper == null) {
      if (other.wrapper != null) {
        return false;
      }
    } else if (!wrapper.equals(other.wrapper)) {
      return false;
    }
    
    return true;
  }
  
  /**
   * Gets the hash of the key.
   *
   * @return the hash of the key
   */
  public byte[] getKeyHash() {
    return keyHash;
  }
  
  /**
   * The ephemeral key pair resulting from chip authentication.
   *
   * @return a key pair
   */
  public KeyPair getKeyPair() {
    return keyPair;
  }
}
