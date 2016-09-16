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
 * $Id$
 */

package org.jmrtd.protocol;

import java.io.Serializable;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import org.jmrtd.SecureMessagingWrapper;
import org.jmrtd.lds.PACEInfo.MappingType;

import net.sf.scuba.util.Hex;

/**
 * Result of PACE protocol.
 * 
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision$
 */
public class PACEResult implements Serializable {
  
  private static final long serialVersionUID = -6819675856205885052L;
  
  private MappingType mappingType;
  private String agreementAlg;
  private String cipherAlg;
  private String digestAlg;
  private int keyLength;
  
  private AlgorithmParameterSpec staticParams;
  
  private byte[] piccNonce;
  private AlgorithmParameterSpec ephemeralParams;
  private KeyPair pcdKeyPair;
  private PublicKey piccPublicKey;
  private byte[] sharedSecretBytes;
  
  /* Only used for PACE-CAM. */
  private byte[] encryptedChipAuthenticationData;
  private byte[] chipAuthenticationData;
  
  private SecureMessagingWrapper wrapper;
  
  public PACEResult(MappingType mappingType, String agreementAlg, String cipherAlg, String digestAlg, int keyLength,
      AlgorithmParameterSpec staticParams,
      byte[] piccNonce, AlgorithmParameterSpec ephemeralParams, KeyPair pcdKeyPair, PublicKey piccPublicKey,
      byte[] sharedSecretBytes, byte[] encryptedChipAuthenticationData, byte[] chipAuthenticationData, SecureMessagingWrapper wrapper) {
    this.mappingType = mappingType;
    this.agreementAlg = agreementAlg;
    this.cipherAlg = cipherAlg;
    this.digestAlg = digestAlg;
    this.keyLength = keyLength;
    this.staticParams = staticParams;
    this.piccNonce = piccNonce;
    this.ephemeralParams = ephemeralParams;
    this.pcdKeyPair = pcdKeyPair;
    this.piccPublicKey = piccPublicKey;
    this.sharedSecretBytes = sharedSecretBytes;
    this.encryptedChipAuthenticationData = encryptedChipAuthenticationData;
    this.chipAuthenticationData = chipAuthenticationData;
    this.wrapper = wrapper;
  }
  
  public SecureMessagingWrapper getWrapper() {
    return wrapper;
  }
  
  public MappingType getMappingType() {
    return mappingType;
  }
  
  public String getAgreementAlg() {
    return agreementAlg;
  }
  
  public String getCipherAlg() {
    return cipherAlg;
  }
  
  public String getDigestAlg() {
    return digestAlg;
  }
  
  public void setDigestAlg(String digestAlg) {
    this.digestAlg = digestAlg;
  }
  
  public int getKeyLength() {
    return keyLength;
  }
  
  public AlgorithmParameterSpec getStaticParams() {
    return staticParams;
  }
  
  public byte[] getPICCNonce() {
    return piccNonce;
  }
  
  public AlgorithmParameterSpec getEphemeralParams() {
    return ephemeralParams;
  }
  
  public KeyPair getPCDKeyPair() {
    return pcdKeyPair;
  }
  
  public PublicKey getPICCPublicKey() {
    return piccPublicKey;
  }
  
  public byte[] getSharedSecretBytes() {
    return sharedSecretBytes;
  }
  
  public byte[] getEncryptedChipAuthenticationData() {
    return encryptedChipAuthenticationData;
  }
  
  public byte[] getChipAuthenticationData() {
    return chipAuthenticationData;
  }
  
  @Override
  public String toString() {
    return (new StringBuilder())
        .append("PACEResult [mappingType: ").append(mappingType)
        .append(", agreementAlg: " + agreementAlg)
        .append(", cipherAlg: " + cipherAlg)
        .append(", digestAlg: " + digestAlg)
        .append(", keyLength: " + keyLength)
        .append(", staticParams: " + staticParams)
        .append(", piccNonce: " + Arrays.toString(piccNonce))
        .append(", ephemeralParams: " + ephemeralParams)
        .append(", pcdKeyPair: " + pcdKeyPair)
        .append(", piccPublicKey: " + piccPublicKey)
        .append(", sharedSecretBytes: " + Hex.bytesToHexString(sharedSecretBytes))
        .append(", encryptedChipAuthenticationData: " + Hex.bytesToHexString(encryptedChipAuthenticationData))
        .append(", chipAuthenticationData: " + Hex.bytesToHexString(chipAuthenticationData))
        .toString();    
  }
  
  @Override
  public int hashCode() {
    final int prime = 1991;
    int result = 11;
    result = prime * result + ((agreementAlg == null) ? 0 : agreementAlg.hashCode());
    result = prime * result + Arrays.hashCode(chipAuthenticationData);
    result = prime * result + ((cipherAlg == null) ? 0 : cipherAlg.hashCode());
    result = prime * result + ((digestAlg == null) ? 0 : digestAlg.hashCode());
    result = prime * result + Arrays.hashCode(encryptedChipAuthenticationData);
    result = prime * result + ((ephemeralParams == null) ? 0 : ephemeralParams.hashCode());
    result = prime * result + keyLength;
    result = prime * result + ((mappingType == null) ? 0 : mappingType.hashCode());
    result = prime * result + ((pcdKeyPair == null) ? 0 : pcdKeyPair.hashCode());
    result = prime * result + Arrays.hashCode(piccNonce);
    result = prime * result + ((piccPublicKey == null) ? 0 : piccPublicKey.hashCode());
    result = prime * result + Arrays.hashCode(sharedSecretBytes);
    result = prime * result + ((staticParams == null) ? 0 : staticParams.hashCode());
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

    PACEResult other = (PACEResult)obj;
    if (agreementAlg == null) {
      if (other.agreementAlg != null) {
        return false;
      }
    } else if (!agreementAlg.equals(other.agreementAlg)) {
      return false;
    }
    if (!Arrays.equals(chipAuthenticationData, other.chipAuthenticationData)) {
      return false;
    }
    if (cipherAlg == null) {
      if (other.cipherAlg != null) {
        return false;
      }
    } else if (!cipherAlg.equals(other.cipherAlg)) {
      return false;
    }
    if (digestAlg == null) {
      if (other.digestAlg != null) {
        return false;
      }
    } else if (!digestAlg.equals(other.digestAlg)) {
      return false;
    }
    if (!Arrays.equals(encryptedChipAuthenticationData, other.encryptedChipAuthenticationData)) {
      return false;
    }
    if (ephemeralParams == null) {
      if (other.ephemeralParams != null) {
        return false;
      }
    } else if (!ephemeralParams.equals(other.ephemeralParams)) {
      return false;
    }
    if (keyLength != other.keyLength) {
      return false;
    }
    if (mappingType != other.mappingType) {
      return false;
    }
    if (pcdKeyPair == null) {
      if (other.pcdKeyPair != null) {
        return false;
      }
    } else if (!pcdKeyPair.equals(other.pcdKeyPair)) {
      return false;
    }
    if (!Arrays.equals(piccNonce, other.piccNonce)) {
      return false;
    }
    if (piccPublicKey == null) {
      if (other.piccPublicKey != null) {
        return false;
      }
    } else if (!piccPublicKey.equals(other.piccPublicKey)) {
      return false;
    }
    if (!Arrays.equals(sharedSecretBytes, other.sharedSecretBytes)) {
      return false;
    }
    if (staticParams == null) {
      if (other.staticParams != null) {
        return false;
      }
    } else if (!staticParams.equals(other.staticParams)) {
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
}
