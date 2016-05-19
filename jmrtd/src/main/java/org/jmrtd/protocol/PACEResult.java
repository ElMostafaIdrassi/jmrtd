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
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;

import org.jmrtd.SecureMessagingWrapper;
import org.jmrtd.lds.PACEInfo.MappingType;

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

}
