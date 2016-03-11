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

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;

import org.jmrtd.ChipAuthenticationResult;
import org.jmrtd.PassportApduService;
import org.jmrtd.SecureMessagingWrapper;
import org.jmrtd.Util;

import net.sf.scuba.smartcards.CardServiceException;

/**
 * The EAC Chip Authentication protocol.
 * 
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: $
 * 
 * @since 0.5.6
 */
public class CAProtocol {
  
  private PassportApduService service;
  
  private SecureMessagingWrapper wrapper;
  
  public CAProtocol(PassportApduService service, SecureMessagingWrapper wrapper) {
    this.service = service;
    this.wrapper = wrapper;
  }
  
  /**
   * Perform CA (Chip Authentication) part of EAC (version 1). For details see TR-03110
   * ver. 1.11. In short, we authenticate the chip with (EC)DH key agreement
   * protocol and create new secure messaging keys.
   *
   * @param keyId passport's public key id (stored in DG14), -1 if none
   * @param publicKey passport's public key (stored in DG14)
   *
   * @return the chip authentication result
   *
   * @throws CardServiceException if CA failed or some error occurred
   */
  public ChipAuthenticationResult doCA(BigInteger keyId, PublicKey publicKey) throws CardServiceException {
    if (publicKey == null) { throw new IllegalArgumentException("Public key is null"); }
    try {
      String agreementAlg = Util.inferKeyAgreementAlgorithm(publicKey);
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(agreementAlg);
      AlgorithmParameterSpec params = null;
      if ("DH".equals(agreementAlg)) {
        DHPublicKey dhPublicKey = (DHPublicKey)publicKey;
        params = dhPublicKey.getParams();
      } else if ("ECDH".equals(agreementAlg)) {
        ECPublicKey ecPublicKey = (ECPublicKey)publicKey;
        params = ecPublicKey.getParams();
      } else {
        throw new IllegalStateException("Unsupported algorithm \"" + agreementAlg + "\"");
      }
      keyPairGenerator.initialize(params);
      KeyPair keyPair = keyPairGenerator.generateKeyPair();
      
      KeyAgreement agreement = KeyAgreement.getInstance(agreementAlg);
      agreement.init(keyPair.getPrivate());
      agreement.doPhase(publicKey, true);
      
      byte[] secret = agreement.generateSecret();
      
      // TODO: this SHA1ing may have to be removed?
      // TODO: this hashing is needed for our Java Card passport applet implementation
      // byte[] secret = md.digest(secret);
      
      byte[] keyData = null;
      byte[] idData = null;
      byte[] keyHash = new byte[0];
      if ("DH".equals(agreementAlg)) {
        DHPublicKey dhPublicKey = (DHPublicKey)keyPair.getPublic();
        keyData = dhPublicKey.getY().toByteArray();
        // TODO: this is probably wrong, what should be hashed?
        MessageDigest md = MessageDigest.getInstance("SHA1");
        md = MessageDigest.getInstance("SHA1");
        keyHash = md.digest(keyData);
      } else if ("ECDH".equals(agreementAlg)) {
        org.bouncycastle.jce.interfaces.ECPublicKey ecPublicKey = (org.bouncycastle.jce.interfaces.ECPublicKey)keyPair.getPublic();
        keyData = ecPublicKey.getQ().getEncoded();
        byte[] t = Util.i2os(ecPublicKey.getQ().getX().toBigInteger());
        keyHash = Util.alignKeyDataToSize(t, ecPublicKey.getParameters().getCurve().getFieldSize() / 8);
      }
      keyData = Util.wrapDO((byte)0x91, keyData);
      if (keyId.compareTo(BigInteger.ZERO) >= 0) {
        byte[] keyIdBytes = keyId.toByteArray();
        idData = Util.wrapDO((byte)0x84, keyIdBytes);
      }
      service.sendMSEKAT(wrapper, keyData, idData);
      

      return new ChipAuthenticationResult(keyId, publicKey, secret, keyHash, keyPair);
    } catch (GeneralSecurityException e) {
      throw new CardServiceException(e.toString());
    }
  }
}
