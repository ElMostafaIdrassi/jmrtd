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

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.logging.Logger;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;

import org.jmrtd.PassportService;
import org.jmrtd.Util;
import org.jmrtd.lds.ChipAuthenticationInfo;
import org.jmrtd.lds.ChipAuthenticationPublicKeyInfo;

import net.sf.scuba.smartcards.CardServiceException;

/**
 * The EAC Chip Authentication protocol.
 * 
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision$
 * 
 * @since 0.5.6
 */
public class CAProtocol {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  private PassportService service;

  private SecureMessagingWrapper wrapper;

  /**
   * Constructs a protocol instance.
   * 
   * @param service the card service
   * @param wrapper the existing secure messaging wrapper
   */
  public CAProtocol(PassportService service, SecureMessagingWrapper wrapper) {
    this.service = service;
    this.wrapper = wrapper;
  }

  /**
   * Perform CA (Chip Authentication) part of EAC (version 1). For details see TR-03110
   * ver. 1.11. In short, we authenticate the chip with DH or ECDH key agreement
   * protocol and create new secure messaging keys.
   * 
   * The newly established secure messaging wrapper is made available to the caller in
   * the result.
   *
   * @param keyId passport's public key id (stored in DG14), {@code null} if none
   * @param oid the object identifier indicating the Chip Authentication protocol
   * @param publicKeyOID the OID indicating the type of public key
   * @param piccPublicKey PICC's public key (stored in DG14)
   *
   * @return the chip authentication result
   *
   * @throws CardServiceException if CA failed or some error occurred
   */
  public CAResult doCA(BigInteger keyId, String oid, String publicKeyOID, PublicKey piccPublicKey) throws CardServiceException {
    if (piccPublicKey == null) {
      throw new IllegalArgumentException("PICC public key is null");
    }

    String agreementAlg = ChipAuthenticationInfo.toKeyAgreementAlgorithm(oid);
    if (agreementAlg == null) {
      throw new IllegalArgumentException("Unknown agreement algorithm");
    }
    if (!("ECDH".equals(agreementAlg) || "DH".equals(agreementAlg))) {
      throw new IllegalArgumentException("Unsupported agreement algorithm, expected ECDH or DH, found " + agreementAlg);  
    }

    if (oid == null) {
      oid = inferChipAuthenticationOIDfromPublicKeyOID(publicKeyOID);
    }

    try {
      AlgorithmParameterSpec params = null;
      if ("DH".equals(agreementAlg)) {
        DHPublicKey piccDHPublicKey = (DHPublicKey)piccPublicKey;
        params = piccDHPublicKey.getParams();
      } else if ("ECDH".equals(agreementAlg)) {
        ECPublicKey piccECPublicKey = (ECPublicKey)piccPublicKey;
        params = piccECPublicKey.getParams();
      }

      /* Generate the inspection system's ephemeral key pair. */
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(agreementAlg);
      keyPairGenerator.initialize(params);
      KeyPair pcdKeyPair = keyPairGenerator.generateKeyPair();
      PublicKey pcdPublicKey = pcdKeyPair.getPublic();
      PrivateKey pcdPrivateKey = pcdKeyPair.getPrivate();

      sendPublicKey(service, wrapper, oid, keyId, pcdPublicKey);

      byte[] keyHash = getKeyHash(agreementAlg, pcdPublicKey);

      byte[] sharedSecret = computeSharedSecret(agreementAlg, piccPublicKey, pcdPrivateKey);

      wrapper = restartSecureMessaging(oid, sharedSecret);

      return new CAResult(keyId, piccPublicKey, keyHash, pcdPublicKey, pcdPrivateKey, wrapper);
    } catch (GeneralSecurityException e) {
      throw new CardServiceException(e.toString());
    }
  }

  /**
   * Sends the PCD's public key to the PICC.
   * 
   * @param service the card service
   * @param wrapper the existing secure messaging wrapper
   * @param oid the Chip Authentication object identifier
   * @param keyId a key identifier or {@code null}
   * @param pcdPublicKey the public key to send
   * 
   * @throws CardServiceException on error
   */
  public static void sendPublicKey(PassportService service, SecureMessagingWrapper wrapper, String oid, BigInteger keyId, PublicKey pcdPublicKey) throws CardServiceException {
    String agreementAlg = ChipAuthenticationInfo.toKeyAgreementAlgorithm(oid);
    String cipherAlg = ChipAuthenticationInfo.toCipherAlgorithm(oid);

    byte[] keyData = getKeyData(agreementAlg, pcdPublicKey);

    if (cipherAlg.startsWith("DESede")) {
      byte[] idData = null;
      if (keyId != null) {
        byte[] keyIdBytes = keyId.toByteArray();
        idData = Util.wrapDO((byte)0x84, keyIdBytes); /* FIXME: Constant for 0x84. */
      }

      service.sendMSEKAT(wrapper, Util.wrapDO((byte)0x91, keyData), idData); /* FIXME: Constant for 0x91. */
    } else if (cipherAlg.startsWith("AES")) {
      service.sendMSESetATIntAuth(wrapper, oid, keyId);        
      service.sendGeneralAuthenticate(wrapper, Util.wrapDO((byte)0x80, keyData), true); /* FIXME: Constant for 0x80. */
    } else {
      throw new IllegalStateException("Cannot set up secure channel with cipher " + cipherAlg);
    }
  }

  /**
   * Does the key agreement step. Genereates a secret based on the PICC's public key and the PCD's private key.
   * 
   * @param agreementAlg the agreement algorithm
   * @param piccPublicKey the PICC's public key
   * @param pcdPrivateKey the PCD's private key
   * 
   * @return the shared secret
   * 
   * @throws NoSuchAlgorithmException if the agreement algorithm is unsupported
   * 
   * @throws InvalidKeyException if one of the keys is invalid
   */
  public static byte[] computeSharedSecret(String agreementAlg, PublicKey piccPublicKey, PrivateKey pcdPrivateKey) throws NoSuchAlgorithmException, InvalidKeyException {
    KeyAgreement agreement = KeyAgreement.getInstance(agreementAlg);
    agreement.init(pcdPrivateKey);
    agreement.doPhase(piccPublicKey, true);
    return agreement.generateSecret();
  }

  /**
   * Restarts secure messaging based on the shared secret.
   * 
   * @param oid the Chip Authentication object identifier
   * @param sharedSecret the shared secret
   * 
   * @return the secure messaging wrapper
   * 
   * @throws GeneralSecurityException on error
   */
  public static SecureMessagingWrapper restartSecureMessaging(String oid, byte[] sharedSecret) throws GeneralSecurityException {
    String cipherAlg = ChipAuthenticationInfo.toCipherAlgorithm(oid);
    int keyLength = ChipAuthenticationInfo.toKeyLength(oid);

    /* Start secure messaging. */
    SecretKey ksEnc = Util.deriveKey(sharedSecret, cipherAlg, keyLength, Util.ENC_MODE);
    SecretKey ksMac = Util.deriveKey(sharedSecret, cipherAlg, keyLength, Util.MAC_MODE);

    if (cipherAlg.startsWith("DESede")) {
      return new DESedeSecureMessagingWrapper(ksEnc, ksMac, 0L);
    } else if (cipherAlg.startsWith("AES")) {
      long ssc = 0L; // wrapper == null ? 0L : wrapper.getSendSequenceCounter();
      return new AESSecureMessagingWrapper(ksEnc, ksMac, ssc);
    } else {
      throw new IllegalStateException("Unsupported cipher algorithm " + cipherAlg);
    }
  }

  /**
   * Gets the secure messaging wrapper currently in use.
   * 
   * @return a secure messaging wrapper
   */
  public SecureMessagingWrapper getWrapper() {
    return wrapper;
  }

  private static byte[] getKeyHash(String agreementAlg, PublicKey pcdPublicKey) throws NoSuchAlgorithmException {
    if ("DH".equals(agreementAlg)) {
      /* TODO: this is probably wrong, what should be hashed? */
      MessageDigest md = MessageDigest.getInstance("SHA-1");
      return md.digest(getKeyData(agreementAlg, pcdPublicKey));
    } else if ("ECDH".equals(agreementAlg)) {
      org.bouncycastle.jce.interfaces.ECPublicKey pcdECPublicKey = (org.bouncycastle.jce.interfaces.ECPublicKey)pcdPublicKey;
      byte[] t = Util.i2os(pcdECPublicKey.getQ().getX().toBigInteger());
      return Util.alignKeyDataToSize(t, pcdECPublicKey.getParameters().getCurve().getFieldSize() / 8);
    }

    throw new IllegalArgumentException("Unsupported agreement algorithm " + agreementAlg);
  }

  private static byte[] getKeyData(String agreementAlg, PublicKey pcdPublicKey) {
    if ("DH".equals(agreementAlg)) {
      DHPublicKey pcdDHPublicKey = (DHPublicKey)pcdPublicKey;
      return pcdDHPublicKey.getY().toByteArray();
    } else if ("ECDH".equals(agreementAlg)) {
      org.bouncycastle.jce.interfaces.ECPublicKey pcdECPublicKey = (org.bouncycastle.jce.interfaces.ECPublicKey)pcdPublicKey;
      return pcdECPublicKey.getQ().getEncoded();
    }

    throw new IllegalArgumentException("Unsupported agreement algorithm " + agreementAlg);
  }
  
  /**
   * Infers the Chip Authentication OID form a Chip Authentication public key OID.
   * This is a best effort.
   * 
   * @param publicKeyOID the Chip Authentication public key OID
   * 
   * @return an OID or {@code null}
   */
  private static String inferChipAuthenticationOIDfromPublicKeyOID(String publicKeyOID) {
    if (ChipAuthenticationPublicKeyInfo.ID_PK_ECDH.equals(publicKeyOID)) {
      /*
       * This seems to work for French passports (generation 2013, 2014),
       * but it is best effort.
       */
      LOGGER.warning("Could not determine ChipAuthentication algorithm, defaulting to id-CA-ECDH-3DES-CBC-CBC");
      return ChipAuthenticationInfo.ID_CA_ECDH_3DES_CBC_CBC;
    } else if (ChipAuthenticationPublicKeyInfo.ID_PK_DH.equals(publicKeyOID)) {
      /*
       * Not tested. Best effort.
       */
      LOGGER.warning("Could not determine ChipAuthentication algorithm, defaulting to id-CA-DH-3DES-CBC-CBC");
      return ChipAuthenticationInfo.ID_CA_DH_3DES_CBC_CBC;
    } else {
      LOGGER.severe("No ChipAuthenticationInfo and unsupported ChipAuthenticationPublicKeyInfo public key OID " + publicKeyOID);
    }

    return null;
  }
}
