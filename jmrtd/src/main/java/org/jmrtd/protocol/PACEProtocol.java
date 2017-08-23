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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.jmrtd.BACKeySpec;
import org.jmrtd.PACEException;
import org.jmrtd.PACEKeySpec;
import org.jmrtd.PACESecretKeySpec;
import org.jmrtd.PassportApduService;
import org.jmrtd.PassportService;
import org.jmrtd.Util;
import org.jmrtd.lds.PACEInfo;
import org.jmrtd.lds.PACEInfo.MappingType;

import net.sf.scuba.smartcards.CardServiceException;
import net.sf.scuba.util.Hex;

/**
 * The Password Authenticated Connection Establishment protocol.
 * 
 * @author The JMRTD team (info@jmrtd.org)
 * 
 * @version $Revision$
 * 
 * @since 0.5.6
 */
public class PACEProtocol {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  private static final Provider BC_PROVIDER = Util.getBouncyCastleProvider();

  /**
   * Used in the last step of PACE-CAM.
   * 
   * From 9303-11:
   * 
   * AES [19] SHALL be used in CBC-mode according to [ISO/IEC 10116]
   * with IV=E(KSEnc,-1), where -1 is the bit string of length 128
   * with all bits set to 1.
   */
  private static final byte[] IV_FOR_PACE_CAM_DECRYPTION = {
      (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
      (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
      (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
      (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
  };

  /** Constant used in IM pseudo random number mapping, see Doc 9303 - Part 11, 4.4.3.3.2. */
  /* a668892a7c41e3ca739f40b057d85904, 16 bytes, 128 bits  */
  private static final byte[] C0_LENGTH_128 = 
    { (byte)0xA6, 0x68, (byte)0x89, 0x2A, 0x7C, 0x41, (byte)0xE3, (byte)0xCA, 0x73, (byte)0x9F, 0x40, (byte)0xB0, 0x57, (byte)0xD8, 0x59, 0x04 };

  /** Constant used in IM pseudo random number mapping, see Doc 9303 - Part 11, 4.4.3.3.2. */
  /* a4e136ac725f738b01c1f60217c188ad, 16 bytes, 128 bits */
  private static final byte[] C1_LENGTH_128 = 
    { (byte)0xA4, (byte)0xE1, 0x36, (byte)0xAC, 0x72, 0x5F, 0x73, (byte)0x8B, 0x01, (byte)0xC1, (byte)0xF6, 0x02, 0x17, (byte)0xC1, (byte)0x88, (byte)0xAD };

  /** Constant used in IM pseudo random number mapping, see Doc 9303 - Part 11, 4.4.3.3.2. */
  /* d463d65234124ef7897054986dca0a174e28df758cbaa03f240616414d5a1676, 32 bytes, 256 bits */
  private static final byte[] C0_LENGTH_256 = 
    { (byte)0xD4, 0x63, (byte)0xD6, 0x52, 0x34, 0x12, 0x4E, (byte)0xF7, (byte)0x89, 0x70, 0x54, (byte)0x98, 0x6D, (byte)0xCA, 0x0A, 0x17,
        0x4E, 0x28, (byte)0xDF, 0x75, (byte)0x8C, (byte)0xBA, (byte)0xA0, 0x3F, 0x24, 0x06, 0x16, 0x41, 0x4D, 0x5A, 0x16, 0x76 };

  /** Constant used in IM pseudo random number mapping, see Doc 9303 - Part 11, 4.4.3.3.2. */
  /* 54bd7255f0aaf831bec3423fcf39d69b6cbf066677d0faae5aadd99df8e53517, 32 bytes, 256 bits */
  private static final byte[] C1_LENGTH_256 = 
    { 0x54, (byte)0xBD, 0x72, 0x55, (byte)0xF0, (byte)0xAA, (byte)0xF8, 0x31, (byte)0xBE, (byte)0xC3, 0x42, 0x3F, (byte)0xCF, 0x39, (byte)0xD6, (byte)0x9B,
        0x6C, (byte)0xBF, 0x06, 0x66, 0x77, (byte)0xD0, (byte)0xFA, (byte)0xAE, 0x5A, (byte)0xAD, (byte)0xD9, (byte)0x9D, (byte)0xF8, (byte)0xE5, 0x35, 0x17 };

  private PassportService service;
  private SecureMessagingWrapper wrapper;

  private Random random;

  /**
   * Constructs a PACE protocol instance.
   * 
   * @param service the service for sending APDUs
   * @param wrapper the already established secure messaging channel (or {@code null})
   */
  public PACEProtocol(PassportService service, SecureMessagingWrapper wrapper) {
    this.service = service;
    this.wrapper = wrapper;
    this.random = new SecureRandom();
  }

  /**
   * Performs the PACE 2.0 / SAC protocol.
   *
   * @param accessKey the MRZ or CAN based access key
   * @param oid as specified in the PACEInfo, indicates GM or IM or CAM, DH or ECDH, cipher, digest, length
   * @param params explicit static domain parameters the domain params for DH or ECDH
   * 
   * @return a PACE result
   *
   * @throws PACEException on error
   */
  public PACEResult doPACE(KeySpec accessKey, String oid, AlgorithmParameterSpec params) throws PACEException {
    try {
      return doPACE(deriveStaticPACEKey(accessKey, oid), oid, params);
    } catch (GeneralSecurityException gse) {
      throw new PACEException("PCD side error in key derivation step");
    }
  }
  
  /**
   * Performs the PACE 2.0 / SAC protocol.
   *
   * @param staticPACEKey the password key
   * @param oid as specified in the PACEInfo, indicates GM or IM or CAM, DH or ECDH, cipher, digest, length
   * @param params explicit static domain parameters the domain params for DH or ECDH
   * 
   * @return a PACE result
   *
   * @throws PACEException if authentication failed
   */
  public PACEResult doPACE(SecretKey staticPACEKey, String oid, AlgorithmParameterSpec params) throws PACEException {
    MappingType mappingType = PACEInfo.toMappingType(oid); /* Either GM, CAM, or IM. */
    String agreementAlg = PACEInfo.toKeyAgreementAlgorithm(oid); /* Either DH or ECDH. */
    String cipherAlg  = PACEInfo.toCipherAlgorithm(oid); /* Either DESede or AES. */
    String digestAlg = PACEInfo.toDigestAlgorithm(oid); /* Either SHA-1 or SHA-256. */
    int keyLength = PACEInfo.toKeyLength(oid); /* Of the enc cipher. Either 128, 192, or 256. */

//    LOGGER.info("DEBUG: PACE: oid = " + oid
//        + " -> mappingType = " + mappingType
//        + ", agreementAlg = " + agreementAlg
//        + ", cipherAlg = " + cipherAlg
//        + ", digestAlg = " + digestAlg
//        + ", keyLength = " + keyLength);

    checkConsistency(agreementAlg, cipherAlg, digestAlg, keyLength, params);

    Cipher staticPACECipher = null;
    try {
      staticPACECipher = Cipher.getInstance(cipherAlg + "/CBC/NoPadding");
    } catch (GeneralSecurityException gse) {
      throw new PACEException("PCD side error in static cipher construction during key derivation step");
    }

    try {

      /* FIXME: multiple domain params feature not implemented here, for now. */
      byte[] referencePrivateKeyOrForComputingSessionKey = null;

      /* Send to the PICC. */
      byte paceKeyReference = PassportApduService.MRZ_PACE_KEY_REFERENCE;
      if (staticPACEKey instanceof PACESecretKeySpec) {
        paceKeyReference = ((PACESecretKeySpec)staticPACEKey).getKeyReference();
      }
      
      service.sendMSESetATMutualAuth(wrapper, oid, paceKeyReference, referencePrivateKeyOrForComputingSessionKey);
    } catch (CardServiceException cse) {
      throw new PACEException("PICC side error in static PACE key derivation step", cse.getSW());
    }

    /*
     * PCD and PICC exchange a chain of general authenticate commands.
     * Steps 1 to 4 below correspond with steps in table 3.3 of
     * ICAO TR-SAC 1.01.
     */

    /*
     * Receive encrypted nonce z = E(K_pi, s).
     * Decrypt nonce s = D(K_pi, z).
     */
    byte[] piccNonce = doPACEStep1(staticPACEKey, staticPACECipher);

    /*
     * Receive additional data required for map (i.e. a public key from PICC, and (conditionally) a nonce t).
     * Compute ephemeral domain parameters D~ = Map(D_PICC, s).
     */
    AlgorithmParameterSpec ephemeralParams = doPACEStep2(mappingType, agreementAlg, params, piccNonce, staticPACECipher);

    /* Choose random ephemeral PCD side keys (SK_PCD~, PK_PCD~, D~). */
    KeyPair pcdKeyPair = doPACEStep3GenerateKeyPair(agreementAlg, ephemeralParams);

    /*
     * Exchange PK_PCD~ and PK_PICC~ with PICC.
     * Check that PK_PCD~ and PK_PICC~ differ.
     */
    PublicKey piccPublicKey = doPACEStep3ExchangePublicKeys(pcdKeyPair.getPublic(), ephemeralParams);

    /* Key agreement K = KA(SK_PCD~, PK_PICC~, D~). */
    byte[] sharedSecretBytes = doPACEStep3KeyAgreement(agreementAlg, pcdKeyPair.getPrivate(), piccPublicKey);

    /* Derive secure messaging keys. */
    /* Compute session keys K_mac = KDF_mac(K), K_enc = KDF_enc(K). */    
    SecretKey encKey = null;
    SecretKey macKey = null;
    try {
      encKey = Util.deriveKey(sharedSecretBytes, cipherAlg, keyLength, Util.ENC_MODE);
      macKey = Util.deriveKey(sharedSecretBytes, cipherAlg, keyLength, Util.MAC_MODE);
    } catch (GeneralSecurityException gse) {
      LOGGER.log(Level.WARNING, "Security exception during secure messaging key derivation", gse);
      throw new PACEException("Security exception during secure messaging key derivation: " + gse.getMessage());
    }

    /*
     * Compute authentication token T_PCD = MAC(K_mac, PK_PICC~).
     * Exchange authentication token T_PCD and T_PICC with PICC.
     * Check authentication token T_PICC.
     * 
     * Extract encryptedChipAuthenticationData, if mapping is CAM.
     */
    byte[] encryptedChipAuthenticationData = doPACEStep4(oid, mappingType, pcdKeyPair, piccPublicKey, macKey);
    byte[] chipAuthenticationData = null;

    /*
     * Start secure messaging.
     *
     * 4.6 of TR-SAC: If Secure Messaging is restarted, the SSC is used as follows:
     *  - The commands used for key agreement are protected with the old session keys and old SSC.
     *    This applies in particular for the response of the last command used for session key agreement.
     *  - The Send Sequence Counter is set to its new start value, i.e. within this specification the SSC is set to 0.
     *  - The new session keys and the new SSC are used to protect subsequent commands/responses.
     */
    try {
      if (cipherAlg.startsWith("DESede")) {
        wrapper = new DESedeSecureMessagingWrapper(encKey, macKey);
      } else if (cipherAlg.startsWith("AES")) {
        long ssc = wrapper == null ? 0L : wrapper.getSendSequenceCounter();
        wrapper = new AESSecureMessagingWrapper(encKey, macKey, ssc);
      }
    } catch (GeneralSecurityException gse) {
      LOGGER.severe("Exception: " + gse.getMessage());
      throw new IllegalStateException("Security exception in secure messaging establishment: " + gse.getMessage());
    }

    if (MappingType.CAM.equals(mappingType)) {

      if (encryptedChipAuthenticationData == null) {
        LOGGER.severe("Encrypted Chip Authentication data is null");
      }

      /* Decrypt A_PICC to recover CA_PICC. */
      try {
        SecretKey secretKey = encKey; // new SecretKeySpec(sharedSecretBytes, "AES");
        Cipher decryptCipher = Cipher.getInstance("AES/CBC/NoPadding");
        decryptCipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(IV_FOR_PACE_CAM_DECRYPTION));
        chipAuthenticationData = Util.unpad(decryptCipher.doFinal(encryptedChipAuthenticationData));

        LOGGER.info("DEBUG: Including Chip Authentication data in PACE result");

      } catch (GeneralSecurityException gse) {
        LOGGER.log(Level.WARNING, "Could not decrypt Chip Authentication data", gse);
      }
    }

    return new PACEResult(mappingType, agreementAlg, cipherAlg, digestAlg, keyLength,
        params,
        piccNonce, ephemeralParams, pcdKeyPair, piccPublicKey, sharedSecretBytes, encryptedChipAuthenticationData, chipAuthenticationData, wrapper);
  }

  /**
   * The first step in the PACE protocol receives an encrypted nonce from the PICC
   * and decrypts it.
   * 
   * @param staticPACEKey the static PACE key
   * @param staticPACECipher the cipher to reuse
   * 
   * @return the decrypted encrypted PICC nonce
   * 
   * @throws PACEException on error
   */
  /*
   * 1. Encrypted Nonce     - --- Absent        - 0x80 Encrypted Nonce
   *
   * Receive encrypted nonce z = E(K_pi, s).
   * (This is steps 1-3 in Table 4.4 in BSI 03111 2.0.)
   *
   * Decrypt nonce s = D(K_pi, z).
   * (This is step 4 in Table 4.4 in BSI 03111 2.0.)
   */
  public byte[] doPACEStep1(SecretKey staticPACEKey, Cipher staticPACECipher) throws PACEException {
    byte[] piccNonce = null;
    try {
      byte[] step1Data = new byte[] { };
      /* Command data is empty. this implies an empty dynamic authentication object. */
      byte[] step1Response = service.sendGeneralAuthenticate(wrapper, step1Data, false);
      byte[] step1EncryptedNonce = Util.unwrapDO((byte)0x80, step1Response);

      /* (Re)initialize the K_pi cipher for decryption. */

      //      staticPACECipher.init(Cipher.DECRYPT_MODE, staticPACEKey, new IvParameterSpec(new byte[16])); /* FIXME: iv length 16 is independent of keylength? */
      //      staticPACECipher.init(Cipher.DECRYPT_MODE, staticPACEKey, new IvParameterSpec(new byte[step1EncryptedNonce.length])); // Fix proposed by Dorian ALADEL (dorian.aladel@gemalto.com)
      staticPACECipher.init(Cipher.DECRYPT_MODE, staticPACEKey, new IvParameterSpec(new byte[staticPACECipher.getBlockSize()])); // Fix proposed by Halvdan Grelland (halvdanhg@gmail.com)

      piccNonce = staticPACECipher.doFinal(step1EncryptedNonce);
      return piccNonce;
    } catch (GeneralSecurityException gse) {
      LOGGER.severe("Exception: " + gse.getMessage());
      throw new PACEException("PCD side exception in tranceiving nonce step: " + gse.getMessage());
    } catch (CardServiceException cse) {
      throw new PACEException("PICC side exception in tranceiving nonce step", cse.getSW());
    }
  }

  /**
   * The second step in the PACE protocol computes ephemeral domain parameters
   * by performing a key agreement protocol with the PICC nonce as
   * input.
   * 
   * @param mappingType either CAM, GM, or IM
   * @param agreementAlg the agreement algorithm, either DH or ECDH
   * @param params the static domain parameters
   * @param piccNonce the nonce received from the PICC
   * @param staticPACECipher the cipher to use in IM
   * 
   * @return the computed ephemeral domain parameters
   * 
   * @throws PACEException on error
   */
  /*
   * 2. Map Nonce       - 0x81 Mapping Data     - 0x82 Mapping Data
   *
   * (This is step 3.a) in the protocol in TR-SAC.)
   * (This is step 5 in Table 4.4 in BSI 03111 2.0.)
   *
   * Receive additional data required for map (i.e. a public key from PICC, and (conditionally) a nonce t).
   * Compute ephemeral domain parameters D~ = Map(D_PICC, s).
   */
  public AlgorithmParameterSpec doPACEStep2(MappingType mappingType, String agreementAlg, AlgorithmParameterSpec params, byte[] piccNonce, Cipher staticPACECipher) throws PACEException {
    switch(mappingType) {
      case CAM:
        // Fall through to GM case.
      case GM:
        return doPACEStep2GM(agreementAlg, params, piccNonce);
      case IM:
        return doPACEStep2IM(agreementAlg, params, piccNonce, staticPACECipher);
      default:
        throw new PACEException("Unsupported mapping type " + mappingType);
    }
  }

  /**
   * The second step in the PACE protocol computes ephemeral domain parameters
   * by performing a key agreement protocol with the PICC nonce as
   * input.
   * 
   * @param agreementAlg the agreement algorithm, either DH or ECDH
   * @param params the static domain parameters
   * @param piccNonce the received nonce from the PICC
   * 
   * @return the computed ephemeral domain parameters
   * 
   * @throws PACEException on error
   */
  public AlgorithmParameterSpec doPACEStep2GM(String agreementAlg, AlgorithmParameterSpec params, byte[] piccNonce) throws PACEException {
    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(agreementAlg, BC_PROVIDER);
      keyPairGenerator.initialize(params);
      KeyPair kp = keyPairGenerator.generateKeyPair();
      PublicKey pcdMappingPublicKey = kp.getPublic();
      PrivateKey pcdMappingPrivateKey = kp.getPrivate();
      KeyAgreement mappingAgreement = KeyAgreement.getInstance(agreementAlg);
      mappingAgreement.init(pcdMappingPrivateKey);

      MyECDHKeyAgreement myECDHKeyAgreement = null;
      if ("ECDH".equals(agreementAlg)) {
        myECDHKeyAgreement = new MyECDHKeyAgreement();
        myECDHKeyAgreement.init((ECPrivateKey)pcdMappingPrivateKey);
      }

      byte[] pcdMappingEncodedPublicKey = Util.encodePublicKeyForSmartCard(pcdMappingPublicKey);            
      byte[] step2Data = Util.wrapDO((byte)0x81, pcdMappingEncodedPublicKey);
      byte[] step2Response = service.sendGeneralAuthenticate(wrapper, step2Data, false);
      byte[] piccMappingEncodedPublicKey = Util.unwrapDO((byte)0x82, step2Response);
      PublicKey piccMappingPublicKey = Util.decodePublicKeyFromSmartCard(piccMappingEncodedPublicKey, params);
      mappingAgreement.doPhase(piccMappingPublicKey, true);

      byte[] mappingSharedSecretBytes = mappingAgreement.generateSecret();

      if ("ECDH".equals(agreementAlg) && myECDHKeyAgreement != null) {
        /* Treat shared secret as an ECPoint. */
        ECPoint sharedSecretPointH = myECDHKeyAgreement.doPhase((ECPublicKey)piccMappingPublicKey);
        return Util.mapNonceGMWithECDH(Util.os2i(piccNonce), sharedSecretPointH, (ECParameterSpec)params);
      } else if ("DH".equals(agreementAlg)) {
        return Util.mapNonceGMWithDH(Util.os2i(piccNonce), Util.os2i(mappingSharedSecretBytes), (DHParameterSpec)params);
      } else {
        throw new IllegalArgumentException("Unsupported parameters for mapping nonce, expected ECParameterSpec or DHParameterSpec, found " + params.getClass().getCanonicalName());
      }
    } catch (GeneralSecurityException gse) {
      throw new PACEException("PCD side error in mapping nonce step: " + gse.getMessage());
    } catch (CardServiceException cse) {
      throw new PACEException("PICC side exception in mapping nonce step", cse.getSW());
    }
  }

  /**
   * The second step in the PACE protocol computes ephemeral domain parameters
   * by performing a key agreement protocol with the PICC and PCD nonces as
   * input.
   * 
   * @param agreementAlg the agreement algorithm, either DH or ECDH
   * @param params the static domain parameters
   * @param piccNonce the received nonce from the PICC
   * @param staticPACECipher the cipher to use for IM
   * 
   * @return the computed ephemeral domain parameters
   * 
   * @throws PACEException on error
   */
  /*
   * The function Map:G -> G_Map is defined as
   * G_Map = f_G(R_p(s,t)),
   * where R_p() is a pseudo-random function that maps octet strings to elements of GF(p)
   * and f_G() is a function that maps elements of GF(p) to <G>.
   * The random nonce t SHALL be chosen randomly by the inspection system
   * and sent to the MRTD chip.
   * The pseudo-random function R_p() is described in Section 3.4.2.2.3.
   * The function f_G() is defined in [4] and [25].
   * 
   * [4]: Brier, Eric; Coron, Jean-S&eacute;́bastien; Icart, Thomas; Madore, David; Randriam, Hugues; and
   *      Tibouch, Mehdi, Efficient Indifferentiable Hashing into Ordinary Elliptic Curves, Advances in
   *      Cryptology – CRYPTO 2010, Springer-Verlag, 2010.
   * [25]: Sagem, MorphoMapping Patents FR09-54043 and FR09-54053, 2009
   */
  public AlgorithmParameterSpec doPACEStep2IM(String agreementAlg, AlgorithmParameterSpec params, byte[] piccNonce, Cipher staticPACECipher) throws PACEException {
    try {
      
      byte[] pcdNonce = new byte[piccNonce.length];
      random.nextBytes(pcdNonce);
      
      byte[] step2Data = Util.wrapDO((byte)0x81, pcdNonce);
      byte[] step2Response = service.sendGeneralAuthenticate(wrapper, step2Data, false);

      /* NOTE: The context specific data object 0x82 SHALL be empty (TR SAC 3.3.2). */      
      
      LOGGER.info("DEBUG: step2Response = " + Hex.bytesToHexString(step2Response));

      if ("ECDH".equals(agreementAlg)) {
        /* Treat shared secret as an ECPoint. */
        
        return mapNonceIMWithECDH(piccNonce, pcdNonce, staticPACECipher.getAlgorithm(), (ECParameterSpec)params);
        
        
      } else if ("DH".equals(agreementAlg)) {
        return mapNonceIMWithDH(piccNonce, pcdNonce, staticPACECipher.getAlgorithm(), (DHParameterSpec)params);
      } else {
        throw new IllegalArgumentException("Unsupported parameters for mapping nonce, expected ECParameterSpec or DHParameterSpec, found " + params.getClass().getCanonicalName());
      }
            
    } catch (GeneralSecurityException gse) {
      throw new PACEException("PCD side error in mapping nonce step: " + gse.getMessage());
    } catch (CardServiceException cse) {
      throw new PACEException("PICC side exception in mapping nonce step", cse.getSW());
    }
  }

  /**
   * @param nonceS
   * @param nonceT
   * @param cipherAlgorithm
   * @param params
   * @return
   * @throws GeneralSecurityException
   */
  public static AlgorithmParameterSpec mapNonceIMWithECDH(byte[] nonceS, byte[] nonceT, String cipherAlgorithm, ECParameterSpec params) throws GeneralSecurityException {
    BigInteger p = Util.getPrime(params);
    BigInteger order = params.getOrder();
    int cofactor = params.getCofactor();
    BigInteger a = params.getCurve().getA();
    BigInteger b = params.getCurve().getB();

    BigInteger t = Util.os2i(pseudoRandomFunction(nonceS, nonceT, p, cipherAlgorithm));

    ECPoint mappedGenerator = pointEncoding(t, params);
    return new ECParameterSpec(new EllipticCurve(new ECFieldFp(p), a, b), mappedGenerator, order, cofactor);
  }

  /**
   * Icart's point encoding.
   *
   * @param t the field element to encode
   * @param params the curve's parameters
   * 
   * @return the point on the curve that the input is mapped to
   */
  private static ECPoint pointEncoding(BigInteger t, ECParameterSpec params) {
    BigInteger p = Util.getPrime(params);
    BigInteger order = params.getOrder();
    int cofactor = params.getCofactor();
    BigInteger a = params.getCurve().getA();
    BigInteger b = params.getCurve().getB();
    
    BigInteger alpha = t.pow(2).negate().mod(p);
    
    BigInteger alphaSq = alpha.multiply(alpha).mod(p);
    BigInteger alphaPlusAlphaSq = alpha.add(alphaSq);
    BigInteger pMinus2 = p.subtract(BigInteger.ONE).subtract(BigInteger.ONE);
    BigInteger x2 = b.negate().multiply(BigInteger.ONE.add(alphaPlusAlphaSq)).multiply((alpha.multiply(alphaPlusAlphaSq)).modPow(pMinus2, p));
    
    /* WORK IN PROGRESS... */
    
    return null; // FIXME
  }

  public static AlgorithmParameterSpec mapNonceIMWithDH(byte[] nonceS, byte[] nonceT, String cipherAlgorithm, DHParameterSpec params) {
    /* FIXME: work in progress. */
    return null;
  }
  
  /*
   * The function R_p(s,t) is a function that maps octet strings s (of bit length l) and t (of bit length k)
   * to an element int(x_1 || x_2 || ... || x_n) mod p of GF(p).
   * The function R(s,t) is specified in Figure 2.
   * The construction is based on the respective block cipher E() in CBC mode according to ISO/IEC 10116 [12]
   * with IV=0, where k is the key size (in bits) of E().
   * Where required, the output k_i MUST be truncated to key size k.
   * The value n SHALL be selected as smallest number, such that n*l >= log2 p + 64.
   */
  /**
   * Pseudo random number function as specified in Doc 9303 - Part 11, 4.4.3.3.2 used in integrated mapping.
   * 
   * @param s the nonce that was sent by the ICC
   * @param t the nonce that was generated by the PCD
   * @param p the order of the prime field
   * @param algorithm the algorithm for block cipher E (either {@code "AES"} or {@code "DESede"})
   * 
   * @return the resulting x
   * 
   * @throws GeneralSecurityException on cryptographic error
   */
  public static byte[] pseudoRandomFunction(byte[] s, byte[] t, BigInteger p, String algorithm) throws GeneralSecurityException {
    if (s == null || t == null) {
      throw new IllegalArgumentException("Null nonce");
    }

    int l = s.length * 8;
    int k = t.length * 8; /* Key size in bits. */

    byte[] c0 = null;
    byte[] c1 = null;
    switch (l) {
      case 128:
        c0 = C0_LENGTH_128;
        c1 = C1_LENGTH_128;
        break;
      case 192: // Fall through
      case 256:
        c0 = C0_LENGTH_256;
        c1 = C1_LENGTH_256;
        break;
      default:
        throw new IllegalArgumentException("Unknown length " + l + ", was expecting 128, 192, or 256");
    }

    Cipher cipher = Cipher.getInstance(algorithm + (algorithm.endsWith("/CBC/NoPadding") ? "" : "/CBC/NoPadding"));
    int blockSize = cipher.getBlockSize(); /* in bytes */

    IvParameterSpec zeroIV = new IvParameterSpec(new byte[blockSize]);

    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(t, algorithm), zeroIV);
    byte[] key = cipher.doFinal(s);

    ByteArrayOutputStream x = new ByteArrayOutputStream();

    try {
      int n = 0;
      while (n * l < p.bitLength() + 64) {
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, 0, k / 8, algorithm), zeroIV);
        key = cipher.doFinal(c0);
        x.write(cipher.doFinal(c1));
        n++;
      }

      byte[] xBytes = x.toByteArray();
      return Util.i2os(Util.os2i(xBytes).mod(p));
    } catch (Exception ioe) {
      /* NOTE: Never happens, writing to byte array output stream. */
      LOGGER.log(Level.WARNING, "Could not write to stream", ioe);

      return Util.i2os(Util.os2i(x.toByteArray()).mod(p));
    } finally {
      try {
        x.close();
      } catch (IOException ioe) {
        LOGGER.log(Level.FINE, "Could not close stream", ioe);
      }
    }
  }

  /* Choose random ephemeral key pair (SK_PCD~, PK_PCD~, D~). */
  public KeyPair doPACEStep3GenerateKeyPair(String agreementAlg, AlgorithmParameterSpec ephemeralParams) throws PACEException {
    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(agreementAlg, BC_PROVIDER);
      keyPairGenerator.initialize(ephemeralParams);
      KeyPair kp = keyPairGenerator.generateKeyPair();
      return kp;
    } catch (GeneralSecurityException gse) {
      throw new PACEException("PCD side error during generation of PCD key pair");
    }
  }

  /*
   * 3. Perform Key Agreement - 0x83 Ephemeral Public Key - 0x84 Ephemeral Public Key
   *
   * Exchange PK_PCD~ and PK_PICC~ with PICC.
   * Check that PK_PCD~ and PK_PICC~ differ.
   */
  public PublicKey doPACEStep3ExchangePublicKeys(PublicKey pcdPublicKey, AlgorithmParameterSpec ephemeralParams)  throws PACEException {    
    try {
      byte[] pcdEncodedPublicKey = Util.encodePublicKeyForSmartCard(pcdPublicKey);
      byte[] step3Data = Util.wrapDO((byte)0x83, pcdEncodedPublicKey);
      byte[] step3Response = service.sendGeneralAuthenticate(wrapper, step3Data, false);
      byte[] piccEncodedPublicKey = Util.unwrapDO((byte)0x84, step3Response);
      PublicKey piccPublicKey = Util.decodePublicKeyFromSmartCard(piccEncodedPublicKey, ephemeralParams);

      if (pcdPublicKey.equals(piccPublicKey)) {
        throw new PACEException("PCD's public key and PICC's public key are the same in key agreement step!");
      }

      return piccPublicKey;
    } catch (IllegalStateException ise) {
      throw new PACEException("PCD side exception in key agreement step: " + ise.getMessage());
    } catch (GeneralSecurityException gse) {
      throw new PACEException("PCD side exception in key agreement step: " + gse.getMessage());
    } catch (CardServiceException cse) {
      throw new PACEException("PICC side exception in key agreement step", cse.getSW());
    }
  }

  /* Key agreement K = KA(SK_PCD~, PK_PICC~, D~). */
  public byte[] doPACEStep3KeyAgreement(String agreementAlg, PrivateKey pcdPrivateKey, PublicKey piccPublicKey) throws PACEException {
    try {
      KeyAgreement keyAgreement = KeyAgreement.getInstance(agreementAlg, BC_PROVIDER);
      keyAgreement.init(pcdPrivateKey);
      keyAgreement.doPhase(updateParameterSpec(piccPublicKey, pcdPrivateKey), true);
      return keyAgreement.generateSecret();
    } catch (GeneralSecurityException gse) {
      LOGGER.log(Level.WARNING, "PCD side error during key agreement", gse);
      throw new PACEException("PCD side error during key agreement");
    }
  }

  /*
   * 4. Mutual Authentication - 0x85 Authentication Token - 0x86 Authentication Token
   *
   * Compute authentication token T_PCD = MAC(K_mac, PK_PICC~).
   * Exchange authentication token T_PCD and T_PICC with PICC.
   * Check authentication token T_PICC.
   * 
   * Extracts encryptedChipAuthenticationData, if mapping type id CAM.
   */
  public byte[] doPACEStep4(String oid, MappingType mappingType, KeyPair pcdKeyPair, PublicKey piccPublicKey, SecretKey macKey) throws PACEException {
    try {
      byte[] pcdToken = generateAuthenticationToken(oid, macKey, piccPublicKey);
      byte[] step4Data = Util.wrapDO((byte)0x85, pcdToken);
      byte[] step4Response = service.sendGeneralAuthenticate(wrapper, step4Data, true);
      byte[] piccToken = Util.unwrapDO((byte)0x86, step4Response);
      byte[] expectedPICCToken = generateAuthenticationToken(oid, macKey, pcdKeyPair.getPublic());
      if (!Arrays.equals(expectedPICCToken, piccToken)) {
        throw new GeneralSecurityException("PICC authentication token mismatch");
      }

      if (mappingType == MappingType.CAM) {
        return Util.unwrapDO((byte)0x8A, step4Data);
      } else {
        return null;
      }
    } catch (GeneralSecurityException gse) {
      throw new PACEException("PCD side exception in authentication token generation step: " + gse.getMessage());
    } catch (CardServiceException cse) {
      throw new PACEException("PICC side exception in authentication token generation step", cse.getSW());
    }
  }

  /**
   * Derives the static key K_pi.
   * 
   * @param keySpec the key material from the MRZ
   * @param oid the PACE object identifier is needed to determine the cipher algorithm and the key length
   * 
   * @return the derived key
   * 
   * @throws GeneralSecurityException on error
   */
  public static SecretKey deriveStaticPACEKey(KeySpec keySpec, String oid) throws GeneralSecurityException {
    String cipherAlg  = PACEInfo.toCipherAlgorithm(oid); /* Either DESede or AES. */
    int keyLength = PACEInfo.toKeyLength(oid); /* Of the enc cipher. Either 128, 192, or 256. */
    byte[] keySeed = computeKeySeedForPACE(keySpec);
    
    byte paceKeyReference = 0;
    if (keySpec instanceof PACEKeySpec) {
      paceKeyReference = ((PACEKeySpec)keySpec).getKeyReference();
    }

    return Util.deriveKey(keySeed, cipherAlg, keyLength, null, Util.PACE_MODE, paceKeyReference);
  }

  public static byte[] computeKeySeedForPACE(KeySpec accessKey) throws GeneralSecurityException {
    if (accessKey == null) {
      throw new IllegalArgumentException("Access key cannot be null");
    }

    /* MRZ based key. */
    if (accessKey instanceof BACKeySpec) {
      BACKeySpec bacKey = (BACKeySpec)accessKey;
      String documentNumber = bacKey.getDocumentNumber();
      String dateOfBirth = bacKey.getDateOfBirth();
      String dateOfExpiry = bacKey.getDateOfExpiry();

      if (dateOfBirth == null || dateOfBirth.length() != 6) {
        throw new IllegalArgumentException("Wrong date format used for date of birth. Expected yyMMdd, found " + dateOfBirth);
      }
      if (dateOfExpiry == null || dateOfExpiry.length() != 6) {
        throw new IllegalArgumentException("Wrong date format used for date of expiry. Expected yyMMdd, found " + dateOfExpiry);
      }
      if (documentNumber == null) {
        throw new IllegalArgumentException("Wrong document number. Found " + documentNumber);
      }

      documentNumber = fixDocumentNumber(documentNumber);

      return computeKeySeedForPACE(documentNumber, dateOfBirth, dateOfExpiry);
    }
    
    if (accessKey instanceof PACEKeySpec) {
      return ((PACEKeySpec)accessKey).getKey();
    }

    throw new IllegalArgumentException("Unsupported access key, was expecting BAC or CAN key specification, found " + accessKey.getClass().getSimpleName());
  }

  /**
   * Updates the parameters of the given public key to match the parameters of the given private key.
   * 
   * @param publicKey the public key, should be an EC public key
   * @param privateKey the private key, should be an EC private key
   * 
   * @return a new public key that uses the parameters of the private key
   * 
   * @throws GeneralSecurityException on security error, or when keys are not EC
   */
  public static PublicKey updateParameterSpec(PublicKey publicKey, PrivateKey privateKey) throws GeneralSecurityException {
    if (!(publicKey instanceof ECPublicKey) || !(privateKey instanceof ECPrivateKey)) {
      throw new NoSuchAlgorithmException("Unsupported key type");
    }

    KeyFactory keyFactory = KeyFactory.getInstance("EC");    
    KeySpec keySpec = new ECPublicKeySpec(((ECPublicKey)publicKey).getW(), ((ECPrivateKey)privateKey).getParams());
    return keyFactory.generatePublic(keySpec);
  }

  /**
   * Computes the static key seed to be used in PACE KDF, based on information from the MRZ.
   *
   * @param documentNumber a string containing the document number
   * @param dateOfBirth a string containing the date of birth (YYMMDD)
   * @param dateOfExpiry a string containing the date of expiry (YYMMDD)
   *
   * @return a byte array of length 16 containing the key seed
   *
   * @throws GeneralSecurityException on security error
   */
  private static byte[] computeKeySeedForPACE(String documentNumber, String dateOfBirth, String dateOfExpiry) throws GeneralSecurityException {
    return Util.computeKeySeed(documentNumber, dateOfBirth, dateOfExpiry, "SHA-1", false);
  }

  private static String fixDocumentNumber(String documentNumber) {
    /* The document number, excluding trailing '<'. */
    String minDocumentNumber = documentNumber.replace('<', ' ').trim().replace(' ', '<');

    /* The document number, including trailing '<' until length 9. */
    String maxDocumentNumber = minDocumentNumber;
    while (maxDocumentNumber.length() < 9) {
      maxDocumentNumber += "<";
    }
    return maxDocumentNumber;
  }

  public static byte[] computeKeySeedForPACE(String cardAccessNumber) throws GeneralSecurityException {
    return Util.computeKeySeed(cardAccessNumber,  "SHA-1", false);
  }

  /**
   * The authentication token SHALL be computed over a public key data object (cf. Section 4.5)
   * containing the object identifier as indicated in MSE:Set AT (cf. Section 3.2.1), and the
   * received ephemeral public key (i.e. excluding the domain parameters, cf. Section 4.5.3)
   * using an authentication code and the key KS MAC derived from the key agreement.
   *
   * @param oid the object identifier as indicated in MSE Set AT
   * @param macKey the KS MAC key derived from the key agreement
   * @param publicKey the received public key
   *
   * @return the authentication code
   *
   * @throws GeneralSecurityException on error while performing the MAC operation
   */
  public static byte[] generateAuthenticationToken(String oid, SecretKey macKey, PublicKey publicKey) throws GeneralSecurityException {
    String cipherAlg = PACEInfo.toCipherAlgorithm(oid);
    String macAlg = inferMacAlgorithmFromCipherAlgorithm(cipherAlg);
    Mac mac = Mac.getInstance(macAlg, BC_PROVIDER);
    byte[] encodedPublicKeyDataObject = Util.encodePublicKeyDataObject(oid, publicKey);
    mac.init(macKey);
    byte[] maccedPublicKeyDataObject = mac.doFinal(encodedPublicKeyDataObject);

    /* Output length needs to be 64 bits, copy first 8 bytes. */
    byte[] authenticationToken = new byte[8];
    System.arraycopy(maccedPublicKeyDataObject, 0, authenticationToken, 0, authenticationToken.length);
    return authenticationToken;
  }

  /**
   * Checks consistency of input parameters.
   * 
   * @param agreementAlg the agreement algorithm derived from the OID
   * @param params the parameters
   */
  private void checkConsistency(String agreementAlg, String cipherAlg, String digestAlg, int keyLength, AlgorithmParameterSpec params) {
    if (agreementAlg == null) {
      throw new IllegalArgumentException("Unknown agreement algorithm");
    }

    /* Agreement algorithm should be ECDH or DH. */
    if (!("ECDH".equalsIgnoreCase(agreementAlg) || "DH".equalsIgnoreCase(agreementAlg))) {
      throw new IllegalArgumentException("Unsupported agreement algorithm, expected ECDH or DH, found \"" + agreementAlg + "\"");
    }

    if (cipherAlg == null) {
      throw new IllegalArgumentException("Unknown cipher algorithm");
    }

    if (!("DESede".equalsIgnoreCase(cipherAlg) || "AES".equalsIgnoreCase(cipherAlg))) {
      throw new IllegalArgumentException("Unsupported cipher algorithm, expected DESede or AES, found \"" + cipherAlg + "\"");
    }

    if (!("SHA-1".equalsIgnoreCase(digestAlg) || "SHA1".equalsIgnoreCase(digestAlg)
        || "SHA-256".equalsIgnoreCase(digestAlg) || "SHA256".equalsIgnoreCase(digestAlg))) {
      throw new IllegalArgumentException("Unsupported cipher algorithm, expected DESede or AES, found \"" + digestAlg + "\"");
    }

    if (!(keyLength == 128 || keyLength == 192 || keyLength == 256)) {
      throw new IllegalArgumentException("Unsupported key length, expected 128, 192, or 256, found " + keyLength);
    }

    /* Params should be correct param spec type, given agreement algorithm. */
    if ("ECDH".equalsIgnoreCase(agreementAlg) && !(params instanceof ECParameterSpec)) {
      throw new IllegalArgumentException("Expected ECParameterSpec for agreement algorithm \"" + agreementAlg + "\", found " + params.getClass().getCanonicalName());
    } else if ("DH".equalsIgnoreCase(agreementAlg) && !(params instanceof DHParameterSpec)) {
      throw new IllegalArgumentException("Expected DHParameterSpec for agreement algorithm \"" + agreementAlg + "\", found " + params.getClass().getCanonicalName());
    }
  }

  private static String inferMacAlgorithmFromCipherAlgorithm(String cipherAlg) throws InvalidAlgorithmParameterException {
    if (cipherAlg == null) {
      throw new IllegalArgumentException("Cannot infer MAC algorithm from cipher algorithm null");
    }

    /*
     * NOTE: AESCMAC will generate 128 bit (16 byte) results, not 64 bit (8 byte),
     * both authentication token generation and secure messaging,
     * where the Mac is applied, will copy only the first 8 bytes. -- MO
     */
    if (cipherAlg.startsWith("DESede")) {
      /* FIXME: Is macAlg = "ISO9797Alg3Mac" equivalent to macAlg = "DESedeMac"??? - MO */
      return "ISO9797Alg3Mac";
    } else if (cipherAlg.startsWith("AES")) {
      return "AESCMAC";
    } else {
      throw new InvalidAlgorithmParameterException("Cannot infer MAC algorithm from cipher algorithm \"" + cipherAlg + "\"");
    }
  }

  public class MyECDHKeyAgreement {

    private ECPrivateKey privateKey;

    public void init(ECPrivateKey privateKey) {
      this.privateKey = privateKey;
    }

    public ECPoint doPhase(ECPublicKey publicKey) {
      ECPublicKeyParameters pub = Util.toBouncyECPublicKeyParameters(publicKey);

      org.bouncycastle.math.ec.ECPoint p = pub.getQ().multiply(Util.toBouncyECPrivateKeyParameters(privateKey).getD()).normalize();
      if (p.isInfinity()) {
        throw new IllegalStateException("Infinity");
      }
      return Util.fromBouncyCastleECPoint(p);
    }
  }
}
