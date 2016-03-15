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

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import org.jmrtd.AESSecureMessagingWrapper;
import org.jmrtd.BACKeySpec;
import org.jmrtd.DESedeSecureMessagingWrapper;
import org.jmrtd.JMRTDSecurityProvider;
import org.jmrtd.PACEException;
import org.jmrtd.PassportApduService;
import org.jmrtd.PassportService;
import org.jmrtd.SecureMessagingWrapper;
import org.jmrtd.Util;
import org.jmrtd.lds.PACEInfo;
import org.jmrtd.lds.PACEInfo.MappingType;

import net.sf.scuba.smartcards.CardServiceException;

/**
 * The Password Authenticated Connection Establishment protocol.
 * 
 * @author The JMRTD team (info@jmrtd.org)
 * 
 * @version $Revision: $
 * 
 * @since 0.5.6
 */
public class PACEProtocol {
  
  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");
  
  private static final Provider BC_PROVIDER = JMRTDSecurityProvider.getBouncyCastleProvider();
  
  private PassportService service;
  private SecureMessagingWrapper wrapper;
  
  /**
   * Constructs a PACE protocol instance.
   * 
   * @param service the service for sending APDUs
   * @param wrapper the already established secure messaging channel (or {@code null})
   */
  public PACEProtocol(PassportService service, SecureMessagingWrapper wrapper) {
    this.service = service;
    this.wrapper = wrapper;
  }
  
  /**
   * Performs the PACE 2.0 / SAC protocol.
   *
   * @param keySpec the MRZ
   * @param oid as specified in the PACEInfo, indicates GM or IM or CAM, DH or ECDH, cipher, digest, length
   * @param params explicit static domain parameters the domain params for DH or ECDH
   *
   * @throws PACEException on error
   */
  public PACEResult doPACE(BACKeySpec keySpec, String oid,  AlgorithmParameterSpec params) throws PACEException {
    try {
      return doPACE(deriveStaticPACEKey(keySpec, oid), oid, params);
    } catch (GeneralSecurityException gse) {
      throw new PACEException("PCD side error in key derivation step");
    }
  }
  /**
   * Performs the PACE 2.0 / SAC protocol.
   *
   * @param keySpec the MRZ
   * @param oid as specified in the PACEInfo, indicates GM or IM or CAM, DH or ECDH, cipher, digest, length
   * @param params explicit static domain parameters the domain params for DH or ECDH
   *
   * @throws PACEException on error
   */
  public PACEResult doPACE(SecretKey staticPACEKey, String oid, AlgorithmParameterSpec params) throws PACEException {
    PACEInfo.MappingType mappingType = PACEInfo.toMappingType(oid); /* Either GM, CAM, or IM. */
    String agreementAlg = PACEInfo.toKeyAgreementAlgorithm(oid); /* Either DH or ECDH. */
    String cipherAlg  = PACEInfo.toCipherAlgorithm(oid); /* Either DESede or AES. */
    String digestAlg = PACEInfo.toDigestAlgorithm(oid); /* Either SHA-1 or SHA-256. */
    int keyLength = PACEInfo.toKeyLength(oid); /* Of the enc cipher. Either 128, 192, or 256. */
    
    /* Check consistency of input parameters. */
    if (agreementAlg == null) {
      throw new IllegalArgumentException("Unknown agreement algorithm");
    }
    if (!("ECDH".equals(agreementAlg) || "DH".equals(agreementAlg))) {
      throw new IllegalArgumentException("Unsupported agreement algorithm, expected ECDH or DH, found " + agreementAlg);  
    }
    if ("ECDH".equals(agreementAlg) && !(params instanceof ECParameterSpec)) {
      throw new IllegalArgumentException("Expected ECParameterSpec for agreement algorithm " + agreementAlg + ", found " + params.getClass().getCanonicalName());
    } else if ("DH".equals(agreementAlg) && !(params instanceof DHParameterSpec)) {
      throw new IllegalArgumentException("Expected DHParameterSpec for agreement algorithm " + agreementAlg + ", found " + params.getClass().getCanonicalName());
    }
    
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
      service.sendMSESetATMutualAuth(wrapper, oid, PassportApduService.MRZ_PACE_KEY_REFERENCE, referencePrivateKeyOrForComputingSessionKey);
    } catch (CardServiceException cse) {
      throw new PACEException("PICC side error in static PACE key derivation step", cse.getSW());
    }
    
    /*
     * PCD and PICC exchange a chain of general authenticate commands.
     * Steps 1 to 4 below correspond with steps in table in 3.3 of
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
    AlgorithmParameterSpec ephemeralParams = doPACEStep2(mappingType, agreementAlg, params, piccNonce);
    
    /* Choose random ephemeral PCD side keys (SK_PCD~, PK_PCD~, D~). */
    KeyPair pcdKeyPair = doPACEStep3GenerateKeyPair(agreementAlg, ephemeralParams);
    
    /*
     * Exchange PK_PCD~ and PK_PICC~ with PICC.
     * Check that PK_PCD~ and PK_PICC~ differ.
     */
    PublicKey piccPublicKey = doPACEStep3ExchangePublicKeys(agreementAlg,  cipherAlg,  keyLength, pcdKeyPair, ephemeralParams);
    
    /* Key agreement K = KA(SK_PCD~, PK_PICC~, D~). */
    byte[] sharedSecretBytes = doPACEStep3KeyAgreement(agreementAlg, pcdKeyPair, piccPublicKey);
    
    /* Derive secure messaging keys. */
    /* Compute session keys K_mac = KDF_mac(K), K_enc = KDF_enc(K). */    
    SecretKey encKey = null;
    SecretKey macKey = null;
    try {
      encKey = Util.deriveKey(sharedSecretBytes, cipherAlg, keyLength, Util.ENC_MODE);
      macKey = Util.deriveKey(sharedSecretBytes, cipherAlg, keyLength, Util.MAC_MODE);
    } catch (GeneralSecurityException gse) {
      LOGGER.severe("Exception: " + gse.getMessage());
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
      LOGGER.info("DEBUG: Starting secure messaging based on PACE");
    } catch (GeneralSecurityException gse) {
      LOGGER.severe("Exception: " + gse.getMessage());
      throw new IllegalStateException("Security exception in secure messaging establishment: " + gse.getMessage());
    }
    
    if (MappingType.CAM.equals(mappingType)) {
      LOGGER.info("DEBUG: Inspecting EF.CardSecurity for Chip Authentication Mapping");
      /*
       * TODO:
       *    - read and verify CardSecurity
       *    - use the Public Key from CardSecurity together with the Mapping Data and
       *      the Chip Authentication Data received as part of PACE-CAM to authenticate
       *      the chip (section 3.4.4.2).
       *      
       *    The terminal SHALL decrypt A_PICC to recover CA_PICC and verify
       *    PK_{Map,PICC}=KA(CA_PICC, PK_PICC,D_PICC),where PK_PICC is the static public key of the MRTD chip.
       */
    }
    
    return new PACEResult(mappingType, agreementAlg, cipherAlg, digestAlg, keyLength,
        piccNonce, ephemeralParams, pcdKeyPair, piccPublicKey, sharedSecretBytes, wrapper);
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
   * @param piccNonce the received nonce from the PICC
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
  public AlgorithmParameterSpec doPACEStep2(MappingType mappingType, String agreementAlg, AlgorithmParameterSpec params, byte[] piccNonce) throws PACEException {
    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(agreementAlg, BC_PROVIDER);
      keyPairGenerator.initialize(params);
      KeyPair kp = keyPairGenerator.generateKeyPair();
      PublicKey pcdMappingPublicKey = kp.getPublic();
      PrivateKey pcdMappingPrivateKey = kp.getPrivate();
      KeyAgreement mappingAgreement = KeyAgreement.getInstance(agreementAlg);
      mappingAgreement.init(pcdMappingPrivateKey);
      
      switch(mappingType) {
        case CAM:
          /* NOTE: Fall through. */
        case GM:
          byte[] pcdMappingEncodedPublicKey = Util.encodePublicKeyForSmartCard(pcdMappingPublicKey);            
          byte[] step2Data = Util.wrapDO((byte)0x81, pcdMappingEncodedPublicKey);
          byte[] step2Response = service.sendGeneralAuthenticate(wrapper, step2Data, false);
          byte[] piccMappingEncodedPublicKey = Util.unwrapDO((byte)0x82, step2Response);
          PublicKey piccMappingPublicKey = Util.decodePublicKeyFromSmartCard(piccMappingEncodedPublicKey, params);
          mappingAgreement.doPhase(piccMappingPublicKey, true);
          byte[] mappingSharedSecretBytes = mappingAgreement.generateSecret();
          
          return Util.mapNonceGM(piccNonce, mappingSharedSecretBytes, params);
        case IM:
          /* NOTE: The context specific data object 0x82 SHALL be empty (TR SAC 3.3.2). */
          throw new PACEException("Integrated Mapping not yet implemented"); // FIXME
        default:
          throw new PACEException("Unsupported mapping type " + mappingType);
      }
    } catch (GeneralSecurityException gse) {
      throw new PACEException("PCD side error in mapping nonce step: " + gse.getMessage());
    } catch (CardServiceException cse) {
      throw new PACEException("PICC side exception in mapping nonce step", cse.getSW());
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
  public PublicKey doPACEStep3ExchangePublicKeys(String agreementAlg, String cipherAlg, int keyLength,
      KeyPair pcdKeyPair,
      AlgorithmParameterSpec ephemeralParams)  throws PACEException {    
    try {
      PublicKey pcdPublicKey = pcdKeyPair.getPublic();
      byte[] pcdEncodedPublicKey = Util.encodePublicKeyForSmartCard(pcdPublicKey);
      byte[] step3Data = Util.wrapDO((byte)0x83, pcdEncodedPublicKey);
      byte[] step3Response = service.sendGeneralAuthenticate(wrapper, step3Data, false);
      byte[] piccEncodedPublicKey = Util.unwrapDO((byte)0x84, step3Response);
      PublicKey piccPublicKey = Util.decodePublicKeyFromSmartCard(piccEncodedPublicKey, ephemeralParams);
      //      ECPoint piccPublicKeyECPoint = ((ECPublicKey)piccPublicKey).getW();
      //      BigInteger p = Util.getPrime(ephemeralParams);
      if (pcdPublicKey.equals(piccPublicKey)) { throw new PACEException("PCD's public key and PICC's public key are the same in key agreement step!"); }
      
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
  public byte[] doPACEStep3KeyAgreement(String agreementAlg, KeyPair pcdKeyPair, PublicKey piccPublicKey) throws PACEException {
    try {
      KeyAgreement keyAgreement = KeyAgreement.getInstance(agreementAlg, BC_PROVIDER);
      keyAgreement.init(pcdKeyPair.getPrivate());
      keyAgreement.doPhase(piccPublicKey, true);
      return keyAgreement.generateSecret();
    } catch (GeneralSecurityException gse) {
      LOGGER.log(Level.SEVERE, "PCD side error during key agreement", gse);
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
      byte[] pcdToken = Util.generateAuthenticationToken(oid, macKey, piccPublicKey);
      byte[] step4Data = Util.wrapDO((byte)0x85, pcdToken);
      byte[] step4Response = service.sendGeneralAuthenticate(wrapper, step4Data, true);
      byte[] piccToken = Util.unwrapDO((byte)0x86, step4Response);
      byte[] expectedPICCToken = Util.generateAuthenticationToken(oid, macKey, pcdKeyPair.getPublic());
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
   */
  public static SecretKey deriveStaticPACEKey(BACKeySpec keySpec, String oid) throws GeneralSecurityException {
    String cipherAlg  = PACEInfo.toCipherAlgorithm(oid); /* Either DESede or AES. */
    int keyLength = PACEInfo.toKeyLength(oid); /* Of the enc cipher. Either 128, 192, or 256. */
    byte[] keySeed = computeKeySeedForPACE(keySpec);
    return Util.deriveKey(keySeed, cipherAlg, keyLength, Util.PACE_MODE);
  }
  
  public static byte[] computeKeySeedForPACE(BACKeySpec bacKey) throws GeneralSecurityException {
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
    
    byte[] keySeed = Util.computeKeySeedForPACE(documentNumber, dateOfBirth, dateOfExpiry);
    
    return keySeed;
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
}
