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

package org.jmrtd.lds;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.eac.EACObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

/* FIXME: dependency on BC in interface? */

/**
 * Abstract base class for security info structure.
 * See the BSI EAC 1.11 specification.
 * See the ICAO TR - SAC v1.1 specification.
 *
 * @author The JMRTD team (info@jmrtd.org)
 * 
 * @version $Revision$
 */
public abstract class SecurityInfo extends AbstractLDSInfo {
  
  private static final long serialVersionUID = -7919854443619069808L;
  
  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");
  
  /**
   * Used in ECDSA based Active Authentication.
   * <code>{joint-iso-itu-t(2) international-organizations(23) 136 mrtd(1) security(1) aaProtocolObject(5)}</code>.
   */
  public static final String ID_AA = "2.23.136.1.1.5";
  
  public static final String
  ID_PK_DH = EACObjectIdentifiers.id_PK_DH.getId(),
  ID_PK_ECDH = EACObjectIdentifiers.id_PK_ECDH.getId();

  /**
   * Used in Chip Authentication 1 and 2.
   */
  public static final String
  ID_CA_DH_3DES_CBC_CBC = EACObjectIdentifiers.id_CA_DH_3DES_CBC_CBC.getId(),
  ID_CA_ECDH_3DES_CBC_CBC = EACObjectIdentifiers.id_CA_ECDH_3DES_CBC_CBC.getId(),
  ID_CA_DH_AES_CBC_CMAC_128 = "0.4.0.127.0.7.2.2.3.1.2",
  ID_CA_DH_AES_CBC_CMAC_192 = "0.4.0.127.0.7.2.2.3.1.3",
  ID_CA_DH_AES_CBC_CMAC_256 = "0.4.0.127.0.7.2.2.3.1.4",
  ID_CA_ECDH_AES_CBC_CMAC_128 = "0.4.0.127.0.7.2.2.3.2.2",
  ID_CA_ECDH_AES_CBC_CMAC_192 = "0.4.0.127.0.7.2.2.3.2.3",
  ID_CA_ECDH_AES_CBC_CMAC_256 = "0.4.0.127.0.7.2.2.3.2.4";

  /**
   * Used in Terminal Authentication 1 and 2.
   */
  public static final String
  ID_TA = EACObjectIdentifiers.id_TA.getId(),
  ID_TA_RSA = EACObjectIdentifiers.id_TA_RSA.getId(),
  ID_TA_RSA_V1_5_SHA_1 = EACObjectIdentifiers.id_TA_RSA_v1_5_SHA_1.getId(),
  ID_TA_RSA_V1_5_SHA_256 = EACObjectIdentifiers.id_TA_RSA_v1_5_SHA_256.getId(),
  ID_TA_RSA_PSS_SHA_1 = EACObjectIdentifiers.id_TA_RSA_PSS_SHA_1.getId(),
  ID_TA_RSA_PSS_SHA_256 = EACObjectIdentifiers.id_TA_RSA_PSS_SHA_256.getId(),
  ID_TA_ECDSA = EACObjectIdentifiers.id_TA_ECDSA.getId(),
  ID_TA_ECDSA_SHA_1 = EACObjectIdentifiers.id_TA_ECDSA_SHA_1.getId(),
  ID_TA_ECDSA_SHA_224 = EACObjectIdentifiers.id_TA_ECDSA_SHA_224.getId(),
  ID_TA_ECDSA_SHA_256 = EACObjectIdentifiers.id_TA_ECDSA_SHA_256.getId();
    
  public static final String
  ID_EC_PUBLIC_KEY_TYPE = X9ObjectIdentifiers.id_publicKeyType.getId(),
  ID_EC_PUBLIC_KEY = X9ObjectIdentifiers.id_ecPublicKey.getId();
  
  private static final String ID_BSI = "0.4.0.127.0.7";
  
  /* protocols (2), smartcard (2), PACE (4) */
  public static final String ID_PACE = ID_BSI + ".2.2.4";
    
  public static final String
  ID_PACE_DH_GM = ID_PACE + ".1",
  ID_PACE_DH_GM_3DES_CBC_CBC = ID_PACE_DH_GM + ".1", /* 0.4.0.127.0.7.2.2.4.1.1, id-PACE-DH-GM-3DES-CBC-CBC */
  ID_PACE_DH_GM_AES_CBC_CMAC_128 = ID_PACE_DH_GM + ".2", /* 0.4.0.127.0.7.2.2.4.1.2, id-PACE-DH-GM-AES-CBC-CMAC-128 */
  ID_PACE_DH_GM_AES_CBC_CMAC_192 = ID_PACE_DH_GM + ".3", /* 0.4.0.127.0.7.2.2.4.1.3, id-PACE-DH-GM-AES-CBC-CMAC-192 */
  ID_PACE_DH_GM_AES_CBC_CMAC_256 = ID_PACE_DH_GM + ".4"; /* 0.4.0.127.0.7.2.2.4.1.4, id-PACE-DH-GM-AES-CBC-CMAC-256 */
  
  public static final String
  ID_PACE_ECDH_GM = ID_PACE + ".2",
  ID_PACE_ECDH_GM_3DES_CBC_CBC = ID_PACE_ECDH_GM + ".1", /* 0.4.0.127.0.7.2.2.4.2.1, id-PACE-ECDH-GM-3DES-CBC-CBC */
  ID_PACE_ECDH_GM_AES_CBC_CMAC_128 = ID_PACE_ECDH_GM + ".2", /* 0.4.0.127.0.7.2.2.4.2.2, id-PACE-ECDH-GM-AES-CBC-CMAC-128 */
  ID_PACE_ECDH_GM_AES_CBC_CMAC_192 = ID_PACE_ECDH_GM + ".3", /* 0.4.0.127.0.7.2.2.4.2.3, id-PACE-ECDH-GM-AES-CBC-CMAC-192 */
  ID_PACE_ECDH_GM_AES_CBC_CMAC_256 = ID_PACE_ECDH_GM + ".4"; /* 0.4.0.127.0.7.2.2.4.2.4, id-PACE-ECDH-GM-AES-CBC-CMAC-256 */
  
  public static final String
  ID_PACE_DH_IM = ID_PACE + ".3",
  ID_PACE_DH_IM_3DES_CBC_CBC = ID_PACE_DH_IM + ".1", /* 0.4.0.127.0.7.2.2.4.3.1, id-PACE-DH-IM-3DES-CBC-CBC */
  ID_PACE_DH_IM_AES_CBC_CMAC_128 = ID_PACE_DH_IM + ".2", /* 0.4.0.127.0.7.2.2.4.3.2, id-PACE-DH-IM-AES-CBC-CMAC-128 */
  ID_PACE_DH_IM_AES_CBC_CMAC_192 = ID_PACE_DH_IM + ".3", /* 0.4.0.127.0.7.2.2.4.3.3, id-PACE-DH-IM-AES-CBC-CMAC-192 */
  ID_PACE_DH_IM_AES_CBC_CMAC_256 = ID_PACE_DH_IM + ".4"; /* 0.4.0.127.0.7.2.2.4.3.4, id-PACE-DH-IM-AES-CBC-CMAC-256 */
  
  public static final String
  ID_PACE_ECDH_IM = ID_PACE + ".4",
  ID_PACE_ECDH_IM_3DES_CBC_CBC = ID_PACE_ECDH_IM + ".1", /* 0.4.0.127.0.7.2.2.4.4.1, id-PACE-ECDH-IM-3DES-CBC-CBC */
  ID_PACE_ECDH_IM_AES_CBC_CMAC_128 = ID_PACE_ECDH_IM + ".2", /* 0.4.0.127.0.7.2.2.4.4.2, id-PACE-ECDH-IM-AES-CBC-CMAC-128 */
  ID_PACE_ECDH_IM_AES_CBC_CMAC_192 = ID_PACE_ECDH_IM + ".3", /* 0.4.0.127.0.7.2.2.4.4.3, id-PACE-ECDH-IM-AES-CBC-CMAC-192 */
  ID_PACE_ECDH_IM_AES_CBC_CMAC_256 = ID_PACE_ECDH_IM + ".4"; /* 0.4.0.127.0.7.2.2.4.4.4, id-PACE-ECDH-IM-AES-CBC-CMAC-256 */
  
  public static final String
  ID_PACE_ECDH_CAM = ID_PACE + ".6",
  ID_PACE_ECDH_CAM_AES_CBC_CMAC_128 = ID_PACE_ECDH_CAM + ".2", /* 0.4.0.127.0.7.2.2.4.6.2, id-PACE-ECDH-CAM-AES-CBC-CMAC-128 */
  ID_PACE_ECDH_CAM_AES_CBC_CMAC_192 = ID_PACE_ECDH_CAM + ".3", /* 0.4.0.127.0.7.2.2.4.6.3, id-PACE-ECDH-CAM-AES-CBC-CMAC-192 */
  ID_PACE_ECDH_CAM_AES_CBC_CMAC_256 = ID_PACE_ECDH_CAM + ".4"; /* 0.4.0.127.0.7.2.2.4.6.4, id-PACE-ECDH-CAM-AES-CBC-CMAC-256 */
  
  /**
   * Returns a DER object with this SecurityInfo data (DER sequence)
   *
   * @return a DER object with this SecurityInfo data
   *
   * @deprecated Remove this method from visible interface (because of dependency on BC API)
   */
  public abstract ASN1Primitive getDERObject();
  
  /**
   * Writes this SecurityInfo to output stream.
   *
   * @param outputStream an ouput stream
   *
   * @throws IOException if writing fails
   */
  public void writeObject(OutputStream outputStream) throws IOException {
    ASN1Primitive derEncoded = getDERObject();
    if (derEncoded == null) {
      throw new IOException("Could not decode from DER.");
    }
    
    byte[] derEncodedBytes = derEncoded.getEncoded(ASN1Encoding.DER);
    if (derEncodedBytes == null) {
      throw new IOException("Could not decode from DER.");
    }
    
    outputStream.write(derEncodedBytes);
  }
  
  /**
   * Gets the protocol object identifier of this SecurityInfo.
   *
   * @return this protocol object identifier
   */
  public abstract String getObjectIdentifier();
  
  public abstract String getProtocolOIDString();
    
  /**
   * Factory method for creating security info objects given an input.
   *
   * @param obj the input
   *
   * @return a concrete security info object
   */
  public static SecurityInfo getInstance(ASN1Primitive obj) {
    try {
      ASN1Sequence sequence = (ASN1Sequence)obj;
      String oid = ((ASN1ObjectIdentifier)sequence.getObjectAt(0)).getId();
      ASN1Primitive requiredData = sequence.getObjectAt(1).toASN1Primitive();
      ASN1Primitive optionalData = null;
      if (sequence.size() == 3) {
        optionalData = sequence.getObjectAt(2).toASN1Primitive();
      }
      
      if (ActiveAuthenticationInfo.checkRequiredIdentifier(oid)) {
        int version = ((ASN1Integer)requiredData).getValue().intValue();
        if (optionalData == null) {
          return new ActiveAuthenticationInfo(oid, version, null);
        } else {
          String signatureAlgorithmOID = ((ASN1ObjectIdentifier)optionalData).getId();
          return new ActiveAuthenticationInfo(oid, version, signatureAlgorithmOID);
        }
      } else if (ChipAuthenticationPublicKeyInfo.checkRequiredIdentifier(oid)) {
        SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo((ASN1Sequence)requiredData);
        if (optionalData == null) {
          return new ChipAuthenticationPublicKeyInfo(oid, subjectPublicKeyInfo);
        } else {
          ASN1Integer optionalDataAsASN1Integer = (ASN1Integer)optionalData;
          BigInteger keyId = optionalDataAsASN1Integer.getValue();
          return new ChipAuthenticationPublicKeyInfo(oid, subjectPublicKeyInfo, keyId);
        }
      } else if (ChipAuthenticationInfo.checkRequiredIdentifier(oid)) {
        int version = ((ASN1Integer)requiredData).getValue().intValue();
        if (optionalData == null) {
          return new ChipAuthenticationInfo(oid, version);
        } else {
          ASN1Integer optionalDataAsASN1Integer = (ASN1Integer)optionalData;
          BigInteger keyId = optionalDataAsASN1Integer.getValue();
          return new ChipAuthenticationInfo(oid, version, keyId);
        }
      } else if (TerminalAuthenticationInfo.checkRequiredIdentifier(oid)) {
        int version = ((ASN1Integer)requiredData).getValue().intValue();
        if (optionalData == null) {
          return new TerminalAuthenticationInfo(oid, version);
        } else {
          ASN1Sequence efCVCA = (ASN1Sequence)optionalData;
          return new TerminalAuthenticationInfo(oid, version, efCVCA);
        }
      } else if (PACEInfo.checkRequiredIdentifier(oid)) {
        int version = ((ASN1Integer)requiredData).getValue().intValue();
        int parameterId = -1;
        if (optionalData != null) {
          parameterId = ((ASN1Integer)optionalData).getValue().intValue();
        }
        return new PACEInfo(oid, version, parameterId);
      } else if (PACEDomainParameterInfo.checkRequiredIdentifier(oid)) {
        AlgorithmIdentifier domainParameters = AlgorithmIdentifier.getInstance(requiredData);
        if (optionalData != null) {
          BigInteger parameterId = ((ASN1Integer)optionalData).getValue();
          return new PACEDomainParameterInfo(oid, domainParameters, parameterId);
        }
        return new PACEDomainParameterInfo(oid, domainParameters);
      }
      //			throw new IllegalArgumentException("Malformed input stream.");
      LOGGER.warning("Unsupported SecurityInfo, oid = " + oid);
      return null;
    } catch (Exception e) {
      LOGGER.log(Level.SEVERE, "Exception", e);
      throw new IllegalArgumentException("Malformed input stream.");
    }
  }  
}
