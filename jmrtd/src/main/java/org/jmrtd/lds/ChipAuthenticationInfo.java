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

package org.jmrtd.lds;

import java.math.BigInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DLSequence;

/**
 * A concrete SecurityInfo structure that stores chip authentication info,
 * see EAC 1.11 specification.
 *
 * This data structure provides detailed information on an implementation of
 * Chip Authentication.
 * <ul>
 * <li>The object identifier <code>protocol</code> SHALL identify the
 *     algorithms to be used (i.e. key agreement, symmetric cipher and MAC).</li>
 * <li>The integer <code>version</code> SHALL identify the version of the protocol.
 *     Currently, versions 1 and 2 are supported.</li>
 * <li>The integer <code>keyId</code> MAY be used to indicate the local key identifier.
 *     It MUST be used if the MRTD chip provides multiple public keys for Chip
 *     Authentication.</li>
 * </ul>
 *
 * @author Wojciech Mostowski (woj@cs.ru.nl)
 * 
 * @version $Revision$
 *
 * FIXME: dependency on BC?
 */
public class ChipAuthenticationInfo extends SecurityInfo {

  private static final long serialVersionUID = 5591988305059068535L;

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  /** Chip Authentication version. */
  public static final int
  VERSION_1 = 1,
  VERSION_2 = 2;

  private String oid;
  private int version;
  private BigInteger keyId;

  /**
   * Constructs a new object.
   *
   * @param oid a proper EAC identifier
   * @param version has to be 1 or 2
   */
  public ChipAuthenticationInfo(String oid, int version) {
    this(oid, version, null);
  }

  /**
   * Constructs a new object.
   *
   * @param oid a proper EAC identifier
   * @param version has to be 1 or 2
   * @param keyId the key identifier
   */
  public ChipAuthenticationInfo(String oid, int version, BigInteger keyId) {
    this.oid = oid;
    this.version = version;
    this.keyId = keyId;
    checkFields();
  }

  @Deprecated
  public ASN1Primitive getDERObject() {
    ASN1EncodableVector v = new ASN1EncodableVector();
    v.add(new ASN1ObjectIdentifier(oid));
    v.add(new ASN1Integer(version));
    if (keyId != null) {
      v.add(new ASN1Integer(keyId));
    }
    return new DLSequence(v);
  }

  /**
   * Gets the protocol object identifier.
   * 
   * @return the {@code ID_CA_} object identifier indicating the Chip Authentication protocol
   */
  public String getObjectIdentifier() {
    return oid;
  }

  public int getVersion() {
    return version;
  }

  /**
   * Gets the protocol object identifier as a human readable string.
   * 
   * @return a string
   */
  public String getProtocolOIDString() {
    return toProtocolOIDString(oid);
  }

  /**
   * Returns a key identifier stored in this ChipAuthenticationInfo structure,
   * {@code null} if not present.
   *
   * @return key identifier stored in this ChipAuthenticationInfo structure
   */
  public BigInteger getKeyId() {
    return keyId;
  }

  /**
   * Checks the correctness of the data for this instance of SecurityInfo
   */
  protected void checkFields() {
    try {
      if (!checkRequiredIdentifier(oid)) {
        throw new IllegalArgumentException("Wrong identifier: "	+ oid);
      }
      if (version != VERSION_1 && version != VERSION_2) {
        throw new IllegalArgumentException("Wrong version. Was expecting " + VERSION_1 + " or " + VERSION_2 + ", found " + version);
      }
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Unexpected exception", e);
      throw new IllegalArgumentException("Malformed ChipAuthenticationInfo.");
    }
  }

  /**
   * Checks whether the given object identifier identifies a
   * ChipAuthenticationInfo structure.
   *
   * FIXME: for EAC 1.11 only the 3DES OIDs are allowed.
   *
   * @param oid
   *            object identifier
   * @return true if the match is positive
   */
  static boolean checkRequiredIdentifier(String oid) {
    return ID_CA_DH_3DES_CBC_CBC.equals(oid)
        || ID_CA_ECDH_3DES_CBC_CBC.equals(oid)
        || ID_CA_DH_AES_CBC_CMAC_128.equals(oid)
        || ID_CA_DH_AES_CBC_CMAC_192.equals(oid)
        || ID_CA_DH_AES_CBC_CMAC_256.equals(oid)
        || ID_CA_ECDH_AES_CBC_CMAC_128.equals(oid)
        || ID_CA_ECDH_AES_CBC_CMAC_192.equals(oid)
        || ID_CA_ECDH_AES_CBC_CMAC_256.equals(oid);
  }

  public String toString() {
    return "ChipAuthenticationInfo ["
        + "protocol: " + toProtocolOIDString(oid)
        + ", version: " + version
        + ", keyId: " + (keyId == null ? "-" : keyId) + "]";
  }

  public int hashCode() {
    return 3 + 11 * (oid == null ? 0 : oid.hashCode()) + 61 * version + 1991 * (keyId == null ? 111 : keyId.hashCode());
  }

  public boolean equals(Object other) {
    if (other == null) { return false; }
    if (other == this) { return true; }
    if (!ChipAuthenticationInfo.class.equals(other.getClass())) { return false; }
    ChipAuthenticationInfo otherChipAuthenticationInfo = (ChipAuthenticationInfo)other;
    return oid.equals(otherChipAuthenticationInfo.oid)
        && version == otherChipAuthenticationInfo.version
        && (keyId == null && otherChipAuthenticationInfo.keyId == null || keyId != null && keyId.equals(otherChipAuthenticationInfo.keyId));
  }

  public static String toKeyAgreementAlgorithm(String oid) {
    if (ID_CA_DH_3DES_CBC_CBC.equals(oid)
        || ID_CA_DH_AES_CBC_CMAC_128.equals(oid)
        || ID_CA_DH_AES_CBC_CMAC_192.equals(oid)
        || ID_CA_DH_AES_CBC_CMAC_256.equals(oid)) {
      return "DH";
    } else if (ID_CA_ECDH_3DES_CBC_CBC.equals(oid)
        || ID_CA_ECDH_AES_CBC_CMAC_128.equals(oid)
        || ID_CA_ECDH_AES_CBC_CMAC_192.equals(oid)
        || ID_CA_ECDH_AES_CBC_CMAC_256.equals(oid)) {
      return "ECDH";
    }
    //    return null;
    throw new NumberFormatException("Unknown OID: " + oid == null ? "null" : "\"" + oid + "\"");
  }

  public static String toCipherAlgorithm(String oid) {
    if (ID_CA_DH_3DES_CBC_CBC.equals(oid)
        || ID_CA_ECDH_3DES_CBC_CBC.equals(oid)) {
      return "DESede";
    } else if (ID_CA_DH_AES_CBC_CMAC_128.equals(oid)
        || ID_CA_DH_AES_CBC_CMAC_192.equals(oid)
        || ID_CA_DH_AES_CBC_CMAC_256.equals(oid)
        || ID_CA_ECDH_AES_CBC_CMAC_128.equals(oid)
        || ID_CA_ECDH_AES_CBC_CMAC_192.equals(oid)
        || ID_CA_ECDH_AES_CBC_CMAC_256.equals(oid)) {
      return "AES";
    }
    //      return null;
    throw new NumberFormatException("Unknown OID: \"" + oid + "\"");
  }

  public static String toDigestAlgorithm(String oid) {
    if (ID_CA_DH_3DES_CBC_CBC.equals(oid)
        || ID_CA_ECDH_3DES_CBC_CBC.equals(oid)
        || ID_CA_DH_AES_CBC_CMAC_128.equals(oid)
        || ID_CA_ECDH_AES_CBC_CMAC_128.equals(oid)) {
      return "SHA-1";
    } else if (ID_CA_DH_AES_CBC_CMAC_192.equals(oid)
        || ID_CA_ECDH_AES_CBC_CMAC_192.equals(oid)
        || ID_CA_DH_AES_CBC_CMAC_256.equals(oid)
        || ID_CA_ECDH_AES_CBC_CMAC_256.equals(oid)) {
      return "SHA-256";
    }
    //      return null;
    throw new NumberFormatException("Unknown OID: \"" + oid + "\"");
  }

  public static int toKeyLength(String oid) {
    if (ID_CA_DH_3DES_CBC_CBC.equals(oid)
        || ID_CA_ECDH_3DES_CBC_CBC.equals(oid)
        || ID_CA_DH_AES_CBC_CMAC_128.equals(oid)
        || ID_CA_ECDH_AES_CBC_CMAC_128.equals(oid)) {
      return 128;
    } else if (ID_CA_DH_AES_CBC_CMAC_192.equals(oid)
        || ID_CA_ECDH_AES_CBC_CMAC_192.equals(oid)) {
      return 192;
    } else if (ID_CA_DH_AES_CBC_CMAC_256.equals(oid)
        || ID_CA_ECDH_AES_CBC_CMAC_256.equals(oid)) {
      return 256;
    } else {
      // return -1;
      throw new NumberFormatException("Unknown OID: \"" + oid + "\"");
    }
  }

  private static String toProtocolOIDString(String oid) {
    if (ID_CA_DH_3DES_CBC_CBC.equals(oid)) { return "id-CA-DH-3DES-CBC-CBC"; }
    if (ID_CA_DH_AES_CBC_CMAC_128.equals(oid)) { return "id-CA-DH-AES-CBC-CMAC-128"; }
    if (ID_CA_DH_AES_CBC_CMAC_192.equals(oid)) { return "id-CA-DH-AES-CBC-CMAC-192"; }
    if (ID_CA_DH_AES_CBC_CMAC_256.equals(oid)) { return "id-CA-DH-AES-CBC-CMAC-256"; }
    if (ID_CA_ECDH_3DES_CBC_CBC.equals(oid)) { return "id-CA-ECDH-3DES-CBC-CBC"; }
    if (ID_CA_ECDH_AES_CBC_CMAC_128.equals(oid)) { return "id-CA-ECDH-AES-CBC-CMAC-128"; }
    if (ID_CA_ECDH_AES_CBC_CMAC_192.equals(oid)) { return "id-CA-ECDH-AES-CBC-CMAC-192"; }
    if (ID_CA_ECDH_AES_CBC_CMAC_256.equals(oid)) { return "id-CA-ECDH-AES-CBC-CMAC-256"; }
    return oid;
  }
}
