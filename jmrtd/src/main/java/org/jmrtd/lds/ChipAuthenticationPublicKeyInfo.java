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
import java.security.PublicKey;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DLSequence;
import org.jmrtd.Util;

/**
 * A concrete SecurityInfo structure that stores chip authentication public
 * key info, see EAC TR 03110 1.11 specification.
 *
 * This data structure provides a Chip Authentication Public Key of the MRTD chip.
 * <ul>
 * <li>The object identifier <code>protocol</code> SHALL identify the type of the public key
 *     (i.e. DH or ECDH).</li>
 * <li>The sequence <code>chipAuthenticationPublicKey</code> SHALL contain the public key
 *     in encoded form.</li>
 * <li>The integer <code>keyId</code> MAY be used to indicate the local key identifier.
 *     It MUST be used if the MRTD chip provides multiple public keys for Chip
 *     Authentication.</li>
 * </ul>
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision$
 */
public class ChipAuthenticationPublicKeyInfo extends SecurityInfo {

  private static final long serialVersionUID = 5687291829854501771L;

  private String oid;

  private BigInteger keyId; /* Optional, use null if implicit. */

  private PublicKey publicKey;

  /**
   * Creates a public key info structure with implicit key identifier.
   *
   * @param publicKey Either a DH public key or an EC public key
   */
  public ChipAuthenticationPublicKeyInfo(PublicKey publicKey) {
    this(publicKey, null);
  }

  /**
   * Creates a public key info structure.
   *
   * @param publicKey Either a DH public key or an EC public key
   * @param keyId key identifier
   */
  public ChipAuthenticationPublicKeyInfo(PublicKey publicKey, BigInteger keyId) {
    this(Util.inferProtocolIdentifier(publicKey), publicKey, keyId);
  }

  /**
   * Creates a public key info structure with implicit key identifier.
   *
   * @param oid a proper public key identifier
   * @param publicKey appropriate public key
   */
  public ChipAuthenticationPublicKeyInfo(String oid, PublicKey publicKey) {
    this(oid, publicKey, null);
  }

  /**
   * Creates a public key info structure.
   *
   * @param oid a proper public key identifier
   * @param publicKey appropriate public key
   * @param keyId the key identifier or {@code null} if not present
   */
  public ChipAuthenticationPublicKeyInfo(String oid, PublicKey publicKey, BigInteger keyId) {
    this.oid = oid;
    this.publicKey = Util.reconstructPublicKey(publicKey);
    this.keyId = keyId;
    checkFields();
  }

  @Override
  @Deprecated
  public ASN1Primitive getDERObject() {
    ASN1EncodableVector vector = new ASN1EncodableVector();
    vector.add(new ASN1ObjectIdentifier(oid));
    vector.add((Util.toSubjectPublicKeyInfo(publicKey).toASN1Primitive()));
    if (keyId != null) {
      vector.add(new ASN1Integer(keyId));
    }
    return new DLSequence(vector);
  }

  @Override
  public String getObjectIdentifier() {
    return oid;
  }

  /**
   * Gets the protocol object identifier as a human readable string.
   *
   * @return a string
   */
  @Override
  public String getProtocolOIDString() {
    return toProtocolOIDString(oid);
  }

  /**
   * Returns a key identifier stored in this ChipAuthenticationPublicKeyInfo
   * structure, {@code null} if not present.
   *
   * @return key identifier stored in this ChipAuthenticationPublicKeyInfo structure
   */
  public BigInteger getKeyId() {
    return keyId;
  }

  /**
   * Returns a SubjectPublicKeyInfo contained in this
   * ChipAuthenticationPublicKeyInfo structure.
   *
   * @return SubjectPublicKeyInfo contained in this
   *         ChipAuthenticationPublicKeyInfo structure
   */
  public PublicKey getSubjectPublicKey() {
    return publicKey;
  }

  /**
   * Checks the correctness of the data for this instance of SecurityInfo
   */
  // FIXME: also check type of public key
  protected void checkFields() {
    try {
      if (!checkRequiredIdentifier(oid)) {
        throw new IllegalArgumentException("Wrong identifier: " + oid);
      }
    } catch (Exception e) {
      throw new IllegalArgumentException("Malformed ChipAuthenticationInfo", e);
    }
  }

  /**
   * Checks whether the given object identifier identifies a
   * ChipAuthenticationPublicKeyInfo structure.
   *
   * @param oid object identifier
   *
   * @return true if the match is positive
   */
  public static boolean checkRequiredIdentifier(String oid) {
    return ID_PK_DH.equals(oid) || ID_PK_ECDH.equals(oid);
  }

  @Override
  public String toString() {
    return "ChipAuthenticationPublicKeyInfo ["
        + "protocol: " + toProtocolOIDString(oid) + ", "
        + "chipAuthenticationPublicKey: " + Util.getDetailedPublicKeyAlgorithm(getSubjectPublicKey()) + ", "
        + "keyId: " + (keyId == null ? "-" : keyId.toString())
        + "]";
  }

  @Override
  public int hashCode() {
    return 	123 + 1337 * (oid.hashCode() + (keyId == null ? 111 : keyId.hashCode()) + (publicKey == null ? 111 : publicKey.hashCode()));
  }

  @Override
  public boolean equals(Object other) {
    if (other == null) {
      return false;
    }
    if (other == this) {
      return true;
    }
    if (!ChipAuthenticationPublicKeyInfo.class.equals(other.getClass())) {
      return false;
    }

    ChipAuthenticationPublicKeyInfo otherInfo = (ChipAuthenticationPublicKeyInfo)other;
    return oid.equals(otherInfo.oid)
        && (keyId == null && otherInfo.keyId == null || keyId != null && keyId.equals(otherInfo.keyId))
        && publicKey.equals(otherInfo.publicKey);
  }

  private static String toProtocolOIDString(String oid) {
    if (ID_PK_DH.equals(oid)) {
      return "id-PK-DH";
    }
    if (ID_PK_ECDH.equals(oid)) {
      return "id-PK-ECDH";
    }

    return oid;
  }
}
