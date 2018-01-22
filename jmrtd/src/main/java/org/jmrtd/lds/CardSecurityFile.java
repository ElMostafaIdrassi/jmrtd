/*
 * JMRTD - A Java API for accessing machine readable travel documents.
 *
 * Copyright (C) 2006 - 2018  The JMRTD team
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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;

/**
 * Card security file stores a set of SecurityInfos for PACE with Chip Authentication Mapping (CAM).
 *
 * FIXME: Strictly speaking this file is not part of the LDS (or even the MRTD application)! Move it out of this package? -- MO
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision$
 *
 * @since 0.5.6
 */
public class CardSecurityFile implements Serializable {

  private static final long serialVersionUID = -3535507558193769952L;

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  private static final String CONTENT_TYPE_OID = "0.4.0.127.0.7.3.2.1"; // FIXME

  private String digestAlgorithm;

  private String digestEncryptionAlgorithm;

  /** The security infos that make up this file. */
  private Set<SecurityInfo> securityInfos;

  /** The signature bytes. */
  private byte[] encryptedDigest;

  /** The embedded document signer certificate. */
  private X509Certificate certificate;

  /**
   * Constructs a new file from the provided data.
   *
   * @param digestAlgorithm the digest algorithm as Java mnemonic
   * @param digestEncryptionAlgorithm the signature algorithm as Java mnemonic
   * @param securityInfos a non-empty list of security infos
   * @param privateKey the private signing key
   * @param certificate the certificate to embed, which should correspond to the given private key
   */
  public CardSecurityFile(String digestAlgorithm, String digestEncryptionAlgorithm, Collection<SecurityInfo> securityInfos, PrivateKey privateKey, X509Certificate certificate) {
    this(digestAlgorithm, digestEncryptionAlgorithm, securityInfos, privateKey, certificate, null);
  }

  /**
   * Constructs a new file from the provided data.
   *
   * @param digestAlgorithm the digest algorithm as Java mnemonic
   * @param digestEncryptionAlgorithm the signature algorithm as Java mnemonic
   * @param securityInfos a non-empty list of security infos
   * @param privateKey the private signing key
   * @param certificate the certificate to embed, which should correspond to the given private key
   * @param provider the security provider to use
   */
  public CardSecurityFile(String digestAlgorithm, String digestEncryptionAlgorithm, Collection<SecurityInfo> securityInfos, PrivateKey privateKey, X509Certificate certificate, String provider) {
    this(digestAlgorithm, digestEncryptionAlgorithm, securityInfos, (byte[])null, certificate);
    ContentInfo contentInfo = toContentInfo(CONTENT_TYPE_OID, securityInfos);
    this.encryptedDigest = SignedDataUtil.signData(digestAlgorithm, digestEncryptionAlgorithm, CONTENT_TYPE_OID, contentInfo, privateKey, provider);
  }

  /**
   * Constructs a new file from the provided data.
   *
   * @param digestAlgorithm the digest algorithm as Java mnemonic
   * @param digestEncryptionAlgorithm the signature algorithm as Java mnemonic
   * @param securityInfos a non-empty list of security infos
   * @param encryptedDigest the signature
   * @param certificate the certificate to embed
   */
  public CardSecurityFile(String digestAlgorithm, String digestEncryptionAlgorithm, Collection<SecurityInfo> securityInfos, byte[] encryptedDigest, X509Certificate certificate) {
    if (securityInfos == null) {
      throw new IllegalArgumentException("Null securityInfos");
    }
    if (certificate == null) {
      throw new IllegalArgumentException("Null certificate");
    }

    this.digestAlgorithm = digestAlgorithm;
    this.digestEncryptionAlgorithm = digestEncryptionAlgorithm;
    this.securityInfos = new HashSet<SecurityInfo>(securityInfos);
    this.encryptedDigest = encryptedDigest;
    this.certificate = certificate;
  }

  /**
   * Constructs a new file from the data in an input stream.
   *
   * @param inputStream the input stream to parse the data from
   *
   * @throws IOException on error reading input stream
   */
  public CardSecurityFile(InputStream inputStream) throws IOException {
    readContent(inputStream);
  }

  public String getDigestAlgorithm() {
    return digestAlgorithm;
  }

  public String getDigestEncryptionAlgorithm() {
    return digestEncryptionAlgorithm;
  }

  public byte[] getEncryptedDigest() {
    return encryptedDigest;
  }

  protected void readContent(InputStream inputStream) throws IOException {
    SignedData signedData = SignedDataUtil.readSignedData(inputStream);

    this.digestAlgorithm = SignedDataUtil.getSignerInfoDigestAlgorithm(signedData);
    this.digestEncryptionAlgorithm = SignedDataUtil.getDigestEncryptionAlgorithm(signedData);

    try {
      this.certificate = SignedDataUtil.getDocSigningCertificate(signedData);
    } catch (CertificateException ce) {
      LOGGER.log(Level.WARNING, "Exceptiong while extracting document signing certificate", ce);
    }

    this.securityInfos = getSecurityInfos(signedData);

    this.encryptedDigest = SignedDataUtil.getEncryptedDigest(signedData);
  }

  protected void writeContent(OutputStream outputStream) throws IOException {
    try {
      ContentInfo contentInfo = toContentInfo(CONTENT_TYPE_OID, securityInfos);
      SignedData signedData = SignedDataUtil.createSignedData(digestAlgorithm, digestEncryptionAlgorithm, CONTENT_TYPE_OID, contentInfo, encryptedDigest, certificate);
      SignedDataUtil.writeData(signedData, outputStream);
    } catch (CertificateException ce) {
      throw new IOException("Certificate exception during SignedData creation", ce);
    } catch (NoSuchAlgorithmException nsae) {
      throw new IOException("Unsupported algorithm", nsae);
    } catch (GeneralSecurityException gse) {
      throw new IOException("General security exception", gse);
    }
  }

  /**
   * Gets the DER encoded file.
   *
   * @return the encoded file
   */
  public byte[] getEncoded() {
    try {
      ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
      writeContent(outputStream);
      outputStream.close();
      return outputStream.toByteArray();
    } catch (IOException ioe) {
      LOGGER.log(Level.WARNING, "Exception while encoding CardSecurityFile", ioe);
      return null;
    }
  }

  /**
   * Gets the security infos as an unordered collection.
   *
   * @return security infos
   */
  public Collection<SecurityInfo> getSecurityInfos() {
    return securityInfos;
  }

  /**
   * Gets the PACE infos embedded in this card access file.
   * If no infos are present, an empty list is returned.
   *
   * @return a list of PACE infos
   */
  public Collection<PACEInfo> getPACEInfos() {
    List<PACEInfo> paceInfos = new ArrayList<PACEInfo>(securityInfos.size());
    for (SecurityInfo securityInfo: securityInfos) {
      if (securityInfo instanceof PACEInfo) {
        paceInfos.add((PACEInfo)securityInfo);
      }
    }
    return paceInfos;
  }

  /**
   * Gets the CA public key infos embedded in this card access file.
   * If no infos are present, an empty list is returned.
   *
   * @return a list of CA public key infos
   */
  public Collection<ChipAuthenticationInfo> getChipAuthenticationInfos() {
    List<ChipAuthenticationInfo> chipAuthenticationInfos = new ArrayList<ChipAuthenticationInfo>(securityInfos.size());
    for (SecurityInfo securityInfo: securityInfos) {
      if (securityInfo instanceof ChipAuthenticationInfo) {
        chipAuthenticationInfos.add((ChipAuthenticationInfo)securityInfo);
      }
    }
    return chipAuthenticationInfos;
  }

  /**
   * Gets the CA public key infos embedded in this card access file.
   * If no infos are present, an empty list is returned.
   *
   * @return a list of CA public key infos
   */
  public Collection<ChipAuthenticationPublicKeyInfo> getChipAuthenticationPublicKeyInfos() {
    List<ChipAuthenticationPublicKeyInfo> chipAuthenticationPublicKeyInfos = new ArrayList<ChipAuthenticationPublicKeyInfo>(securityInfos.size());
    for (SecurityInfo securityInfo: securityInfos) {
      if (securityInfo instanceof ChipAuthenticationPublicKeyInfo) {
        chipAuthenticationPublicKeyInfos.add((ChipAuthenticationPublicKeyInfo)securityInfo);
      }
    }
    return chipAuthenticationPublicKeyInfos;
  }

  /**
   * Gets the signature algorithm object identifier.
   *
   * @return signature algorithm OID
   */
  @Override
  public String toString() {
    return "CardSecurityFile [" + securityInfos.toString() + "]";
  }

  /**
   * Tests equality with respect to another object.
   *
   * @param otherObj another object
   *
   * @return whether this object equals the other object
   */
  @Override
  public boolean equals(Object otherObj) {
    if (otherObj == null) {
      return false;
    }
    if (!(otherObj.getClass().equals(this.getClass()))) {
      return false;
    }
    CardSecurityFile other = (CardSecurityFile)otherObj;
    if (securityInfos == null) {
      return  other.securityInfos == null;
    }
    if (other.securityInfos == null) {
      return securityInfos == null;
    }
    return securityInfos.equals(other.securityInfos);
  }

  /**
   * Gets a hash code of this object.
   *
   * @return the hash code
   */
  @Override
  public int hashCode() {
    return 3 * securityInfos.hashCode() + 63;
  }

  /* FIXME: rewrite (using writeObject instead of getDERObject) to remove interface dependency on BC. */
  private static ContentInfo toContentInfo(String contentTypeOID, Collection<SecurityInfo> securityInfos) {
    try {
      ASN1EncodableVector vector = new ASN1EncodableVector();
      for (SecurityInfo securityInfo: securityInfos) {
        vector.add(securityInfo.getDERObject());
      }
      ASN1Set derSet = new DLSet(vector);

      return new ContentInfo(new ASN1ObjectIdentifier(contentTypeOID), new DEROctetString(derSet));
    } catch (IOException ioe) {
      LOGGER.log(Level.WARNING, "Error creating signedData", ioe);
      throw new IllegalArgumentException("Error DER encoding the security infos");
    }
  }

  private static Set<SecurityInfo> getSecurityInfos(SignedData signedData) throws IOException {
    ASN1Primitive encapsulatedContent = SignedDataUtil.getContent(signedData);

    if (!(encapsulatedContent instanceof ASN1Set)) {
      throw new IOException("Was expecting an ASN1Set, found " + encapsulatedContent.getClass());
    }

    ASN1Set set = (ASN1Set)encapsulatedContent;
    Set<SecurityInfo> securityInfos = new HashSet<SecurityInfo>();
    for (int i = 0; i < set.size(); i++) {
      ASN1Primitive object = set.getObjectAt(i).toASN1Primitive();
      try {
        SecurityInfo securityInfo = SecurityInfo.getInstance(object);
        if (securityInfo == null) {
          LOGGER.log(Level.WARNING, "Could not parse, skipping security info");
          continue;
        }
        securityInfos.add(securityInfo);
      } catch (Exception e) {
        LOGGER.log(Level.WARNING, "Exception while parsing, skipping security info", e);
      }
    }

    return securityInfos;
  }
}
