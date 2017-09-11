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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Map;
import java.util.TreeMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.icao.DataGroupHash;
import org.bouncycastle.asn1.icao.LDSSecurityObject;
import org.bouncycastle.asn1.icao.LDSVersionInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * File structure for the EF_SOD file (the Document Security Object).
 * Based on Appendix 3 of Doc 9303 Part 1 Vol 2.
 *
 * Basically the Document Security Object is a SignedData type as specified in
 * <a href="http://www.ietf.org/rfc/rfc3369.txt">RFC 3369</a>.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision$
 */
public class SODFile extends AbstractTaggedLDSFile {

  private static final long serialVersionUID = -1081347374739311111L;

  //  private static final String SHA1_HASH_ALG_OID = "1.3.14.3.2.26";
  //  private static final String SHA1_WITH_RSA_ENC_OID = "1.2.840.113549.1.1.5";
  //  private static final String SHA256_HASH_ALG_OID = "2.16.840.1.101.3.4.2.1";
  //  private static final String E_CONTENT_TYPE_OID = "1.2.528.1.1006.1.20.1";

  /**
   * OID to indicate content-type in encapContentInfo.
   *
   * <pre>
   * id-icao-ldsSecurityObject OBJECT IDENTIFIER ::=
   *    {joint-iso-itu-t(2) international-organizations(23) icao(136) mrtd(1) security(1) ldsSecurityObject(1)}
   * </pre>
   */
  private static final String ICAO_LDS_SOD_OID = "2.23.136.1.1.1";

  /**
   * This TC_SOD_IOD is apparently used in
   * "PKI for Machine Readable Travel Documents Offering ICC Read-Only Access Version - 1.1, Annex C".
   * Seen in live French and Belgian MRTDs.
   *
   * <pre>
   * id-icao-ldsSecurityObjectid OBJECT IDENTIFIER ::=
   *    {iso(1) identified-organization(3) icao(27) atn-end-system-air(1) security(1) ldsSecurityObject(1)}
   * </pre>
   */
  private static final String ICAO_LDS_SOD_ALT_OID = "1.3.27.1.1.1";

  /**
   * This is used in some test MRTDs.
   * Appears to have been included in a "worked example" somewhere and perhaps used in live documents.
   *
   * <pre>
   * id-sdu-ldsSecurityObjectid OBJECT IDENTIFIER :=
   *    {iso(1) member-body(2) nl(528) nederlandse-organisatie(1) enschede-sdu(1006) 1 20 1}
   * </pre>
   */
  private static final String SDU_LDS_SOD_OID = "1.2.528.1.1006.1.20.1";

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  /*
   * FIXME: This field is now transient, but probably shouldn't be!
   * 
   * - We can either leave this transient and explicitly (de)serialize it in
   *   readObject/writeObject (using BC's getEncoded())
   * - Or replace this field with something that implements Serializable and that we control.
   */
  private transient SignedData signedData;

  /**
   * Constructs a Security Object data structure.
   *
   * @param digestAlgorithm a digest algorithm, such as "SHA1" or "SHA256"
   * @param digestEncryptionAlgorithm a digest encryption algorithm, such as "SHA256withRSA"
   * @param dataGroupHashes maps datagroup numbers (1 to 16) to hashes of the data groups
   * @param privateKey private key to sign the data
   * @param docSigningCertificate the document signing certificate
   *
   * @throws NoSuchAlgorithmException if either of the algorithm parameters is not recognized
   * @throws CertificateException if the document signing certificate cannot be used
   */
  public SODFile(String digestAlgorithm, String digestEncryptionAlgorithm,
      Map<Integer, byte[]> dataGroupHashes,
      PrivateKey privateKey,
      X509Certificate docSigningCertificate) throws NoSuchAlgorithmException, CertificateException {
    this(digestAlgorithm, digestEncryptionAlgorithm, dataGroupHashes, privateKey, docSigningCertificate, null);
  }

  /**
   * Constructs a Security Object data structure using a specified signature provider.
   *
   * @param digestAlgorithm a digest algorithm, such as "SHA-1" or "SHA-256"
   * @param digestEncryptionAlgorithm a digest encryption algorithm, such as "SHA256withRSA"
   * @param dataGroupHashes maps datagroup numbers (1 to 16) to hashes of the data groups
   * @param privateKey private key to sign the contents
   * @param docSigningCertificate the document signing certificate to embed
   * @param provider specific signature provider that should be used to create the signature
   *
   * @throws NoSuchAlgorithmException if either of the algorithm parameters is not recognized
   * @throws CertificateException if the document signing certificate cannot be used
   */
  public SODFile(String digestAlgorithm, String digestEncryptionAlgorithm,
      Map<Integer, byte[]> dataGroupHashes,
      PrivateKey privateKey,
      X509Certificate docSigningCertificate, String provider) throws NoSuchAlgorithmException, CertificateException {
    this(digestAlgorithm, digestEncryptionAlgorithm, dataGroupHashes, privateKey, docSigningCertificate, provider, null, null);
  }

  /**
   * Constructs a Security Object data structure using a specified signature provider.
   *
   * @param digestAlgorithm a digest algorithm, such as "SHA-1" or "SHA-256"
   * @param digestEncryptionAlgorithm a digest encryption algorithm, such as "SHA256withRSA"
   * @param dataGroupHashes maps datagroup numbers (1 to 16) to hashes of the data groups
   * @param privateKey private key to sign the data
   * @param docSigningCertificate the document signing certificate
   * @param provider specific signature provider that should be used to create the signature
   * @param ldsVersion LDS version
   * @param unicodeVersion Unicode version
   *
   * @throws NoSuchAlgorithmException if either of the algorithm parameters is not recognized
   * @throws CertificateException if the document signing certificate cannot be used
   */
  public SODFile(String digestAlgorithm, String digestEncryptionAlgorithm,
      Map<Integer, byte[]> dataGroupHashes,
      PrivateKey privateKey,
      X509Certificate docSigningCertificate, String provider,
      String ldsVersion, String unicodeVersion) throws NoSuchAlgorithmException, CertificateException {
    super(EF_SOD_TAG);
    try {
      ContentInfo contentInfo = toContentInfo(ICAO_LDS_SOD_OID, digestAlgorithm, dataGroupHashes, ldsVersion, unicodeVersion);
      byte[] encryptedDigest = SignedDataUtil.signData(digestAlgorithm, digestEncryptionAlgorithm, ICAO_LDS_SOD_OID, contentInfo, privateKey, provider);

      signedData = SignedDataUtil.createSignedData(digestAlgorithm,
          digestEncryptionAlgorithm,
          ICAO_LDS_SOD_OID, contentInfo,
          encryptedDigest, docSigningCertificate);      
    } catch (IOException ioe) {
      throw new IllegalArgumentException("Error creating signedData", ioe);
    }
  }

  /**
   * Constructs a Security Object data structure.
   *
   * @param digestAlgorithm a digest algorithm, such as "SHA-1" or "SHA-256"
   * @param digestEncryptionAlgorithm a digest encryption algorithm, such as "SHA256withRSA"
   * @param dataGroupHashes maps datagroup numbers (1 to 16) to hashes of the data groups
   * @param encryptedDigest externally signed contents
   * @param docSigningCertificate the document signing certificate
   *
   * @throws NoSuchAlgorithmException if either of the algorithm parameters is not recognized
   * @throws CertificateException if the document signing certificate cannot be used
   */
  public SODFile(String digestAlgorithm, String digestEncryptionAlgorithm,
      Map<Integer, byte[]> dataGroupHashes,
      byte[] encryptedDigest,
      X509Certificate docSigningCertificate) throws NoSuchAlgorithmException, CertificateException {
    super(EF_SOD_TAG);
    try {      
      signedData = SignedDataUtil.createSignedData(digestAlgorithm,
          digestEncryptionAlgorithm,
          ICAO_LDS_SOD_OID,
          toContentInfo(ICAO_LDS_SOD_OID, digestAlgorithm, dataGroupHashes, null, null),
          encryptedDigest,
          docSigningCertificate);
    } catch (IOException ioe) {
      throw new IllegalArgumentException("Error creating signedData", ioe);
    }
  }

  /**
   * Constructs a Security Object data structure.
   *
   * @param inputStream some inputstream
   *
   * @throws IOException if something goes wrong
   */
  public SODFile(InputStream inputStream) throws IOException {
    super(EF_SOD_TAG, inputStream);
  }

  @Override
  protected void readContent(InputStream inputStream) throws IOException {
    this.signedData = SignedDataUtil.readSignedData(inputStream);
  }

  @Override
  protected void writeContent(OutputStream outputStream) throws IOException {
    SignedDataUtil.writeData(this.signedData, outputStream);
  }

  /**
   * Gets the stored data group hashes.
   *
   * @return data group hashes indexed by data group numbers (1 to 16)
   */
  public Map<Integer, byte[]> getDataGroupHashes() {
    DataGroupHash[] hashObjects = getLDSSecurityObject(signedData).getDatagroupHash();
    Map<Integer, byte[]> hashMap = new TreeMap<Integer, byte[]>(); /* HashMap... get it? :D (not funny anymore, now that it's a TreeMap.) */
    for (int i = 0; i < hashObjects.length; i++) {
      DataGroupHash hashObject = hashObjects[i];
      int number = hashObject.getDataGroupNumber();
      byte[] hashValue = hashObject.getDataGroupHashValue().getOctets();
      hashMap.put(number, hashValue);
    }
    return hashMap;
  }

  /**
   * Gets the signature (the encrypted digest) over the hashes.
   *
   * @return the encrypted digest
   */
  public byte[] getEncryptedDigest() {
    return SignedDataUtil.getEncryptedDigest(signedData);
  }

  /**
   * Gets the parameters of the digest encryption (signature) algorithm.
   * For instance for {@code "RSASSA/PSS"} this includes the hash algorithm
   * and the salt length.
   * 
   * @return the algorithm parameters
   */
  public AlgorithmParameterSpec getDigestEncryptionAlgorithmParams() {
    return SignedDataUtil.getDigestEncryptionAlgorithmParams(signedData);
  }

  /**
   * Gets the e-content inside the signed data structure.
   *
   * @return the e-content
   * 
   * @throws SignatureException if the contents do not check out
   */
  public byte[] getEContent() throws SignatureException {    
    return SignedDataUtil.getEContent(signedData);
  }

  /**
   * Gets the name of the algorithm used in the data group hashes.
   *
   * @return an algorithm string such as "SHA-1" or "SHA-256"
   */
  public String getDigestAlgorithm() {
    return getDigestAlgorithm(getLDSSecurityObject(signedData));
  }

  private static String getDigestAlgorithm(LDSSecurityObject ldsSecurityObject) {
    try {
      return SignedDataUtil.lookupMnemonicByOID(ldsSecurityObject.getDigestAlgorithmIdentifier().getAlgorithm().getId());
    } catch (NoSuchAlgorithmException nsae) {
      LOGGER.log(Level.WARNING, "Exception", nsae);
      return null;
    }
  }

  /**
   * Gets the name of the digest algorithm used in the signature.
   *
   * @return an algorithm string such as "SHA-1" or "SHA-256"
   */
  public String getSignerInfoDigestAlgorithm() {
    return SignedDataUtil.getSignerInfoDigestAlgorithm(signedData);
  }

  /**
   * Gets the name of the digest encryption algorithm used in the signature.
   *
   * @return an algorithm string such as "SHA256withRSA"
   */
  public String getDigestEncryptionAlgorithm() {
    return SignedDataUtil.getDigestEncryptionAlgorithm(signedData);
  }

  /**
   * Gets the version of the LDS if stored in the Security Object (SOd).
   *
   * @return the version of the LDS in "aabb" format or null if LDS &lt; V1.8
   *
   * @since LDS V1.8
   */
  public String getLDSVersion() {
    LDSVersionInfo ldsVersionInfo = getLDSSecurityObject(signedData).getVersionInfo();
    if (ldsVersionInfo == null) {
      return null;
    } else {
      return ldsVersionInfo.getLdsVersion();
    }
  }

  /**
   * Gets the version of unicode if stored in the Security Object (SOd).
   *
   * @return the unicode version in "aabbcc" format or null if LDS &lt; V1.8
   *
   * @since LDS V1.8
   */
  public String getUnicodeVersion() {
    LDSVersionInfo ldsVersionInfo = getLDSSecurityObject(signedData).getVersionInfo();
    if (ldsVersionInfo == null) {
      return null;
    } else {
      return ldsVersionInfo.getUnicodeVersion();
    }
  }

  /**
   * Gets the embedded document signing certificate (if present).
   * Use this certificate to verify that <i>eSignature</i> is a valid
   * signature for <i>eContent</i>. This certificate itself is signed
   * using the country signing certificate.
   *
   * @return the document signing certificate
   *
   * @throws CertificateException when certificate not be constructed from this SOd
   */
  public X509Certificate getDocSigningCertificate() throws CertificateException {
    return SignedDataUtil.getDocSigningCertificate(signedData);
  }

  /**
   * Gets the issuer of the document signing certificate.
   *
   * @return a certificate issuer
   */
  public X500Principal getIssuerX500Principal() {
    try {
      IssuerAndSerialNumber issuerAndSerialNumber = SignedDataUtil.getIssuerAndSerialNumber(signedData);
      X500Name name = issuerAndSerialNumber.getName();
      X500Principal x500Principal = new X500Principal(name.getEncoded(ASN1Encoding.DER));   
      return x500Principal;
    } catch (IOException ioe) {
      LOGGER.log(Level.WARNING, "Could not get issuer", ioe);
      return null;
    }
  }

  /**
   * Gets the serial number of the document signing certificate.
   *
   * @return a certificate serial number
   */
  public BigInteger getSerialNumber() {
    IssuerAndSerialNumber issuerAndSerialNumber = SignedDataUtil.getIssuerAndSerialNumber(signedData);
    BigInteger serialNumber = issuerAndSerialNumber.getSerialNumber().getValue();
    return serialNumber;
  }

  /**
   * Gets a textual representation of this file.
   *
   * @return a textual representation of this file
   */
  @Override
  public String toString() {
    try {
      X509Certificate cert = getDocSigningCertificate();
      return "SODFile " + cert.getIssuerX500Principal();
    } catch (Exception e) {
      return "SODFile";
    }
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == null) {
      return false;
    }
    if (obj == this) {
      return true;
    }
    if (!obj.getClass().equals(this.getClass())) {
      return false;
    }

    SODFile other = (SODFile)obj;
    return Arrays.equals(getEncoded(), other.getEncoded());
  }

  @Override
  public int hashCode() {
    return 11 * Arrays.hashCode(getEncoded()) + 111;
  }

  /* ONLY PRIVATE METHODS BELOW */

  private static ContentInfo toContentInfo(String contentTypeOID, String digestAlgorithm,
      Map<Integer, byte[]> dataGroupHashes,
      String ldsVersion, String unicodeVersion) throws NoSuchAlgorithmException, IOException {
    DataGroupHash[] dataGroupHashesArray = new DataGroupHash[dataGroupHashes.size()];
    int i = 0;
    for (int dataGroupNumber: dataGroupHashes.keySet()) {
      byte[] hashBytes = dataGroupHashes.get(dataGroupNumber);
      DataGroupHash hash = new DataGroupHash(dataGroupNumber, new DEROctetString(hashBytes));
      dataGroupHashesArray[i++] = hash;
    }
    AlgorithmIdentifier digestAlgorithmIdentifier = new AlgorithmIdentifier(new ASN1ObjectIdentifier(SignedDataUtil.lookupOIDByMnemonic(digestAlgorithm)));
    LDSSecurityObject securityObject = null;
    if (ldsVersion == null) {
      securityObject = new LDSSecurityObject(digestAlgorithmIdentifier, dataGroupHashesArray);
    } else {
      securityObject = new LDSSecurityObject(digestAlgorithmIdentifier, dataGroupHashesArray, new LDSVersionInfo(ldsVersion, unicodeVersion));
    }

    return new ContentInfo(new ASN1ObjectIdentifier(contentTypeOID), new DEROctetString(securityObject));
  }

  /**
   * Reads the security object (containing the hashes
   * of the data groups) found in the SignedData field.
   *
   * @return the security object
   *
   * @throws IOException
   */
  private static LDSSecurityObject getLDSSecurityObject(SignedData signedData) {
    try {
      ContentInfo encapContentInfo = signedData.getEncapContentInfo();
      String contentType = encapContentInfo.getContentType().getId();
      DEROctetString eContent = (DEROctetString)encapContentInfo.getContent();
      if (!(ICAO_LDS_SOD_OID.equals(contentType)
          || SDU_LDS_SOD_OID.equals(contentType)
          || ICAO_LDS_SOD_ALT_OID.equals(contentType))) {
        LOGGER.warning("SignedData does not appear to contain an LDS SOd. (content type is " + contentType + ", was expecting " + ICAO_LDS_SOD_OID + ")");
      }
      ASN1InputStream inputStream = new ASN1InputStream(new ByteArrayInputStream(eContent.getOctets()));
      try {
        Object firstObject = inputStream.readObject();
        if (!(firstObject instanceof ASN1Sequence)) {
          throw new IllegalStateException("Expected ASN1Sequence, found " + firstObject.getClass().getSimpleName());
        }
        LDSSecurityObject sod = LDSSecurityObject.getInstance(firstObject);
        Object nextObject = inputStream.readObject();
        if (nextObject != null) {
          LOGGER.warning("Ignoring extra object found after LDSSecurityObject...");
        }
        return sod;
      } finally {
        inputStream.close();
      }
    } catch (IOException ioe) {
      throw new IllegalStateException("Could not read security object in signedData");
    }
  }
}
