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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.jmrtd.JMRTDSecurityProvider;

/**
 * Utility class for helping with CMS SignedData in security object document and
 * card security file.
 * 
 * This hopefully abstracts some of the BC dependencies away.
 * 
 * FIXME: WORK IN PROGRESS
 * 
 * @author The JMRTD team (info@jmrtd.org)
 * 
 * @version $Revision$
 */
/* package-visible */ class SignedDataUtil {
  
  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");
  
  private static final Provider BC_PROVIDER = JMRTDSecurityProvider.getBouncyCastleProvider();
  
  /** SignedData related object identifier. */
  public static final String
  RFC_3369_SIGNED_DATA_OID = "1.2.840.113549.1.7.2",    /* id-signedData OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs7(7) 2 } */
  RFC_3369_CONTENT_TYPE_OID = "1.2.840.113549.1.9.3",
  RFC_3369_MESSAGE_DIGEST_OID = "1.2.840.113549.1.9.4",
  PKCS1_RSA_OID = "1.2.840.113549.1.1.1",
  PKCS1_MD2_WITH_RSA_OID = "1.2.840.113549.1.1.2",
  PKCS1_MD4_WITH_RSA_OID = "1.2.840.113549.1.1.3",
  PKCS1_MD5_WITH_RSA_OID = "1.2.840.113549.1.1.4",
  PKCS1_SHA1_WITH_RSA_OID = "1.2.840.113549.1.1.5",
  //  PKCS1_RSAOAEP_ENC_SET = "1.2.840.113549.1.1.6", // other identifier: ripemd160WithRSAEncryption
  //  PKCS1_RSAES_OAEP = "1.2.840.113549.1.1.7",
  PKCS1_SHA256_WITH_RSA_AND_MGF1 = "1.2.840.113549.1.1.8",
  PKCS1_RSASSA_PSS_OID = "1.2.840.113549.1.1.10",
  PKCS1_SHA256_WITH_RSA_OID = "1.2.840.113549.1.1.11",
  PKCS1_SHA384_WITH_RSA_OID = "1.2.840.113549.1.1.12",
  PKCS1_SHA512_WITH_RSA_OID = "1.2.840.113549.1.1.13",
  PKCS1_SHA224_WITH_RSA_OID = "1.2.840.113549.1.1.14",
  X9_SHA1_WITH_ECDSA_OID = "1.2.840.10045.4.1",
  X9_SHA224_WITH_ECDSA_OID = "1.2.840.10045.4.3.1",
  X9_SHA256_WITH_ECDSA_OID = "1.2.840.10045.4.3.2",
  IEEE_P1363_SHA1_OID = "1.3.14.3.2.26";
  
  /**
   * Prevents instantiation.
   */
  private SignedDataUtil() {
  }
  
  public static SignedData readSignedData(InputStream inputStream) throws IOException {
    ASN1InputStream asn1in = new ASN1InputStream(inputStream);
    ASN1Sequence sequence = (ASN1Sequence)asn1in.readObject();
    
    if (sequence.size() != 2) {
      throw new IOException("Was expecting a DER sequence of length 2, found a DER sequence of length " + sequence.size());
    }
    
    String contentTypeOID = ((ASN1ObjectIdentifier)sequence.getObjectAt(0)).getId();
    if (!SignedDataUtil.RFC_3369_SIGNED_DATA_OID.equals(contentTypeOID)) {
      throw new IOException("Was expecting signed-data content type OID (" + SignedDataUtil.RFC_3369_SIGNED_DATA_OID + "), found " + contentTypeOID);
    }
    
    ASN1Primitive asn1SequenceWithSignedData = SignedDataUtil.getObjectFromTaggedObject(sequence.getObjectAt(1));
    
    if (!(asn1SequenceWithSignedData instanceof ASN1Sequence)) {
      throw new IOException("Was expecting an ASN.1 sequence as content");
    }
    
    return SignedData.getInstance(asn1SequenceWithSignedData);
  }
  
  public static void writeData(SignedData signedData, OutputStream outputStream) throws IOException {
    ASN1EncodableVector v = new ASN1EncodableVector();
    v.add(new ASN1ObjectIdentifier(SignedDataUtil.RFC_3369_SIGNED_DATA_OID));
    v.add(new DERTaggedObject(0, signedData));
    ASN1Sequence fileContentsObject = new DLSequence(v);
    byte[] fileContentsBytes = fileContentsObject.getEncoded(ASN1Encoding.DER);
    outputStream.write(fileContentsBytes);
  }
  
  public static ASN1Primitive getContent(SignedData signedData) {
    ContentInfo encapContentInfo = signedData.getEncapContentInfo();
    
    String contentType = encapContentInfo.getContentType().getId();
    
    DEROctetString eContent = (DEROctetString)encapContentInfo.getContent();    
    
    ASN1InputStream inputStream = null;
    try {
      inputStream = new ASN1InputStream(new ByteArrayInputStream(eContent.getOctets()));
      ASN1Primitive firstObject = inputStream.readObject();
      return firstObject;      
    } catch (IOException ioe) {
      LOGGER.log(Level.WARNING, "Unexpected exception", ioe);
    } finally {
      if (inputStream != null) {
        try {
          inputStream.close();
        } catch (IOException ioe) {
          LOGGER.log(Level.WARNING, "Exception closing input stream");
          /* At least we tried... */
        }
      }
    }
    
    return null;
  }
  
  /**
   * Removes the tag from a tagged object.
   * 
   * @param asn1Encodable the encoded tagged object
   * 
   * @return the object
   * 
   * @throws IOException if the input is not a tagged object or the tagNo is not 0
   */
  public static ASN1Primitive getObjectFromTaggedObject(ASN1Encodable asn1Encodable) throws IOException {
    if (!(asn1Encodable instanceof ASN1TaggedObject)) {
      throw new IOException("Was expecting an ASN1TaggedObject, found " + asn1Encodable.getClass().getCanonicalName());
    }
    
    ASN1TaggedObject asn1TaggedObject = (ASN1TaggedObject)asn1Encodable;
    
    int tagNo = asn1TaggedObject.getTagNo();
    if (tagNo != 0) {
      throw new IOException("Was expecting tag 0, found " + Integer.toHexString(tagNo));
    }   
    
    return asn1TaggedObject.getObject();     
  }
  
  public static String getSignerInfoDigestAlgorithm(SignedData signedData) {
    try {
      SignerInfo signerInfo = getSignerInfo(signedData);
      String digestAlgOID = signerInfo.getDigestAlgorithm().getAlgorithm().getId();
      return SignedDataUtil.lookupMnemonicByOID(digestAlgOID);
    } catch (NoSuchAlgorithmException nsae) {
      LOGGER.severe("Exception: " + nsae.getMessage());
      return null; // throw new IllegalStateException(nsae.toString());
    }
  }
  
  public static String getDigestEncryptionAlgorithm(SignedData signedData) {
    try {
      SignerInfo signerInfo = getSignerInfo(signedData);
      String digestEncryptionAlgorithmOID = signerInfo.getDigestEncryptionAlgorithm().getAlgorithm().getId();
      if (digestEncryptionAlgorithmOID == null) { return null; }
      return SignedDataUtil.lookupMnemonicByOID(digestEncryptionAlgorithmOID);
    } catch (NoSuchAlgorithmException nsae) {
      LOGGER.severe("Exception: " + nsae.getMessage());
      return null; // throw new IllegalStateException(nsae.toString());
    }
  }
  
  /**
   * Gets the contents of the signed data over which the
   * signature is to be computed.
   *
   * See RFC 3369, Cryptographic Message Syntax, August 2002,
   * Section 5.4 for details.
   *
   * FIXME: Maybe throw an exception instead of issuing warnings
   * on logger if signed attributes do not check out.
   *
   * @see #getDocSigningCertificate()
   * @see #getSignature()
   *
   * @return the contents of the security object over which the
   *         signature is to be computed
   */
  public static byte[] getEContent(SignedData signedData) {
    SignerInfo signerInfo = getSignerInfo(signedData);
    ASN1Set signedAttributesSet = signerInfo.getAuthenticatedAttributes();
    
    ContentInfo contentInfo = signedData.getEncapContentInfo();
    byte[] contentBytes = ((DEROctetString)contentInfo.getContent()).getOctets();
    
    if (signedAttributesSet.size() == 0) {
      /* Signed attributes absent, return content to be signed... */
      return contentBytes;
    }
    
    /* Signed attributes present (i.e. a structure containing a hash of the content), return that structure to be signed... */
    /* This option is taken by ICAO passports. */
    byte[] attributesBytes = null;
    String digAlg = signerInfo.getDigestAlgorithm().getAlgorithm().getId();
    
    try {
      attributesBytes = signedAttributesSet.getEncoded(ASN1Encoding.DER);
      
      checkEContent(getAttributes(signedAttributesSet), digAlg, contentBytes);
      
    } catch (NoSuchAlgorithmException nsae) {
      LOGGER.warning("Error checking signedAttributes in eContent! No such algorithm: \"" + digAlg + "\": " + nsae.getMessage());
    } catch (IOException ioe) {
      LOGGER.severe("Error getting signedAttributes: " + ioe.getMessage());
    }
    
    return attributesBytes;
  }
  
  /* FIXME: Move this from lds package to verifier. -- MO */
  /* FIXME: This only warns on logger. */
  /**
   * Checks that the content actually digests to the hash value contained in the message digest attribute.
   * 
   * @param attributes the attributes, this should contain an attribute of type {@link #RFC_3369_MESSAGE_DIGEST_OID}
   * @param digAlg the digest algorithm
   * @param contentBytes the contents
   * 
   * @throws NoSuchAlgorithmException if the digest algorithm is unsupported
   */
  private static void checkEContent(Collection<Attribute> attributes, String digAlg, byte[] contentBytes) throws NoSuchAlgorithmException {
    for (Attribute attribute: attributes) {
      if (!RFC_3369_MESSAGE_DIGEST_OID.equals(attribute.getAttrType().getId())) {
        continue;
      }
      
      ASN1Set attrValuesSet = attribute.getAttrValues();
      if (attrValuesSet.size() != 1) {
        LOGGER.warning("Expected only one attribute value in signedAttribute message digest in eContent!");
      }
      byte[] storedDigestedContent = ((DEROctetString)attrValuesSet.getObjectAt(0)).getOctets();
      
      if (storedDigestedContent == null) {
        LOGGER.warning("Error extracting signedAttribute message digest in eContent!");
      } 
      
      MessageDigest dig = MessageDigest.getInstance(digAlg);
      byte[] computedDigestedContent = dig.digest(contentBytes);
      if (!Arrays.equals(storedDigestedContent, computedDigestedContent)) {
        LOGGER.warning("Error checking signedAttribute message digest in eContent!");
      }
    }    
  }
  
  private static List<Attribute> getAttributes(ASN1Set signedAttributesSet) {
    List<ASN1Sequence> attributeObjects = Collections.list(signedAttributesSet.getObjects());
    List<Attribute> attributes = new ArrayList(attributeObjects.size());
    for (ASN1Sequence attributeObject: attributeObjects) {
      Attribute attribute = Attribute.getInstance(attributeObject);
      attributes.add(attribute);
    }
    return attributes;
  }
  
  /**
   * Gets the stored signature of the security object.
   *
   * @see #getDocSigningCertificate()
   *
   * @return the signature
   */
  public static byte[] getEncryptedDigest(SignedData signedData) {
    SignerInfo signerInfo = getSignerInfo(signedData);
    return signerInfo.getEncryptedDigest().getOctets();
  }
  
  public static IssuerAndSerialNumber getIssuerAndSerialNumber(SignedData signedData) {
    SignerInfo signerInfo = getSignerInfo(signedData);
    SignerIdentifier signerIdentifier = signerInfo.getSID();
    IssuerAndSerialNumber issuerAndSerialNumber = IssuerAndSerialNumber.getInstance(signerIdentifier.getId());
    X500Name issuer = issuerAndSerialNumber.getName();
    BigInteger serialNumber = issuerAndSerialNumber.getSerialNumber().getValue();
    return new IssuerAndSerialNumber(issuer, serialNumber);
  }
  
  private static SignerInfo getSignerInfo(SignedData signedData)  {
    ASN1Set signerInfos = signedData.getSignerInfos();
    if (signerInfos.size() > 1) {
      LOGGER.warning("Found " + signerInfos.size() + " signerInfos");
    }
    for (int i = 0; i < signerInfos.size(); i++) {
      SignerInfo info = new SignerInfo((ASN1Sequence)signerInfos.getObjectAt(i));
      return info;
    }
    return null;
  }
  
  public static X509Certificate getDocSigningCertificate(SignedData signedData) throws CertificateException {
    byte[] certSpec = null;
    ASN1Set certs = signedData.getCertificates();
    if (certs == null || certs.size() <= 0) { return null; }
    if (certs.size() != 1) {
      LOGGER.warning("Found " + certs.size() + " certificates");
    }
    X509CertificateObject certObject = null;
    for (int i = 0; i < certs.size(); i++) {
      org.bouncycastle.asn1.x509.Certificate certAsASN1Object = org.bouncycastle.asn1.x509.Certificate.getInstance((ASN1Sequence)certs.getObjectAt(i));
      certObject = new X509CertificateObject(certAsASN1Object); // NOTE: >= BC 1.48
      //      certObject = new X509CertificateObject(X509CertificateStructure.getInstance(certAsASN1Object)); // NOTE: <= BC 1.47
      certSpec = certObject.getEncoded();
    }
    
    /*
     * NOTE: we could have just returned that X509CertificateObject here,
     * but by reconstructing it using the client's default provider we hide
     * the fact that we're using BC.
     */
    try {
      CertificateFactory factory = CertificateFactory.getInstance("X.509");
      X509Certificate cert = (X509Certificate)factory.generateCertificate(new ByteArrayInputStream(certSpec));
      return cert;
    } catch (Exception e) {
      /* NOTE: Reconstructing using preferred provider didn't work?!?! */
      return certObject;
    }
  }
  
  public static SignedData createSignedData(String digestAlgorithm, String digestEncryptionAlgorithm,
      String contentTypeOID, ContentInfo contentInfo, byte[] encryptedDigest,
      X509Certificate docSigningCertificate) throws NoSuchAlgorithmException, CertificateException, IOException {
    ASN1Set digestAlgorithmsSet = SignedDataUtil.createSingletonSet(SignedDataUtil.createDigestAlgorithms(digestAlgorithm));
    ASN1Set certificates =  createSingletonSet(SignedDataUtil.createCertificate(docSigningCertificate));
    ASN1Set crls = null;
    ASN1Set signerInfos = createSingletonSet(createSignerInfo(digestAlgorithm, digestEncryptionAlgorithm, contentTypeOID, contentInfo, encryptedDigest, docSigningCertificate).toASN1Object());
    return new SignedData(digestAlgorithmsSet, contentInfo, certificates, crls, signerInfos);
  }  
  
  public static SignerInfo createSignerInfo(String digestAlgorithm,
      String digestEncryptionAlgorithm, String contentTypeOID, ContentInfo contentInfo,
      byte[] encryptedDigest, X509Certificate docSigningCertificate) throws NoSuchAlgorithmException {
    /* Get the issuer name (CN, O, OU, C) from the cert and put it in a SignerIdentifier struct. */
    X500Principal docSignerPrincipal = ((X509Certificate)docSigningCertificate).getIssuerX500Principal();
    X500Name docSignerName = new X500Name(docSignerPrincipal.getName(X500Principal.RFC2253));
    BigInteger serial = ((X509Certificate)docSigningCertificate).getSerialNumber();
    SignerIdentifier sid = new SignerIdentifier(new IssuerAndSerialNumber(docSignerName, serial));
    
    AlgorithmIdentifier digestAlgorithmObject = new AlgorithmIdentifier(new ASN1ObjectIdentifier(SignedDataUtil.lookupOIDByMnemonic(digestAlgorithm)));
    AlgorithmIdentifier digestEncryptionAlgorithmObject = new AlgorithmIdentifier(new ASN1ObjectIdentifier(SignedDataUtil.lookupOIDByMnemonic(digestEncryptionAlgorithm)));
    
    ASN1Set authenticatedAttributes = createAuthenticatedAttributes(digestAlgorithm, contentTypeOID, contentInfo); // struct containing the hash of content
    ASN1OctetString encryptedDigestObject = new DEROctetString(encryptedDigest); // this is the signature
    ASN1Set unAuthenticatedAttributes = null; // should be empty set?
    return new SignerInfo(sid, digestAlgorithmObject, authenticatedAttributes, digestEncryptionAlgorithmObject, encryptedDigestObject, unAuthenticatedAttributes);
  }
  
  public static ASN1Set createAuthenticatedAttributes(String digestAlgorithm, String contentTypeOID, ContentInfo contentInfo) throws NoSuchAlgorithmException {
    /* Check bug found by Paulo Assumpco. */
    if ("SHA256".equals(digestAlgorithm)) { digestAlgorithm = "SHA-256"; }
    MessageDigest dig = MessageDigest.getInstance(digestAlgorithm);
    byte[] contentBytes = ((DEROctetString)contentInfo.getContent()).getOctets();
    byte[] digestedContentBytes = dig.digest(contentBytes);
    ASN1OctetString digestedContent = new DEROctetString(digestedContentBytes);
    Attribute contentTypeAttribute = new Attribute(new ASN1ObjectIdentifier(SignedDataUtil.RFC_3369_CONTENT_TYPE_OID), createSingletonSet(new ASN1ObjectIdentifier(contentTypeOID)));
    Attribute messageDigestAttribute = new Attribute(new ASN1ObjectIdentifier(SignedDataUtil.RFC_3369_MESSAGE_DIGEST_OID), createSingletonSet(digestedContent));
    ASN1Object[] result = { contentTypeAttribute.toASN1Primitive(), messageDigestAttribute.toASN1Primitive() };
    return new DLSet(result);
  }
  
  public static ASN1Sequence createDigestAlgorithms(String digestAlgorithm) throws NoSuchAlgorithmException {
    ASN1ObjectIdentifier algorithmIdentifier = new ASN1ObjectIdentifier(SignedDataUtil.lookupOIDByMnemonic(digestAlgorithm));
    ASN1EncodableVector v = new ASN1EncodableVector();
    v.add(algorithmIdentifier);
    return new DLSequence(v);
  }
  
  public static ASN1Sequence createCertificate(X509Certificate cert) throws CertificateException {
    try {
      byte[] certSpec = cert.getEncoded();
      ASN1InputStream asn1In = new ASN1InputStream(certSpec);
      try {
        ASN1Sequence certSeq = (ASN1Sequence)asn1In.readObject();
        return certSeq;
      } finally {
        asn1In.close();
      }
    } catch (IOException ioe) {
      throw new CertificateException("Could not construct certificate byte stream");
    }
  }
  
  public static byte[] signData(String digestAlgorithm, String digestEncryptionAlgorithm, String contentTypeOID, ContentInfo contentInfo, PrivateKey privateKey, String provider) {
    byte[] encryptedDigest = null;
    try {
      byte[] dataToBeSigned = createAuthenticatedAttributes(digestAlgorithm, contentTypeOID, contentInfo).getEncoded(ASN1Encoding.DER);
      Signature s = null;
      if (provider != null) {
        s = Signature.getInstance(digestEncryptionAlgorithm, provider);             
      } else {
        s = Signature.getInstance(digestEncryptionAlgorithm);             
      }
      s.initSign(privateKey);
      s.update(dataToBeSigned);
      encryptedDigest = s.sign();
    } catch (Exception e) {
      LOGGER.severe("Exception: " + e.getMessage());
      return null;
    }
    return encryptedDigest;
  }
  
  private static ASN1Set createSingletonSet(ASN1Object e) {
    return new DLSet(new ASN1Encodable[] { e });
  }
  
  /**
   * Gets the common mnemonic string (such as "SHA1", "SHA256withRSA") given an OID.
   *
   * @param oid an OID
   *
   * @throws NoSuchAlgorithmException if the provided OID is not yet supported
   */
  public static String lookupMnemonicByOID(String oid) throws NoSuchAlgorithmException {
    if (oid == null) { return null; }
    if (oid.equals(X509ObjectIdentifiers.organization.getId())) { return "O"; }
    if (oid.equals(X509ObjectIdentifiers.organizationalUnitName.getId())) { return "OU"; }
    if (oid.equals(X509ObjectIdentifiers.commonName.getId())) { return "CN"; }
    if (oid.equals(X509ObjectIdentifiers.countryName.getId())) { return "C"; }
    if (oid.equals(X509ObjectIdentifiers.stateOrProvinceName.getId())) { return "ST"; }
    if (oid.equals(X509ObjectIdentifiers.localityName.getId())) { return "L"; }
    if(oid.equals(X509ObjectIdentifiers.id_SHA1.getId())) { return "SHA-1"; }
    if(oid.equals(NISTObjectIdentifiers.id_sha224.getId())) { return "SHA-224"; }
    if(oid.equals(NISTObjectIdentifiers.id_sha256.getId())) { return "SHA-256"; }
    if(oid.equals(NISTObjectIdentifiers.id_sha384.getId())) { return "SHA-384"; }
    if(oid.equals(NISTObjectIdentifiers.id_sha512.getId())) { return "SHA-512"; }
    if (oid.equals(X9_SHA1_WITH_ECDSA_OID)) { return "SHA1withECDSA"; }
    if (oid.equals(X9_SHA224_WITH_ECDSA_OID)) { return "SHA224withECDSA"; }
    if (oid.equals(X9_SHA256_WITH_ECDSA_OID)) { return "SHA256withECDSA"; }   
    if (oid.equals(PKCS1_RSA_OID)) { return "RSA"; }
    if (oid.equals(PKCS1_MD2_WITH_RSA_OID)) { return "MD2withRSA"; }
    if (oid.equals(PKCS1_MD4_WITH_RSA_OID)) { return "MD4withRSA"; }
    if (oid.equals(PKCS1_MD5_WITH_RSA_OID)) { return "MD5withRSA"; }
    if (oid.equals(PKCS1_SHA1_WITH_RSA_OID)) { return "SHA1withRSA"; }
    if (oid.equals(PKCS1_SHA256_WITH_RSA_OID)) { return "SHA256withRSA"; }
    if (oid.equals(PKCS1_SHA384_WITH_RSA_OID)) { return "SHA384withRSA"; }
    if (oid.equals(PKCS1_SHA512_WITH_RSA_OID)) { return "SHA512withRSA"; }
    if (oid.equals(PKCS1_SHA224_WITH_RSA_OID)) { return "SHA224withRSA"; }
    if (oid.equals(IEEE_P1363_SHA1_OID)) { return "SHA-1"; }
    if (oid.equals(PKCS1_RSASSA_PSS_OID)) { return "SSAwithRSA/PSS"; }
    if (oid.equals(PKCS1_SHA256_WITH_RSA_AND_MGF1)) { return "SHA256withRSAandMGF1"; }
    throw new NoSuchAlgorithmException("Unknown OID " + oid);
  }
  
  public static String lookupOIDByMnemonic(String name) throws NoSuchAlgorithmException {
    if (name.equals("O")) { return X509ObjectIdentifiers.organization.getId(); }
    if (name.equals("OU")) { return X509ObjectIdentifiers.organizationalUnitName.getId(); }
    if (name.equals("CN")) { return X509ObjectIdentifiers.commonName.getId(); }
    if (name.equals("C")) { return X509ObjectIdentifiers.countryName.getId(); }
    if (name.equals("ST")) { return X509ObjectIdentifiers.stateOrProvinceName.getId(); }
    if (name.equals("L")) { return X509ObjectIdentifiers.localityName.getId(); }
    if(name.equalsIgnoreCase("SHA-1") || name.equalsIgnoreCase("SHA1")) { return X509ObjectIdentifiers.id_SHA1.getId(); }
    if(name.equalsIgnoreCase("SHA-224") || name.equalsIgnoreCase("SHA224")) { return NISTObjectIdentifiers.id_sha224.getId(); }
    if(name.equalsIgnoreCase("SHA-256") || name.equalsIgnoreCase("SHA256")) { return NISTObjectIdentifiers.id_sha256.getId(); }
    if(name.equalsIgnoreCase("SHA-384") || name.equalsIgnoreCase("SHA384")) { return NISTObjectIdentifiers.id_sha384.getId(); }
    if(name.equalsIgnoreCase("SHA-512") || name.equalsIgnoreCase("SHA512")) { return NISTObjectIdentifiers.id_sha512.getId(); }
    if (name.equalsIgnoreCase("RSA")) { return PKCS1_RSA_OID; }
    if (name.equalsIgnoreCase("MD2withRSA")) { return PKCS1_MD2_WITH_RSA_OID; }
    if (name.equalsIgnoreCase("MD4withRSA")) { return PKCS1_MD4_WITH_RSA_OID; }
    if (name.equalsIgnoreCase("MD5withRSA")) { return  PKCS1_MD5_WITH_RSA_OID; }
    if (name.equalsIgnoreCase("SHA1withRSA")) { return  PKCS1_SHA1_WITH_RSA_OID; }
    if (name.equalsIgnoreCase("SHA256withRSA")) { return PKCS1_SHA256_WITH_RSA_OID; }
    if (name.equalsIgnoreCase("SHA384withRSA")) { return PKCS1_SHA384_WITH_RSA_OID; }
    if (name.equalsIgnoreCase("SHA512withRSA")) { return PKCS1_SHA512_WITH_RSA_OID; }
    if (name.equalsIgnoreCase("SHA224withRSA")) { return PKCS1_SHA224_WITH_RSA_OID; }
    if (name.equalsIgnoreCase("SHA1withECDSA")) { return X9_SHA1_WITH_ECDSA_OID; }
    if (name.equalsIgnoreCase("SHA224withECDSA")) { return X9_SHA224_WITH_ECDSA_OID; }
    if (name.equalsIgnoreCase("SHA256withECDSA")) { return X9_SHA256_WITH_ECDSA_OID; }
    if (name.equalsIgnoreCase("SAwithRSA/PSS")) { return PKCS1_RSASSA_PSS_OID; }
    if (name.equalsIgnoreCase("SSAwithRSA/PSS")) { return PKCS1_RSASSA_PSS_OID; }
    if (name.equalsIgnoreCase("RSASSA-PSS")) { return PKCS1_RSASSA_PSS_OID; }
    if (name.equalsIgnoreCase("SHA256withRSAandMGF1")) { return PKCS1_SHA256_WITH_RSA_AND_MGF1; }
    throw new NoSuchAlgorithmException("Unknown name " + name);
  }
}
