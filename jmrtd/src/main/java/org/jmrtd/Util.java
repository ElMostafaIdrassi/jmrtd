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

package org.jmrtd;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECField;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.DHParameter;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962NamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.jmrtd.lds.PACEInfo;
import org.jmrtd.lds.SecurityInfo;
import org.jmrtd.lds.icao.MRZInfo;

import net.sf.scuba.util.Hex;

/* FIXME: Move some of these to specific protocol classes. */

/**
 * Some static helper functions. Mostly dealing with low-level crypto.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision$
 */
/* FIXME: We may want to change the visibility of this class to package. */
public class Util {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  /** Mode for KDF. */
  public static final int ENC_MODE = 1;
  public static final int MAC_MODE = 2;
  public static final int PACE_MODE = 3;

  private static final Provider BC_PROVIDER = new BouncyCastleProvider();

  private Util() {
  }

  /**
   * Gets the BC provider, if present.
   *
   * @return the BC provider, the SC provider, or <code>null</code>
   */
  public static Provider getBouncyCastleProvider() {
    return BC_PROVIDER;
  }

  /**
   * Derives the ENC or MAC key for BAC from the keySeed.
   *
   * @param keySeed the key seed.
   * @param mode either <code>ENC_MODE</code> or <code>MAC_MODE</code>
   *
   * @return the key
   *
   * @throws GeneralSecurityException on security error
   */
  public static SecretKey deriveKey(byte[] keySeed, int mode) throws GeneralSecurityException {
    return deriveKey(keySeed, "DESede", 128, mode);
  }

  /**
   * Derives the ENC or MAC key for BAC or PACE
   *
   * @param keySeed the key seed.
   * @param cipherAlgName either AES or DESede
   * @param keyLength key length in bits
   * @param mode either {@code ENC_MODE}, {@code MAC_MODE}, or {@code PACE_MODE}
   *
   * @return the key.
   *
   * @throws GeneralSecurityException on security error
   */
  public static SecretKey deriveKey(byte[] keySeed, String cipherAlgName, int keyLength, int mode) throws GeneralSecurityException {
    return deriveKey(keySeed, cipherAlgName, keyLength, null, mode);
  }

  /**
   * Derives a shared key.
   *
   * @param keySeed the shared secret, as octets
   * @param cipherAlg in Java mnemonic notation (for example "DESede", "AES")
   * @param keyLength length in bits
   * @param nonce optional nonce or <code>null</code>
   * @param mode the mode either {@code ENC}, {@code MAC}, or {@code PACE} mode
   *
   * @return the derived key
   *
   * @throws GeneralSecurityException if something went wrong
   */
  public static SecretKey deriveKey(byte[] keySeed, String cipherAlg, int keyLength, byte[] nonce, int mode) throws GeneralSecurityException {
    return deriveKey(keySeed, cipherAlg, keyLength, nonce, mode, PassportService.NO_PACE_KEY_REFERENCE);
  }

  /**
   * Derives a shared key.
   *
   * @param keySeed the shared secret, as octets
   * @param cipherAlg in Java mnemonic notation (for example "DESede", "AES")
   * @param keyLength length in bits
   * @param nonce optional nonce or <code>null</code>
   * @param mode the mode either {@code ENC}, {@code MAC}, or {@code PACE} mode
   * @param paceKeyReference Key Reference For Pace Protocol
   *
   * @return the derived key
   *
   * @throws GeneralSecurityException if something went wrong
   */
  public static SecretKey deriveKey(byte[] keySeed, String cipherAlg, int keyLength, byte[] nonce, int mode, byte paceKeyReference) throws GeneralSecurityException {
    String digestAlg = inferDigestAlgorithmFromCipherAlgorithmForKeyDerivation(cipherAlg, keyLength);
    MessageDigest digest = getMessageDigest(digestAlg);
    digest.reset();
    digest.update(keySeed);
    if (nonce != null) {
      digest.update(nonce);
    }
    digest.update(new byte[] { 0x00, 0x00, 0x00, (byte)mode });
    byte[] hashResult = digest.digest();
    byte[] keyBytes = null;
    if ("DESede".equalsIgnoreCase(cipherAlg) || "3DES".equalsIgnoreCase(cipherAlg)) {
      /* TR-SAC 1.01, 4.2.1. */
      switch(keyLength) {
        case 112: /* Fall through. */
        case 128:
          keyBytes = new byte[24];
          System.arraycopy(hashResult, 0, keyBytes, 0, 8); /* E  (octets 1 to 8) */
          System.arraycopy(hashResult, 8, keyBytes, 8, 8); /* D  (octets 9 to 16) */
          System.arraycopy(hashResult, 0, keyBytes, 16, 8); /* E (again octets 1 to 8, i.e. 112-bit 3DES key) */
          break;
        default:
          throw new IllegalArgumentException("KDF can only use DESede with 128-bit key length");
      }
    } else if ("AES".equalsIgnoreCase(cipherAlg) || cipherAlg.startsWith("AES")) {
      /* TR-SAC 1.01, 4.2.2. */
      switch(keyLength) {
        case 128:
          keyBytes = new byte[16]; /* NOTE: 128 = 16 * 8 */
          System.arraycopy(hashResult, 0, keyBytes, 0, 16);
          break;
        case 192:
          keyBytes = new byte[24]; /* NOTE: 192 = 24 * 8 */
          System.arraycopy(hashResult, 0, keyBytes, 0, 24);
          break;
        case 256:
          keyBytes = new byte[32]; /* NOTE: 256 = 32 * 8 */
          System.arraycopy(hashResult, 0, keyBytes, 0, 32);
          break;
        default:
          throw new IllegalArgumentException("KDF can only use AES with 128-bit, 192-bit key or 256-bit length, found: " + keyLength + "-bit key length");
      }
    }

    if (paceKeyReference == PassportService.NO_PACE_KEY_REFERENCE) {
      return new SecretKeySpec(keyBytes, cipherAlg);
    } else {
      return new PACESecretKeySpec(keyBytes, cipherAlg, paceKeyReference);
    }
  }

  /**
   * Computes the static key seed, based on information from the MRZ.
   *
   * @param documentNumber a string containing the document number
   * @param dateOfBirth a string containing the date of birth (YYMMDD)
   * @param dateOfExpiry a string containing the date of expiry (YYMMDD)
   * @param digestAlg a Java mnemonic algorithm string to indicate the digest algorithm (typically SHA-1)
   * @param doTruncate whether to truncate the resulting output to 16 bytes
   *
   * @return a byte array of length 16 containing the key seed
   *
   * @throws GeneralSecurityException on security error
   */
  public static byte[] computeKeySeed(String documentNumber, String dateOfBirth, String dateOfExpiry, String digestAlg, boolean doTruncate) throws GeneralSecurityException {
    String text = new StringBuilder()
        .append(documentNumber)
        .append(MRZInfo.checkDigit(documentNumber))
        .append(dateOfBirth)
        .append(MRZInfo.checkDigit(dateOfBirth))
        .append(dateOfExpiry)
        .append(MRZInfo.checkDigit(dateOfExpiry))
        .toString();

    return computeKeySeed(text, digestAlg, doTruncate);
  }

  public static byte[] computeKeySeed(String cardAccessNumber, String digestAlg, boolean doTruncate) throws GeneralSecurityException {
    MessageDigest shaDigest = MessageDigest.getInstance(digestAlg);

    shaDigest.update(getBytes(cardAccessNumber));

    byte[] hash = shaDigest.digest();

    if (doTruncate) {
      /* FIXME: truncate to 16 byte only for BAC with 3DES. Also for PACE and/or AES? -- MO */
      byte[] keySeed = new byte[16];
      System.arraycopy(hash, 0, keySeed, 0, 16);
      return keySeed;
    } else {
      return hash;
    }
  }

  /**
   * Pads the input <code>in</code> according to ISO9797-1 padding method 2,
   * using the given block size.
   *
   * @param in input
   * @param blockSize the block size
   *
   * @return padded bytes
   */
  public static byte[] pad(byte[] in, int blockSize) {
    return pad(in, 0, in.length, blockSize);
  }

  /**
   * Pads the input {@code bytes} indicated by {@code offset} and {@code length}
   * according to ISO9797-1 padding method 2, using the given block size in {@code blockSize}.
   *
   * @param bytes input
   * @param offset the offset
   * @param length the length
   * @param blockSize the block size
   *
   * @return padded bytes
   */
  public static byte[] pad(byte[] bytes, int offset, int length, int blockSize) {
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    outputStream.write(bytes, offset, length);
    outputStream.write((byte)0x80);
    while (outputStream.size() % blockSize != 0) {
      outputStream.write((byte)0x00);
    }
    return outputStream.toByteArray();
  }

  /**
   * Unpads the input {@code bytes} according to ISO9797-1 padding method 2.
   *
   * @param bytes the input
   *
   * @return the unpadded bytes
   *
   * @throws BadPaddingException on padding exception
   */
  public static byte[] unpad(byte[] bytes) throws BadPaddingException {
    int i = bytes.length - 1;
    while (i >= 0 && bytes[i] == 0x00) {
      i--;
    }
    if ((bytes[i] & 0xFF) != 0x80) {
      throw new BadPaddingException("Expected constant 0x80, found 0x" + Integer.toHexString((bytes[i] & 0x000000FF)) + "\nDEBUG: in = " + Hex.bytesToHexString(bytes) + ", index = " + i);
    }
    byte[] out = new byte[i];
    System.arraycopy(bytes, 0, out, 0, i);
    return out;
  }

  /**
   * Recovers the M1 part of the message sent back by the AA protocol
   * (INTERNAL AUTHENTICATE command). The algorithm is described in
   * ISO 9796-2:2002 9.3.
   *
   * @param digestLength should be 20
   * @param decryptedResponse response from card, already 'decrypted' (using the AA public key)
   *
   * @return the m1 part of the message
   */
  public static byte[] recoverMessage(int digestLength, byte[] decryptedResponse) {
    if (decryptedResponse == null || decryptedResponse.length < 1) {
      throw new IllegalArgumentException("Plaintext is too short to recover message");
    }

    /* Trailer. */
    if (((decryptedResponse[decryptedResponse.length - 1] & 0xF) ^ 0xC) != 0) {
      /*
       * Trailer.
       * NOTE: 0xF = 0000 1111, 0xC = 0000 1100.
       */
      throw new NumberFormatException("Could not get M1, malformed trailer");
    }

    int trailerLength = 1;
    /* Trailer. Find out whether this is t=1 or t=2. */
    if (((decryptedResponse[decryptedResponse.length - 1] & 0xFF) ^ 0xBC) == 0) {
      /* Option 1 (t = 1): the trailer shall consist of a single octet; this octet shall be equal to hexadecimal 'BC'. */
      trailerLength = 1;
    } else if (((decryptedResponse[decryptedResponse.length - 1] & 0xFF) ^ 0xCC) == 0) {
      /*
       * Option 2 (t = 2): the trailer shall consist of two consecutive octets;
       * the rightmost octet shall be equal hexadecimal 'CC' and the leftmost octet shall be the hash-function identifier.
       * The hash-function identifier indicates the hash-function in use.
       */
      trailerLength = 2;
    } else {
      throw new NumberFormatException("Not an ISO 9796-2 scheme 2 signature trailer");
    }

    /* Header. */
    if (((decryptedResponse[0] & 0xC0) ^ 0x40) != 0) {
      /*
       * First two bits (working from left to right) should be '01'.
       * NOTE: 0xC0 = 1100 0000, 0x40 = 0100 0000.
       */
      throw new NumberFormatException("Could not get M1");
    }
    if ((decryptedResponse[0] & 0x20) == 0) {
      /* Third bit (working from left to right) should be '1' for partial recovery. */
      throw new NumberFormatException("Could not get M1, first byte indicates partial recovery not enabled: " + Integer.toHexString(decryptedResponse[0]));
    }

    /* Padding to the left of M1, find out how long. */
    int paddingLength = 0;
    for (; paddingLength < decryptedResponse.length; paddingLength++) {
      // 0x0A = 0000 1010
      if (((decryptedResponse[paddingLength] & 0x0F) ^ 0x0A) == 0) {
        break;
      }
    }
    int messageOffset = paddingLength + 1;

    int paddedMessageLength = decryptedResponse.length - trailerLength - digestLength;
    int messageLength = paddedMessageLength - messageOffset;

    /* There must be at least one byte of message string. */
    if (messageLength <= 0) {
      throw new NumberFormatException("Could not get M1");
    }

    /* TODO: If we contain the whole message as well, check the hash of that. */

    byte[] recoveredMessage = new byte[messageLength];
    System.arraycopy(decryptedResponse, messageOffset, recoveredMessage, 0, messageLength);

    return recoveredMessage;
  }

  /**
   * For ECDSA the EAC 1.11 specification requires the signature to be stripped down from any ASN.1 wrappers, as so.
   *
   * @param signedData signed data
   * @param keySize key size
   *
   * @return signature without wrappers
   *
   * @throws IOException on error
   */
  public static byte[] getRawECDSASignature(byte[] signedData, int keySize) throws IOException {
    ASN1InputStream asn1In = new ASN1InputStream(signedData);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    try {
      ASN1Sequence obj = (ASN1Sequence)asn1In.readObject();
      Enumeration<ASN1Primitive> e = obj.getObjects();
      while (e.hasMoreElements()) {
        ASN1Integer i = (ASN1Integer)e.nextElement();
        byte[] t = i.getValue().toByteArray();
        t = alignKeyDataToSize(t, keySize);
        out.write(t);
      }
      out.flush();
      return out.toByteArray();
    } finally {
      asn1In.close();
      out.close();
    }
  }

  public static byte[] alignKeyDataToSize(byte[] keyData, int size) {
    byte[] result = new byte[size];
    if (keyData.length < size) {
      size = keyData.length;
    }
    System.arraycopy(keyData, keyData.length - size, result, result.length - size, size);
    return result;
  }

  /**
   * Converts an integer to an octet string.
   * Based on BSI TR 03111 Section 3.1.2.
   *
   * @param val positive integer
   * @param length length
   *
   * @return octet string
   */
  public static byte[] i2os(BigInteger val, int length) {
    BigInteger base = BigInteger.valueOf(256);
    byte[] result = new byte[length];
    for (int i = 0; i < length; i++) {
      BigInteger remainder = val.mod(base);
      val = val.divide(base);
      result[length - 1 - i] = (byte)remainder.intValue();
    }
    return result;
  }

  /**
   * Converts an integer to an octet string.
   *
   * @param val positive integer
   * @return octet string
   */
  public static byte[] i2os(BigInteger val) {
    /* FIXME: Quick hack. What if val < 0? -- MO */
    /* Do something with: int sizeInBytes = val.bitLength() / Byte.SIZE; */

    int sizeInNibbles = val.toString(16).length();
    if (sizeInNibbles % 2 != 0) {
      sizeInNibbles++;
    }
    int length = sizeInNibbles / 2;
    return i2os(val, length);
  }

  /**
   * Converts an octet string to an integer.
   * Based on BSI TR 03111 Section 3.1.2.
   *
   * @param bytes octet string
   *
   * @return positive integer
   */
  public static BigInteger os2i(byte[] bytes) {
    if (bytes == null) {
      throw new IllegalArgumentException();
    }
    return os2i(bytes, 0, bytes.length);
  }

  /**
   * Converts an octet string to an integer.
   * Based on BSI TR 03111 Section 3.1.2.
   *
   * @param bytes octet string
   * @param offset offset of octet string
   * @param length length of octet string
   *
   * @return positive integer
   */
  public static BigInteger os2i(byte[] bytes, int offset, int length) {
    if (bytes == null) {
      throw new IllegalArgumentException();
    }

    BigInteger result = BigInteger.ZERO;
    BigInteger base = BigInteger.valueOf(256);
    for (int i = offset; i < offset + length; i++) {
      result = result.multiply(base);
      result = result.add(BigInteger.valueOf(bytes[i] & 0xFF));
    }

    return result;
  }

  /**
   * Convert an octet string to field element via OS2FE as specified in BSI TR-03111.
   *
   * @param bytes octet string
   * @param p modulus
   *
   * @return positive integer
   */
  public static BigInteger os2fe(byte[] bytes, BigInteger p) {
    return Util.os2i(bytes).mod(p);
  }

  /* Best effort. Needs testing and improvement. -- MO */
  /**
   * Infers a digest algorithm mnemonic from a signature algorithm mnemonic.
   *
   * @param signatureAlgorithm a signature algorithm
   * 
   * @return a digest algorithm, or {@code null} if inference failed
   */
  public static String inferDigestAlgorithmFromSignatureAlgorithm(String signatureAlgorithm) {
    if (signatureAlgorithm == null) {
      throw new IllegalArgumentException();
    }

    String digestAlgorithm = null;
    String signatureAlgorithmToUppercase = signatureAlgorithm.toUpperCase();
    if (signatureAlgorithmToUppercase.contains("WITH")) {
      String[] components = signatureAlgorithmToUppercase.split("WITH");
      digestAlgorithm = components[0];
    }

    if ("SHA1".equalsIgnoreCase(digestAlgorithm)) {
      return "SHA-1";
    }
    if ("SHA224".equalsIgnoreCase(digestAlgorithm)) {
      return "SHA-224";
    }
    if ("SHA256".equalsIgnoreCase(digestAlgorithm)) {
      return "SHA-256";
    }
    if ("SHA384".equalsIgnoreCase(digestAlgorithm)) {
      return "SHA-384";
    }
    if ("SHA512".equalsIgnoreCase(digestAlgorithm)) {
      return "SHA-512";
    }

    return digestAlgorithm;
  }

  /* Best effort. Needs testing and improvement. -- MO */
  /**
   * Infers a digest algorithm mnemonic from a signature algorithm mnemonic for
   * use in key derivation.
   *
   * @param cipherAlg a cipher algorithm
   * @param keyLength the key length
   * 
   * @return a (best effort approximation) digest algorithm that is typically used in conjunction
   *         with the given cipher algorithm and key length, or {@code null} if inference failed
   */
  public static String inferDigestAlgorithmFromCipherAlgorithmForKeyDerivation(String cipherAlg, int keyLength) {
    if (cipherAlg == null) {
      throw new IllegalArgumentException();
    }
    if ("DESede".equals(cipherAlg) || "AES-128".equals(cipherAlg)) {
      return "SHA-1";
    }
    if ("AES".equals(cipherAlg) && keyLength == 128) {
      return "SHA-1";
    }
    if ("AES-256".equals(cipherAlg) || "AES-192".equals(cipherAlg)) {
      return "SHA-256";
    }
    if ("AES".equals(cipherAlg) && (keyLength == 192 || keyLength == 256)) {
      return "SHA-256";
    }

    throw new IllegalArgumentException("Unsupported cipher algorithm or key length \"" + cipherAlg + "\", " + keyLength);
  }

  /**
   * Returns a Difie-Hellman parameter specification which includes
   * the prime order of the subgroup generated by the generator if this
   * information is available in the given (Bouncy Castle) parameters.
   * 
   * @param params parameters for Diffie-Hellman as a Bouncy Castle specific object.
   * 
   * @return a JCE Diffie-Hellman parameter spec
   */
  public static DHParameterSpec toExplicitDHParameterSpec(DHParameters params) {
    BigInteger p = params.getP();
    BigInteger generator = params.getG();
    BigInteger q = params.getQ();
    int order = params.getL();
    if (q == null) {
      return new DHParameterSpec(p, generator, order);
    } else {
      return new PACEInfo.DHCParameterSpec(p, generator, q);
    }
  }

  /**
   * Return detailed information about the given public key (like RSA or) with some extra
   * information (like 1024 bits).
   *
   * @param publicKey a public key
   *
   * @return the algorithm
   */
  public static String getDetailedPublicKeyAlgorithm(PublicKey publicKey) {
    if (publicKey == null) {
      return "null";
    }

    String algorithm = publicKey.getAlgorithm();
    if (publicKey instanceof RSAPublicKey) {
      RSAPublicKey rsaPublicKey = (RSAPublicKey)publicKey;
      int bitLength = rsaPublicKey.getModulus().bitLength();
      algorithm += " [" + bitLength + " bit]";
    } else if (publicKey instanceof ECPublicKey) {
      ECPublicKey ecPublicKey = (ECPublicKey)publicKey;
      ECParameterSpec ecParams = ecPublicKey.getParams();
      String name = getCurveName(ecParams);
      if (name != null) {
        algorithm += " [" + name + "]";
      }
    } else if (publicKey instanceof DHPublicKey) {
      DHPublicKey dhPublicKey = (DHPublicKey)publicKey;
      dhPublicKey.getY();
      DHParameterSpec dhParamSpec = dhPublicKey.getParams();
      BigInteger g = dhParamSpec.getG();
      int l = dhParamSpec.getL();
      BigInteger p = dhParamSpec.getP();
      algorithm += " [p.length = " + p.bitLength() + ", g.length = " + g.bitLength() + ", l = " + l + "]";
    }

    return algorithm;
  }

  /**
   * Returns detailed algorithm information (including key length) about the given private key.
   * 
   * @param privateKey a private key
   * 
   * @return detailed information about the given private key
   */
  public static String getDetailedPrivateKeyAlgorithm(PrivateKey privateKey) {
    if (privateKey == null) {
      return "null";
    }

    String algorithm = privateKey.getAlgorithm();
    if (privateKey instanceof RSAPrivateKey) {
      RSAPrivateKey rsaPrivateKey = (RSAPrivateKey)privateKey;
      int bitLength = rsaPrivateKey.getModulus().bitLength();
      algorithm += " [" + bitLength + " bit]";
    } else if (privateKey instanceof ECPrivateKey) {
      ECPrivateKey ecPrivateKey = (ECPrivateKey)privateKey;
      ECParameterSpec ecParams = ecPrivateKey.getParams();
      String name = getCurveName(ecParams);
      if (name != null) {
        algorithm += " [" + name + "]";
      }
    }
    return algorithm;
  }

  /**
   * Gets the curve name if known (or {@code null}).
   *
   * @param params an specification of the curve
   *
   * @return the name
   */
  public static String getCurveName(ECParameterSpec params) {
    org.bouncycastle.jce.spec.ECNamedCurveSpec namedECParams = toNamedCurveSpec(params);
    if (namedECParams == null) {
      return null;
    }

    return namedECParams.getName();
  }

  public static ECParameterSpec toExplicitECParameterSpec(ECNamedCurveParameterSpec parameterSpec) {
    return toExplicitECParameterSpec(toECNamedCurveSpec(parameterSpec));
  }

  /**
   * Translates (named) curve spec to JCA compliant explicit param spec.
   *
   * @param params an EC parameter spec, possibly named
   *
   * @return another spec not name based
   */
  public static ECParameterSpec toExplicitECParameterSpec(ECParameterSpec params) {
    try {
      ECPoint g = params.getGenerator();
      BigInteger n = params.getOrder(); // Order, order
      int h = params.getCofactor(); // co-factor
      EllipticCurve curve = params.getCurve();
      BigInteger a = curve.getA();
      BigInteger b = curve.getB();
      ECField field = curve.getField();
      if (field instanceof ECFieldFp) {
        BigInteger p = ((ECFieldFp)field).getP();
        ECField resultField = new ECFieldFp(p);
        EllipticCurve resultCurve = new EllipticCurve(resultField, a, b);
        return new ECParameterSpec(resultCurve, g, n, h);
      } else if (field instanceof ECFieldF2m) {
        int m = ((ECFieldF2m)field).getM();
        ECField resultField = new ECFieldF2m(m);
        EllipticCurve resultCurve = new EllipticCurve(resultField, a, b);
        return new ECParameterSpec(resultCurve, g, n, h);
      } else {
        LOGGER.warning("Could not make named EC param spec explicit");
        return params;
      }
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Could not make named EC param spec explicit", e);
      return params;
    }
  }

  private static org.bouncycastle.jce.spec.ECNamedCurveSpec toNamedCurveSpec(ECParameterSpec ecParamSpec) {
    if (ecParamSpec == null) {
      return null;
    }
    if (ecParamSpec instanceof org.bouncycastle.jce.spec.ECNamedCurveSpec) {
      return (org.bouncycastle.jce.spec.ECNamedCurveSpec)ecParamSpec;
    }

    @SuppressWarnings("unchecked")
    List<String> names = Collections.list(ECNamedCurveTable.getNames());
    List<org.bouncycastle.jce.spec.ECNamedCurveSpec> namedSpecs = new ArrayList<org.bouncycastle.jce.spec.ECNamedCurveSpec>();
    for (String name: names) {
      org.bouncycastle.jce.spec.ECNamedCurveSpec namedSpec = toECNamedCurveSpec(ECNamedCurveTable.getParameterSpec(name));
      if (namedSpec.getCurve().equals(ecParamSpec.getCurve())
          && namedSpec.getGenerator().equals(ecParamSpec.getGenerator())
          && namedSpec.getOrder().equals(ecParamSpec.getOrder())
          && namedSpec.getCofactor() == ecParamSpec.getCofactor()) {
        namedSpecs.add(namedSpec);
      }
    }
    if (namedSpecs.isEmpty()) {
      // throw new IllegalArgumentException("No named curve found");
      return null;
    } else if (namedSpecs.size() == 1) {
      return namedSpecs.get(0);
    } else {
      return namedSpecs.get(0);
    }
  }

  /**
   * Translates internal BC named curve spec to BC provided JCA compliant named curve spec.
   *
   * @param namedParamSpec a named EC parameter spec
   *
   * @return a JCA compliant named EC parameter spec
   */
  public static org.bouncycastle.jce.spec.ECNamedCurveSpec toECNamedCurveSpec(org.bouncycastle.jce.spec.ECNamedCurveParameterSpec namedParamSpec) {
    String name = namedParamSpec.getName();
    org.bouncycastle.math.ec.ECCurve curve = namedParamSpec.getCurve();
    org.bouncycastle.math.ec.ECPoint generator = namedParamSpec.getG();
    BigInteger order = namedParamSpec.getN();
    BigInteger coFactor = namedParamSpec.getH();
    byte[] seed = namedParamSpec.getSeed();
    return new org.bouncycastle.jce.spec.ECNamedCurveSpec(name, curve, generator, order, coFactor, seed);
  }

  /*
   * NOTE: Woj, I moved this here from DG14File, seemed more appropriate here. -- MO
   * FIXME: Do we still need this now that we have reconstructPublicKey? -- MO
   *
   * Woj says: Here we need to some hocus-pokus, the EAC specification require for
   * all the key information to include the domain parameters explicitly. This is
   * not what Bouncy Castle does by default. But we first have to check if this is
   * the case.
   */
  public static SubjectPublicKeyInfo toSubjectPublicKeyInfo(PublicKey publicKey) {
    try {
      String algorithm = publicKey.getAlgorithm();
      if ("EC".equals(algorithm) || "ECDH".equals(algorithm) || (publicKey instanceof ECPublicKey)) {
        ASN1InputStream asn1In = new ASN1InputStream(publicKey.getEncoded());
        try {
          SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(asn1In.readObject());
          AlgorithmIdentifier algorithmIdentifier = subjectPublicKeyInfo.getAlgorithm();
          String algOID = algorithmIdentifier.getAlgorithm().getId();
          if (!SecurityInfo.ID_EC_PUBLIC_KEY.equals(algOID)) {
            throw new IllegalStateException("Was expecting id-ecPublicKey (" + SecurityInfo.ID_EC_PUBLIC_KEY_TYPE + "), found " + algOID);
          }
          ASN1Primitive derEncodedParams = algorithmIdentifier.getParameters().toASN1Primitive();
          X9ECParameters params = null;
          if (derEncodedParams instanceof ASN1ObjectIdentifier) {
            ASN1ObjectIdentifier paramsOID = (ASN1ObjectIdentifier)derEncodedParams;

            /* It's a named curve from X9.62. */
            params = X962NamedCurves.getByOID(paramsOID);
            if (params == null) {
              throw new IllegalStateException("Could not find X9.62 named curve for OID " + paramsOID.getId());
            }

            /* Reconstruct the parameters. */
            org.bouncycastle.math.ec.ECPoint generator = params.getG();
            org.bouncycastle.math.ec.ECCurve curve = generator.getCurve();
            generator = curve.createPoint(generator.getAffineXCoord().toBigInteger(), generator.getAffineYCoord().toBigInteger());
            params = new X9ECParameters(params.getCurve(), generator, params.getN(), params.getH(), params.getSeed());
          } else {
            /* It's not a named curve, we can just return the decoded public key info. */
            return subjectPublicKeyInfo;
          }

          if (publicKey instanceof org.bouncycastle.jce.interfaces.ECPublicKey) {
            org.bouncycastle.jce.interfaces.ECPublicKey ecPublicKey = (org.bouncycastle.jce.interfaces.ECPublicKey)publicKey;
            AlgorithmIdentifier id = new AlgorithmIdentifier(subjectPublicKeyInfo.getAlgorithm().getAlgorithm(), params.toASN1Primitive());
            org.bouncycastle.math.ec.ECPoint q = ecPublicKey.getQ();
            /* FIXME: investigate the compressed versus uncompressed point issue. What is allowed in TR03110? -- MO */
            // In case we would like to compress the point:
            // p = p.getCurve().createPoint(p.getX().toBigInteger(), p.getY().toBigInteger(), true);

            LOGGER.info("DEBUG: =====> q " + q);
            subjectPublicKeyInfo = new SubjectPublicKeyInfo(id, q.getEncoded(false));
            return subjectPublicKeyInfo;
          } else {
            return subjectPublicKeyInfo;
          }
        } finally {
          asn1In.close();
        }
      } else if ("DH".equals(algorithm) || (publicKey instanceof DHPublicKey)) {
        ASN1InputStream asn1In = new ASN1InputStream(publicKey.getEncoded());
        try {
          SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance((asn1In.readObject()));
          AlgorithmIdentifier algorithmIdentifier = subjectPublicKeyInfo.getAlgorithm();

          DHPublicKey dhPublicKey = (DHPublicKey)publicKey;
          DHParameterSpec dhSpec = dhPublicKey.getParams();
          return new SubjectPublicKeyInfo(
              new AlgorithmIdentifier(algorithmIdentifier.getAlgorithm(),
                  new DHParameter(dhSpec.getP(), dhSpec.getG(), dhSpec.getL()).toASN1Primitive()),
              new ASN1Integer(dhPublicKey.getY()));
        } finally {
          asn1In.close();
        }
      } else {
        throw new IllegalArgumentException("Unrecognized key type, found " + publicKey.getAlgorithm() + ", should be DH or ECDH");
      }
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      return null;
    }
  }

  public static PublicKey toPublicKey(SubjectPublicKeyInfo subjectPublicKeyInfo) {
    try {
      byte[] encodedPublicKeyInfoBytes = subjectPublicKeyInfo.getEncoded(ASN1Encoding.DER);
      KeySpec keySpec = new X509EncodedKeySpec(encodedPublicKeyInfoBytes);
      try {
        KeyFactory factory = KeyFactory.getInstance("DH");
        return factory.generatePublic(keySpec);
      } catch (GeneralSecurityException gse) {
        LOGGER.log(Level.FINE, "Not DH public key? Fine, let's try EC public key", gse);
        KeyFactory factory = KeyFactory.getInstance("EC", BC_PROVIDER);
        return factory.generatePublic(keySpec);
      }
    } catch (GeneralSecurityException gse2) {
      LOGGER.log(Level.WARNING, "Exception", gse2);
      return null;
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      return null;
    }
  }

  /**
   * Reconstructs the public key to use explicit domain params for EC public keys
   *
   * @param publicKey the public key
   *
   * @return the same public key (if not EC or error), or a reconstructed one (if EC)
   */
  public static PublicKey reconstructPublicKey(PublicKey publicKey) {
    if (!(publicKey instanceof ECPublicKey)) {
      return publicKey;
    }

    try {
      ECPublicKey ecPublicKey = (ECPublicKey)publicKey;
      ECPoint w = ecPublicKey.getW();
      ECParameterSpec params = ecPublicKey.getParams();
      params = toExplicitECParameterSpec(params);
      ECPublicKeySpec explicitPublicKeySpec = new ECPublicKeySpec(w, params);

      return KeyFactory.getInstance("EC", BC_PROVIDER).generatePublic(explicitPublicKeySpec);
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Could not make public key param spec explicit", e);
      return publicKey;
    }
  }

  public static ECPoint os2ECPoint(byte[] encodedECPoint) {
    DataInputStream dataIn = new DataInputStream(new ByteArrayInputStream(encodedECPoint));
    try {
      int b = dataIn.read();
      if (b != 0x04) {
        throw new IllegalArgumentException("Expected encoded ECPoint to start with 0x04");
      }
      int length = (encodedECPoint.length - 1) / 2;
      byte[] xCoordBytes = new byte[length];
      byte[] yCoordBytes = new byte[length];
      dataIn.readFully(xCoordBytes);
      dataIn.readFully(yCoordBytes);
      dataIn.close();
      BigInteger x = Util.os2i(xCoordBytes);
      BigInteger y = Util.os2i(yCoordBytes);
      return new ECPoint(x, y);
    } catch (IOException ioe) {
      throw new IllegalArgumentException("Exception", ioe);
    } finally {
      try {
        dataIn.close();
      } catch (IOException ioe) {
        LOGGER.log(Level.FINE, "Error closing stream", ioe);
      }
    }
  }

  /**
   * Encode an EC point (for use as public key value).
   * Prefixes a {@code 0x04} (without a length).
   *
   * @param point an EC Point
   *
   * @return an octet string
   */
  public static byte[] ecPoint2OS(ECPoint point) {
    ByteArrayOutputStream bOut = new ByteArrayOutputStream();
    BigInteger x = point.getAffineX();
    BigInteger y = point.getAffineY();
    try {
      bOut.write(0x04);
      bOut.write(i2os(x));
      bOut.write(i2os(y));
      bOut.close();
    } catch (IOException ioe) {
      throw new IllegalStateException("Exception", ioe);
    }
    return bOut.toByteArray();
  }

  /**
   * Infer an EAC object identifier for an EC or DH public key.
   *
   * @param publicKey a public key
   *
   * @return either ID_PK_ECDH or ID_PK_DH
   */
  public static String inferProtocolIdentifier(PublicKey publicKey) {
    String algorithm = publicKey.getAlgorithm();
    if ("EC".equals(algorithm) || "ECDH".equals(algorithm)) {
      return SecurityInfo.ID_PK_ECDH;
    } else if ("DH".equals(algorithm)) {
      return SecurityInfo.ID_PK_DH;
    } else {
      throw new IllegalArgumentException("Wrong key type. Was expecting ECDH or DH public key.");
    }
  }

  /**
   * EC point addition.
   *
   * @param x an EC point
   * @param y another EC point
   * @param params the domain parameters
   *
   * @return the resulting EC point
   */
  public static ECPoint add(ECPoint x, ECPoint y, ECParameterSpec params) {
    org.bouncycastle.math.ec.ECPoint bcX = toBouncyCastleECPoint(x, params);
    org.bouncycastle.math.ec.ECPoint bcY = toBouncyCastleECPoint(y, params);
    org.bouncycastle.math.ec.ECPoint bcSum = bcX.add(bcY);
    return fromBouncyCastleECPoint(bcSum);
  }

  /**
   * EC point scalar multiplication.
   *
   * @param s the scalar
   * @param point an EC point
   * @param params the domain parameters
   *
   * @return the resulting EC point
   */
  public static ECPoint multiply(BigInteger s, ECPoint point, ECParameterSpec params) {
    org.bouncycastle.math.ec.ECPoint bcPoint = toBouncyCastleECPoint(point, params);
    org.bouncycastle.math.ec.ECPoint bcProd = bcPoint.multiply(s);
    return fromBouncyCastleECPoint(bcProd);
  }

  public static byte[] getBytes(String str) {
    byte[] bytes = str.getBytes();
    try {
      bytes = str.getBytes("UTF-8");
    } catch (UnsupportedEncodingException use) {
      /* NOTE: unlikely. */
      LOGGER.log(Level.WARNING, "Exception", use);
    }
    return bytes;
  }

  public static BigInteger getPrime(AlgorithmParameterSpec params) {
    if (params == null) {
      throw new IllegalArgumentException("Parameters null");
    }

    if (params instanceof DHParameterSpec) {
      return ((DHParameterSpec)params).getP();
    } else if (params instanceof ECParameterSpec) {
      EllipticCurve curve = ((ECParameterSpec)params).getCurve();
      ECField field = curve.getField();
      if (!(field instanceof ECFieldFp)) {
        throw new IllegalStateException("Was expecting prime field of type ECFieldFp, found " + field.getClass().getCanonicalName());
      }
      return ((ECFieldFp)field).getP();
    } else {
      throw new IllegalArgumentException("Unsupported agreement algorithm, was expecting DHParameterSpec or ECParameterSpec, found " + params.getClass().getCanonicalName());
    }
  }

  public static String inferKeyAgreementAlgorithm(PublicKey publicKey) {
    if (publicKey instanceof ECPublicKey) {
      return "ECDH";
    } else if (publicKey instanceof DHPublicKey) {
      return "DH";
    } else {
      throw new IllegalArgumentException("Unsupported public key: " + publicKey);
    }
  }

  /**
   * This just solves the curve equation for y.
   *
   * @param affineX the x coord of a point on the curve
   * @param params EC parameters for curve over Fp
   * @return the corresponding y coord
   */
  public static BigInteger computeAffineY(BigInteger affineX, ECParameterSpec params) {
    ECCurve bcCurve = toBouncyCastleECCurve(params);
    ECFieldElement a = bcCurve.getA();
    ECFieldElement b = bcCurve.getB();
    ECFieldElement x = bcCurve.fromBigInteger(affineX);
    LOGGER.info("DEBUG: x.bitLength = " + x.bitLength());
    ECFieldElement y = x.multiply(x).add(a).multiply(x).add(b).sqrt();
    LOGGER.info("DEBUG: y.bitLength = " + y.bitLength());

    return y.toBigInteger();
  }

  public static org.bouncycastle.math.ec.ECPoint toBouncyCastleECPoint(ECPoint point, ECParameterSpec params) {
    org.bouncycastle.math.ec.ECCurve bcCurve = toBouncyCastleECCurve(params);
    return bcCurve.createPoint(point.getAffineX(), point.getAffineY());
  }

  public static ECPoint fromBouncyCastleECPoint(org.bouncycastle.math.ec.ECPoint point) {
    point = point.normalize();
    if (!point.isValid()) {
      LOGGER.warning("point not valid");
    }
    return new ECPoint(point.getAffineXCoord().toBigInteger(), point.getAffineYCoord().toBigInteger());
  }

  public static boolean isValid(ECPoint ecPoint, ECParameterSpec params) {
    org.bouncycastle.math.ec.ECPoint bcPoint = toBouncyCastleECPoint(ecPoint, params);
    return bcPoint.isValid();
  }

  public static ECPoint normalize(ECPoint ecPoint, ECParameterSpec params) {
    org.bouncycastle.math.ec.ECPoint bcPoint = toBouncyCastleECPoint(ecPoint, params);
    bcPoint = bcPoint.normalize();
    return fromBouncyCastleECPoint(bcPoint);
  }

  private static ECCurve toBouncyCastleECCurve(ECParameterSpec params) {
    EllipticCurve curve = params.getCurve();
    ECField field = curve.getField();
    if (!(field instanceof ECFieldFp)) {
      throw new IllegalArgumentException("Only prime field supported (for now), found " + field.getClass().getCanonicalName());
    }
    int coFactor = params.getCofactor();
    BigInteger order = params.getOrder();
    BigInteger a = curve.getA();
    BigInteger b = curve.getB();
    BigInteger p = getPrime(params);
    return new ECCurve.Fp(p, a, b, order, BigInteger.valueOf(coFactor));
  }

  public static ECPublicKeyParameters toBouncyECPublicKeyParameters(ECPublicKey publicKey) {
    ECParameterSpec ecParams = publicKey.getParams();
    org.bouncycastle.math.ec.ECPoint q = toBouncyCastleECPoint(publicKey.getW(), ecParams);
    return new ECPublicKeyParameters(q, toBouncyECDomainParameters(ecParams));
  }

  public static ECPrivateKeyParameters toBouncyECPrivateKeyParameters(ECPrivateKey privateKey) {
    BigInteger d = privateKey.getS();
    ECDomainParameters ecParams = toBouncyECDomainParameters(privateKey.getParams());
    return new ECPrivateKeyParameters(d, ecParams);
  }

  public static ECDomainParameters toBouncyECDomainParameters(ECParameterSpec params) {
    ECCurve curve = toBouncyCastleECCurve(params);
    org.bouncycastle.math.ec.ECPoint g = toBouncyCastleECPoint(params.getGenerator(), params);
    BigInteger n = params.getOrder();
    BigInteger h = BigInteger.valueOf(params.getCofactor());
    byte[] seed = params.getCurve().getSeed();
    return new ECDomainParameters(curve, g, n, h, seed);
  }

  public static byte[] getKeyHash(String agreementAlg, PublicKey pcdPublicKey) throws NoSuchAlgorithmException {
    if ("DH".equals(agreementAlg)) {
      /* TODO: this is probably wrong, what should be hashed? */
      MessageDigest md = MessageDigest.getInstance("SHA-1");
      md = MessageDigest.getInstance("SHA-1");
      return md.digest(getKeyData(agreementAlg, pcdPublicKey));
    } else if ("ECDH".equals(agreementAlg)) {
      org.bouncycastle.jce.interfaces.ECPublicKey pcdECPublicKey = (org.bouncycastle.jce.interfaces.ECPublicKey)pcdPublicKey;
      byte[] t = Util.i2os(pcdECPublicKey.getQ().getAffineXCoord().toBigInteger());
      return Util.alignKeyDataToSize(t, (int)Math.ceil(pcdECPublicKey.getParameters().getCurve().getFieldSize() / 8.0)); // TODO: Interop Ispra for SecP521r1 20170925.
//      return Util.alignKeyDataToSize(t, pcdECPublicKey.getParameters().getCurve().getFieldSize() / 8);
    }

    throw new NoSuchAlgorithmException("Unsupported agreement algorithm " + agreementAlg);
  }

  public static byte[] getKeyData(String agreementAlg, PublicKey pcdPublicKey) {
    if ("DH".equals(agreementAlg)) {
      DHPublicKey pcdDHPublicKey = (DHPublicKey)pcdPublicKey;
      return pcdDHPublicKey.getY().toByteArray();
    } else if ("ECDH".equals(agreementAlg)) {
      org.bouncycastle.jce.interfaces.ECPublicKey pcdECPublicKey = (org.bouncycastle.jce.interfaces.ECPublicKey)pcdPublicKey;
      return pcdECPublicKey.getQ().getEncoded(false);
    }

    throw new IllegalArgumentException("Unsupported agreement algorithm " + agreementAlg);
  }

  /* Get standard crypto primitives from default provider or (if that fails) from BC. */

  public static Cipher getCipher(String algorithm) throws GeneralSecurityException {
    try {
      return Cipher.getInstance(algorithm);
    } catch (Exception e) {
      LOGGER.log(Level.FINE, "Default provider could not provide this cipher, falling back to explicit BC", e);
      return Cipher.getInstance(algorithm, BC_PROVIDER);
    }
  }

  public static Cipher getCipher(String algorithm, int mode, Key keySpec) throws GeneralSecurityException {
    try {
      Cipher cipher =  Cipher.getInstance(algorithm);
      cipher.init(mode, keySpec);
      return cipher;
    } catch (Exception e) {
      LOGGER.log(Level.FINE, "Default provider could not provide this Cipher, falling back to explicit BC", e);
      Cipher cipher =  Cipher.getInstance(algorithm, BC_PROVIDER);
      cipher.init(mode, keySpec);
      return cipher;
    }
  }

  public static KeyAgreement getKeyAgreement(String algorithm) throws GeneralSecurityException {
    try {
      return KeyAgreement.getInstance(algorithm);
    } catch (Exception e) {
      LOGGER.log(Level.FINE, "Default provider could not provide this Key Agreement, falling back to explicit BC", e);
      return KeyAgreement.getInstance(algorithm, BC_PROVIDER);
    }
  }

  public static KeyPairGenerator getKeyPairGenerator(String algorithm) throws GeneralSecurityException {
    try {
      return KeyPairGenerator.getInstance(algorithm);
    } catch (Exception e) {
      LOGGER.log(Level.FINE, "Default provider could not provide this Key Pair Generator, falling back to explicit BC", e);
      return KeyPairGenerator.getInstance(algorithm, BC_PROVIDER);
    }
  }

  public static Mac getMac(String algorithm) throws GeneralSecurityException {
    try {
      return Mac.getInstance(algorithm);
    } catch (Exception e) {
      LOGGER.log(Level.FINE, "Default provider could not provide this Mac, falling back to explicit BC", e);
      return Mac.getInstance(algorithm, BC_PROVIDER);
    }
  }

  public static Mac getMac(String algorithm, Key key) throws GeneralSecurityException {
    try {
      Mac mac = Mac.getInstance(algorithm);
      mac.init(key);
      return mac;
    } catch (Exception e) {
      LOGGER.log(Level.FINE, "Default provider could not provide this Mac, falling back to explicit BC", e);
      Mac mac = Mac.getInstance(algorithm, BC_PROVIDER);
      mac.init(key);
      return mac;
    }
  }

  public static MessageDigest getMessageDigest(String algorithm) throws GeneralSecurityException {
    try {
      return MessageDigest.getInstance(algorithm);
    } catch (Exception e) {
      LOGGER.log(Level.FINE, "Default provider could not provide this Message Digest, falling back to explicit BC", e);
      return MessageDigest.getInstance(algorithm, BC_PROVIDER);
    }
  }

  public static PublicKey getPublicKey(String algorithm, KeySpec keySpec) throws GeneralSecurityException {
    try {
      KeyFactory kf = KeyFactory.getInstance(algorithm);
      return kf.generatePublic(keySpec);
    } catch (Exception e) {
      LOGGER.log(Level.FINE, "Default provider could not provide this Key Factory or Public Key, falling back to explicit BC", e);
      KeyFactory kf = KeyFactory.getInstance(algorithm, BC_PROVIDER);
      return kf.generatePublic(keySpec);
    }
  }

  public static Signature getSignature(String algorithm) throws GeneralSecurityException {
    try {
      return Signature.getInstance(algorithm);
    } catch (Exception e) {
      LOGGER.log(Level.FINE, "Default provider could not provide this Signature, falling back to explicit BC", e);
      return Signature.getInstance(algorithm, BC_PROVIDER);
    }
  }

  public static CertificateFactory getCertificateFactory(String algorithm) throws GeneralSecurityException {
    try {
      return CertificateFactory.getInstance(algorithm);
    } catch (Exception e) {
      LOGGER.log(Level.FINE, "Default provider could not provide this Certificate Factory, falling back ot explicit BC", e);
      return CertificateFactory.getInstance(algorithm, BC_PROVIDER);
    }
  }
}
