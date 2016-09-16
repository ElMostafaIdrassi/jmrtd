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

package org.jmrtd;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import net.sf.scuba.smartcards.CommandAPDU;
import net.sf.scuba.smartcards.ISO7816;
import net.sf.scuba.smartcards.ResponseAPDU;
import net.sf.scuba.tlv.TLVInputStream;
import net.sf.scuba.tlv.TLVUtil;

/*
 * TODO: Can we use TLVInputStream instead of those readDOXX methods? -- MO
 */

/**
 * Secure messaging wrapper for APDUs.
 * Initially based on Section E.3 of ICAO-TR-PKI.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision$
 */
public class DESedeSecureMessagingWrapper extends SecureMessagingWrapper implements Serializable {
  
  private static final long serialVersionUID = -2859033943345961793L;
  
  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");
  
  /** Initialization vector consisting of 8 zero bytes. */
  public static final IvParameterSpec ZERO_IV_PARAM_SPEC = new IvParameterSpec(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 });
  
  private SecretKey ksEnc, ksMac;
  private transient Cipher cipher;
  private transient Mac mac;
  
  private long ssc;
  
  private boolean shouldCheckMAC;
  
  /**
   * Constructs a secure messaging wrapper based on the secure messaging
   * session keys. The initial value of the send sequence counter is set to
   * <code>0L</code>.
   *
   * @param ksEnc the session key for encryption
   * @param ksMac the session key for macs
   *
   * @throws GeneralSecurityException
   *             when the available JCE providers cannot provide the necessary
   *             cryptographic primitives
   *             ("DESede/CBC/Nopadding" Cipher, "ISO9797Alg3Mac" Mac).
   */
  public DESedeSecureMessagingWrapper(SecretKey ksEnc, SecretKey ksMac) throws GeneralSecurityException {
    this(ksEnc, ksMac, true);
  }
  
  /**
   * Constructs a secure messaging wrapper based on the secure messaging
   * session keys. The initial value of the send sequence counter is set to
   * <code>0L</code>.
   *
   * @param ksEnc the session key for encryption
   * @param ksMac the session key for macs
   * @param doCheckMAC whether to check the MAC when unwrapping response APDUs
   *
   * @throws GeneralSecurityException
   *             when the available JCE providers cannot provide the necessary
   *             cryptographic primitives
   *             ("DESede/CBC/Nopadding" Cipher, "ISO9797Alg3Mac" Mac).
   */
  public DESedeSecureMessagingWrapper(SecretKey ksEnc, SecretKey ksMac, boolean doCheckMAC) throws GeneralSecurityException {
    this(ksEnc, ksMac, doCheckMAC, 0L);
  }
  
  /**
   * Constructs a secure messaging wrapper based on the secure messaging
   * session keys and the initial value of the send sequence counter.
   * Used in BAC and EAC 1.
   *
   * @param ksEnc the session key for encryption
   * @param ksMac the session key for macs
   * @param ssc the initial value of the send sequence counter
   *
   * @throws NoSuchPaddingException when the available JCE providers cannot provide the necessary cryptographic primitives
   * @throws NoSuchAlgorithmException when the available JCE providers cannot provide the necessary cryptographic primitives
   *
   */
  public DESedeSecureMessagingWrapper(SecretKey ksEnc, SecretKey ksMac, long ssc) throws NoSuchAlgorithmException, NoSuchPaddingException {
    this(ksEnc, ksMac, "DESede/CBC/NoPadding", "ISO9797Alg3Mac", true, ssc);
  }
  
  /**
   * Constructs a secure messaging wrapper based on the secure messaging
   * session keys and the initial value of the send sequence counter.
   * Used in BAC and EAC 1.
   *
   * @param ksEnc the session key for encryption
   * @param ksMac the session key for macs
   * @param doCheckMAC whether to check the MAC when unwrapping response APDUs
   * @param ssc the initial value of the send sequence counter
   *
   * @throws NoSuchPaddingException when the available JCE providers cannot provide the necessary cryptographic primitives
   * @throws NoSuchAlgorithmException when the available JCE providers cannot provide the necessary cryptographic primitives
   *
   */
  public DESedeSecureMessagingWrapper(SecretKey ksEnc, SecretKey ksMac, boolean doCheckMAC, long ssc) throws NoSuchAlgorithmException, NoSuchPaddingException {
    this(ksEnc, ksMac, "DESede/CBC/NoPadding", "ISO9797Alg3Mac", doCheckMAC, ssc);
  }
  
  private DESedeSecureMessagingWrapper(SecretKey ksEnc, SecretKey ksMac, String cipherAlg, String macAlg, boolean doCheckMAC, long ssc) throws NoSuchAlgorithmException, NoSuchPaddingException {
    this.ksEnc = ksEnc;
    this.ksMac = ksMac;
    this.shouldCheckMAC = doCheckMAC;
    this.ssc = ssc;
    cipher = Cipher.getInstance(cipherAlg);
    mac = Mac.getInstance(macAlg);
  }
  
  /**
   * Wraps the APDU buffer <code>capdu</code> of a command APDU.
   * As a side effect, this method increments the internal send
   * sequence counter maintained by this wrapper.
   *
   * @param commandAPDU buffer containing the command APDU
   *
   * @return length of the command apdu after wrapping
   */
  public CommandAPDU wrap(CommandAPDU commandAPDU) {
    ssc++;
    try {
      return wrapCommandAPDU(commandAPDU, ssc);
    } catch (GeneralSecurityException gse) {
      LOGGER.log(Level.SEVERE, "Exception", gse);
      throw new IllegalStateException(gse.getMessage());
    } catch (IOException ioe) {
      LOGGER.log(Level.SEVERE, "Exception", ioe);
      throw new IllegalStateException(ioe.getMessage());
    }
  }
  
  /**
   * Unwraps the apdu buffer <code>rapdu</code> of a response apdu.
   *
   * @param responseAPDU the response APDU
   *
   * @return a new byte array containing the unwrapped buffer
   */
  public ResponseAPDU unwrap(ResponseAPDU responseAPDU) {
    ssc++;
    try {
      byte[] data = responseAPDU.getData();
      if (data == null || data.length <= 0) {        
        // no sense in unwrapping - card indicates some kind of error
        throw new IllegalStateException("Card indicates SM error, SW = " + Integer.toHexString(responseAPDU.getSW() & 0xFFFF));
        /* FIXME: wouldn't it be cleaner to throw a CardServiceException? */
      }
      return unwrapResponseAPDU(responseAPDU, ssc);
    } catch (GeneralSecurityException gse) {
      LOGGER.log(Level.SEVERE, "Exception", gse);
      throw new IllegalStateException(gse.getMessage());
    } catch (IOException ioe) {
      LOGGER.log(Level.SEVERE, "Exception", ioe);
      throw new IllegalStateException(ioe.getMessage());
    }
  }
  
  public SecretKey getEncryptionKey() {
    return ksEnc;
  }
  
  public SecretKey getMACKey() {
    return ksMac;
  }
  
  /**
   * Gets the current value of the send sequence counter.
   *
   * @return the current value of the send sequence counter.
   */
  @Override
  public long getSendSequenceCounter() {
    return ssc;
  }
  
  @Override
  public String toString() {
    return "DESedeSecureMessagingWrapper [ " + ksEnc.toString() + ", " + ksMac.toString() + ", " + ssc + "]";
  }
  
  /**
   * Does the actual encoding of a command APDU.
   * Based on Section E.3 of ICAO-TR-PKI, especially the examples.
   *
   * @param commandAPDU the command APDU
   * @param ssc the send sequence counter which, is assumed, has already been increased
   *
   * @return a byte array containing the wrapped apdu buffer
   */
  private CommandAPDU wrapCommandAPDU(CommandAPDU commandAPDU, long ssc) throws GeneralSecurityException, IOException {
    int lc = commandAPDU.getNc();
    int le = commandAPDU.getNe();
    
    ByteArrayOutputStream bOut = new ByteArrayOutputStream();		
    
    byte[] maskedHeader = new byte[] { (byte)(commandAPDU.getCLA() | (byte)0x0C), (byte)commandAPDU.getINS(), (byte)commandAPDU.getP1(), (byte)commandAPDU.getP2() };
    byte[] paddedMaskedHeader = Util.padWithMRZ(maskedHeader);
    
    boolean hasDO85 = ((byte)commandAPDU.getINS() == ISO7816.INS_READ_BINARY2);
    
    byte[] do8587 = new byte[0];
    byte[] do97 = new byte[0];
    
    if (le > 0) {
      bOut.reset();
      bOut.write((byte)0x97);
      bOut.write((byte)0x01);
      bOut.write((byte)le);
      do97 = bOut.toByteArray();
    }
    
    cipher.init(Cipher.ENCRYPT_MODE, ksEnc, ZERO_IV_PARAM_SPEC);
    
    if (lc > 0) {
      /* If we have command data, encrypt it. */
      byte[] data = Util.padWithMRZ(commandAPDU.getData());
      byte[] ciphertext = cipher.doFinal(data);
      
      bOut.reset();
      bOut.write(hasDO85 ? (byte)0x85 : (byte)0x87);
      bOut.write(TLVUtil.getLengthAsBytes(ciphertext.length + (hasDO85 ? 0 : 1)));
      if (!hasDO85) { bOut.write(0x01); };
      bOut.write(ciphertext, 0, ciphertext.length);
      do8587 = bOut.toByteArray();
    }
    
    bOut.reset();
    DataOutputStream dataOut = new DataOutputStream(bOut);
    dataOut.writeLong(ssc);
    dataOut.write(paddedMaskedHeader);
    dataOut.write(do8587);
    dataOut.write(do97);
    
    dataOut.flush();
    byte[] n = Util.padWithMRZ(bOut.toByteArray());
    
    /* Compute cryptographic checksum... */
    mac.init(ksMac);
    byte[] cc = mac.doFinal(n);
    int ccLength = cc.length;
    if (ccLength != 8) {
      ccLength = 8;
    }
    
    bOut.reset();
    bOut.write((byte) 0x8E);
    bOut.write(ccLength);
    bOut.write(cc, 0, ccLength);
    byte[] do8E = bOut.toByteArray();
    
    /* Construct protected APDU... */
    bOut.reset();
    bOut.write(do8587);
    bOut.write(do97);
    bOut.write(do8E);
    byte[] data = bOut.toByteArray();
    
    CommandAPDU wrappedCommandAPDU = new CommandAPDU(maskedHeader[0], maskedHeader[1], maskedHeader[2], maskedHeader[3], data, 256);
    
    /* FIXME: If extended length APDUs are supported (they must for EAC, that 256 should be 65536). See bug #26 in SF bugtracker. -- MO */
    //		wc = new CommandAPDU(maskedHeader[0], maskedHeader[1], maskedHeader[2], maskedHeader[3], data, 65536);
    
    return wrappedCommandAPDU;
  }
  
  /**
   * Unwraps a response APDU sent by the ICC.
   * Based on Section E.3 of TR-PKI, especially the examples.
   *
   * @param responseAPDU the response APDU
   * @param ssc the send sequence counter which, it is assumed, has already been incremented by the caller
   *
   * @return a byte array containing the unwrapped APDU buffer
   */
  private ResponseAPDU unwrapResponseAPDU(ResponseAPDU responseAPDU, long ssc) throws GeneralSecurityException, IOException {
    byte[] rapdu = responseAPDU.getBytes();
    if (rapdu == null || rapdu.length < 2) {
      throw new IllegalArgumentException("Invalid response APDU");
    }
    cipher.init(Cipher.DECRYPT_MODE, ksEnc, ZERO_IV_PARAM_SPEC);
    DataInputStream inputStream = new DataInputStream(new ByteArrayInputStream(rapdu));
    byte[] data = new byte[0];
    short sw = 0;
    boolean isFinished = false;
    byte[] cc = null;
    while (!isFinished) {
      int tag = inputStream.readByte();
      switch (tag) {
        case (byte)0x87: data = readDO87(inputStream, false); break;
        case (byte)0x85: data = readDO87(inputStream, true); break;
        case (byte)0x99: sw = readDO99(inputStream); break;
        case (byte)0x8E: cc = readDO8E(inputStream); isFinished = true; break;
      }
    }
    if (shouldCheckMAC && !checkMac(rapdu, cc, ssc)) {
      throw new IllegalStateException("Invalid MAC");
    }
    ByteArrayOutputStream bOut = new ByteArrayOutputStream();
    bOut.write(data, 0, data.length);
    bOut.write((sw & 0xFF00) >> 8);
    bOut.write(sw & 0x00FF);
    return new ResponseAPDU(bOut.toByteArray());
  }
  
  /*
   *
   * The SM Data Objects (see [ISO/IEC 7816-4]) MUST be used in the following order:
   *   - Command APDU: [DO‘85’ or DO‘87’] [DO‘97’] DO‘8E’.
   *   - Response APDU: [DO‘85’ or DO‘87’] [DO‘99’] DO‘8E’.
   * 
   */
  
  /**
   * The <code>0x87</code> tag has already been read.
   *
   * @param inputStream inputstream to read from
   */
  private byte[] readDO87(DataInputStream inputStream, boolean do85) throws IOException, GeneralSecurityException {
    /* Read length... */
    int length = 0;
    int buf = inputStream.readUnsignedByte();
    if ((buf & 0x00000080) != 0x00000080) {
      /* Short form */
      length = buf;
    } else {
      /* Long form */
      int lengthBytesCount = buf & 0x0000007F;
      for (int i = 0; i < lengthBytesCount; i++) {
        length = (length << 8) | inputStream.readUnsignedByte();
      }
    }
    
    if (!do85) {
      buf = inputStream.readUnsignedByte(); /* should be 0x01... */
      if (buf != 0x01) {
        throw new IllegalStateException("DO'87 expected 0x01 marker, found " + Integer.toHexString(buf & 0xFF));
      }
      
      length--; /* takes care of the extra 0x01 marker... */
    }
    
    /* Read, decrypt, unpad the data... */
    byte[] ciphertext = new byte[length];
    inputStream.readFully(ciphertext);
    byte[] paddedData = cipher.doFinal(ciphertext);
    byte[] data = Util.unpad(paddedData);
    return data;
  }
  
  /**
   * The <code>0x99</code> tag has already been read.
   *
   * @param inputStream inputstream to read from.
   */
  private short readDO99(DataInputStream inputStream) throws IOException {
    int length = inputStream.readUnsignedByte();
    if (length != 2) {
      throw new IllegalStateException("DO'99 wrong length");
    }
    byte sw1 = inputStream.readByte();
    byte sw2 = inputStream.readByte();
    return (short) (((sw1 & 0x000000FF) << 8) | (sw2 & 0x000000FF));
  }
  
  /**
   * The <code>0x8E</code> tag has already been read.
   *
   * @param inputStream inputstream to read from.
   */
  private byte[] readDO8E(DataInputStream inputStream) throws IOException, GeneralSecurityException {
    int length = inputStream.readUnsignedByte();
    if (length != 8) {
      throw new IllegalStateException("DO'8E wrong length");
    }
    byte[] cc1 = new byte[8];
    inputStream.readFully(cc1);
    return cc1;
  }
  
  /**
   * Check the MAC.
   * 
   * @param rapdu the bytes of the response APDU, including the {@code 0x8E} tag, the length of the MAC, the MAC itself, and the status word
   * @param cc1 the MAC sent by the other party
   * @param ssc the send sequence counter
   * @return whether the computed MAC is identical
   * 
   * @throws GeneralSecurityException on security related error
   */
  private boolean checkMac(byte[] rapdu, byte[] cc1, long ssc) throws GeneralSecurityException {
    try {
      ByteArrayOutputStream bOut = new ByteArrayOutputStream();
      DataOutputStream dataOut = new DataOutputStream(bOut);
      dataOut.writeLong(ssc);
      byte[] paddedData = Util.padWithMRZ(rapdu, 0, rapdu.length - 2 - 8 - 2);
      dataOut.write(paddedData, 0, paddedData.length);
      dataOut.flush();
      dataOut.close();
      mac.init(ksMac);
      byte[] cc2 = mac.doFinal(bOut.toByteArray());
      if (cc2.length > 8 && cc1.length == 8) {
        byte[] newCC2 = new byte[8];
        System.arraycopy(cc2, 0, newCC2, 0, newCC2.length);
        cc2 = newCC2;
      }
      return Arrays.equals(cc1, cc2);
    } catch (IOException ioe) {
      return false;
    }
  }
}
