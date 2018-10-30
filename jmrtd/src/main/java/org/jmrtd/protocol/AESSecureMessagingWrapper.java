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

package org.jmrtd.protocol;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.jmrtd.Util;

import net.sf.scuba.smartcards.CommandAPDU;
import net.sf.scuba.smartcards.ISO7816;
import net.sf.scuba.smartcards.ResponseAPDU;
import net.sf.scuba.tlv.TLVUtil;

/**
 * An AES secure messaging wrapper for APDUs. Based on TR-SAC.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision$
 */
public class AESSecureMessagingWrapper extends SecureMessagingWrapper implements Serializable {

  private static final long serialVersionUID = 2086301081448345496L;

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  private SecretKey ksEnc;
  private SecretKey ksMac;

  private transient Cipher sscIVCipher;
  private transient Cipher cipher;
  private transient Mac mac;

  /** The send sequence counter. */
  private long ssc;

  /**
   * Constructs a secure messaging wrapper based on the secure messaging
   * session keys and the initial value of the send sequence counter.
   * Used in BAC and EAC 1.
   *
   * @param ksEnc the session key for encryption
   * @param ksMac the session key for macs
   * @param ssc the initial value of the send sequence counter
   *
   * @throws GeneralSecurityException when the available JCE providers cannot provide the necessary cryptographic primitives
   */
  public AESSecureMessagingWrapper(SecretKey ksEnc, SecretKey ksMac, long ssc) throws GeneralSecurityException {
    this(ksEnc, ksMac, 256, true, ssc);
  }

  /**
   * Constructs a secure messaging wrapper based on the secure messaging
   * session keys and the initial value of the send sequence counter.
   * Used in BAC and EAC 1.
   *
   * @param ksEnc the session key for encryption
   * @param ksMac the session key for macs
   * @param maxTranceiveLength the maximum tranceive length, typical values are 256 or 65536
   * @param shouldCheckMAC a boolean indicating whether this wrapper will check the MAC in wrapped response APDUs
   * @param ssc the initial value of the send sequence counter
   *
   * @throws GeneralSecurityException when the available JCE providers cannot provide the necessary cryptographic primitives
   */
  public AESSecureMessagingWrapper(SecretKey ksEnc, SecretKey ksMac, int maxTranceiveLength, boolean shouldCheckMAC, long ssc) throws GeneralSecurityException {
    super(maxTranceiveLength, shouldCheckMAC);
    this.ksEnc = ksEnc;
    this.ksMac = ksMac;
    this.ssc = ssc;
    sscIVCipher = Util.getCipher("AES/ECB/NoPadding", Cipher.ENCRYPT_MODE, ksEnc);
    cipher = Util.getCipher("AES/CBC/NoPadding");
    mac = Util.getMac("AESCMAC", ksMac);
  }

  /**
   * Returns the type of secure messaging wrapper (in this case {@code "AES"}).
   *
   * @return the type of secure messaging wrapper
   */
  public String getType() {
    return "AES";
  }

  /**
   * Returns the current value of the send sequence counter.
   *
   * @return the current value of the send sequence counter.
   */
  @Override
  public long getSendSequenceCounter() {
    return ssc;
  }

  /**
   * Wraps the APDU buffer of a command apdu.
   * As a side effect, this method increments the internal send
   * sequence counter maintained by this wrapper.
   *
   * @param commandAPDU buffer containing the command apdu.
   *
   * @return length of the command apdu after wrapping.
   */
  public CommandAPDU wrap(CommandAPDU commandAPDU) {
    try {
      return wrapCommandAPDU(commandAPDU);
    } catch (GeneralSecurityException gse) {
      throw new IllegalStateException("Exception", gse);
    } catch (IOException ioe) {
      throw new IllegalStateException("Exception", ioe);
    }
  }

  /**
   * Unwraps the buffer of a response APDU.
   *
   * @param responseAPDU the response APDU
   *
   * @return a new byte array containing the unwrapped buffer
   */
  public ResponseAPDU unwrap(ResponseAPDU responseAPDU) {
    try {
      byte[] rapdu = responseAPDU.getBytes();
      if (rapdu.length == 2) {
        // No sense in unwrapping - card indicates some kind of error.
        throw new IllegalStateException("Card indicates SM error, SW = " + Integer.toHexString(responseAPDU.getSW() & 0xFFFF));
      }
      return new ResponseAPDU(unwrapResponseAPDU(rapdu));
    } catch (GeneralSecurityException gse) {
      throw new IllegalStateException("Exception", gse);
    } catch (IOException ioe) {
      throw new IllegalStateException("Exception", ioe);
    }
  }

  @Override
  public SecretKey getEncryptionKey() {
    return ksEnc;
  }

  @Override
  public SecretKey getMACKey() {
    return ksMac;
  }

  @Override
  public String toString() {
    return "AESSecureMessagingWrapper [ " + ksEnc.toString() + ", " + ksMac.toString() + ", " + ssc + "]";
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((ksEnc == null) ? 0 : ksEnc.hashCode());
    result = prime * result + ((ksMac == null) ? 0 : ksMac.hashCode());
    result = prime * result + (int) (ssc ^ (ssc >>> 32));
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null) {
      return false;
    }
    if (getClass() != obj.getClass()) {
      return false;
    }
    AESSecureMessagingWrapper other = (AESSecureMessagingWrapper) obj;
    if (ksEnc == null) {
      if (other.ksEnc != null) {
        return false;
      }
    } else if (!ksEnc.equals(other.ksEnc)) {
      return false;
    }
    if (ksMac == null) {
      if (other.ksMac != null) {
        return false;
      }
    } else if (!ksMac.equals(other.ksMac)) {
      return false;
    }
    if (ssc != other.ssc) {
      return false;
    }

    return true;
  }

  /**
   * Does the actual encoding of a command APDU.
   * Based on Section E.3 of ICAO-TR-PKI, especially the examples.
   *
   * @param commandAPDU buffer containing the APDU data. It must be large enough to receive the wrapped APDU
   *
   * @return the wrapped command APDU
   *
   * @throws GeneralSecurityException on error wrapping the command APDU
   * @throws IOException on error
   */
  private CommandAPDU wrapCommandAPDU(CommandAPDU commandAPDU) throws GeneralSecurityException, IOException {
    int lc = commandAPDU.getNc();
    int le = commandAPDU.getNe();

    ByteArrayOutputStream bOut = new ByteArrayOutputStream();

    byte[] maskedHeader = new byte[] { (byte)(commandAPDU.getCLA() | (byte)0x0C), (byte)commandAPDU.getINS(), (byte)commandAPDU.getP1(), (byte)commandAPDU.getP2() };
    byte[] paddedMaskedHeader = Util.pad(maskedHeader, 16); // 128 bits is 16 bytes

    boolean hasDO85 = ((byte)commandAPDU.getINS() == ISO7816.INS_READ_BINARY2);

    byte[] do8587 = new byte[0];
    byte[] do97 = new byte[0];

    /* Include the expected length, if present. Always include for Active Authentication. */
    int ins = commandAPDU.getINS();
    if ((0 < le && le < getMaxTranceiveLength()) || (byte)ins == ISO7816.INS_INTERNAL_AUTHENTICATE) {
      bOut.reset();
      bOut.write((byte)0x97);
      bOut.write((byte)0x01);
      bOut.write((byte)le);
      do97 = bOut.toByteArray();
    }

    ssc++;
    byte[] sscBytes = getSSCAsBytes(ssc);

    if (lc > 0) {
      /* If we have command data, encrypt it. */
      byte[] data = Util.pad(commandAPDU.getData(), 16);

      /* Re-initialize cipher, this time with IV based on SSC. */
      cipher.init(Cipher.ENCRYPT_MODE, ksEnc, getIV(sscBytes));

      byte[] ciphertext = cipher.doFinal(data);

      bOut.reset();
      bOut.write(hasDO85 ? (byte)0x85 : (byte)0x87);
      bOut.write(TLVUtil.getLengthAsBytes(ciphertext.length + (hasDO85 ? 0 : 1)));
      if (!hasDO85) {
        bOut.write(0x01);
      }
      bOut.write(ciphertext);
      do8587 = bOut.toByteArray();
    }

    bOut.reset();
    bOut.write(paddedMaskedHeader);
    bOut.write(do8587);
    bOut.write(do97);

    byte[] m = bOut.toByteArray();

    bOut.reset();
    bOut.write(sscBytes);
    bOut.write(m);
    bOut.flush();
    byte[] n = Util.pad(bOut.toByteArray(), 16);

    /* Compute cryptographic checksum... */
    mac.init(ksMac);
    byte[] cc = mac.doFinal(n);
    int ccLength = cc.length;
    if (ccLength != 8) {
      ccLength = 8;
    }

    bOut.reset();
    bOut.write((byte)0x8E);
    bOut.write(ccLength);
    bOut.write(cc, 0, ccLength);
    byte[] do8E = bOut.toByteArray();

    /* Construct protected apdu... */
    bOut.reset();
    bOut.write(do8587);
    bOut.write(do97);
    bOut.write(do8E);
    byte[] data = bOut.toByteArray();

    return new CommandAPDU(maskedHeader[0], maskedHeader[1], maskedHeader[2], maskedHeader[3], data, getMaxTranceiveLength());
  }

  /**
   * Does the actual decoding of a response APDU. Based on Section E.3 of
   * TR-PKI, especially the examples.
   *
   * @param rapdu buffer containing the APDU data
   *
   * @return a byte array containing the unwrapped APDU buffer
   *
   * @throws GeneralSecurityException on error unwrapping
   * @throws IOException on error
   */
  private byte[] unwrapResponseAPDU(byte[] rapdu) throws GeneralSecurityException, IOException {
    long oldssc = ssc;
    try {
      if (rapdu == null || rapdu.length < 2) {
        throw new IllegalArgumentException("Invalid response APDU");
      }
      ssc++;
      cipher.init(Cipher.DECRYPT_MODE, ksEnc, getIV(ssc));
      byte[] cc = null;
      byte[] data = new byte[0];
      short sw = 0;
      DataInputStream inputStream = new DataInputStream(new ByteArrayInputStream(rapdu));
      try {
        boolean finished = false;
        while (!finished) {
          int tag = inputStream.readByte();
          switch (tag) {
            case (byte) 0x87:
              data = readDO87(inputStream, false);
            break;
            case (byte) 0x85:
              data = readDO87(inputStream, true);
            break;
            case (byte) 0x99:
              sw = readDO99(inputStream);
            break;
            case (byte) 0x8E:
              cc = readDO8E(inputStream);
            finished = true;
            break;
            default:
              LOGGER.warning("Unexpected tag " + Integer.toHexString(tag));
              break;
          }
        }
      } finally {
        inputStream.close();
      }
      if (shouldCheckMAC() && !checkMac(rapdu, cc)) {
        throw new IllegalStateException("Invalid MAC");
      }
      ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
      byteArrayOutputStream.write(data, 0, data.length);
      byteArrayOutputStream.write((sw & 0xFF00) >> 8);
      byteArrayOutputStream.write(sw & 0x00FF);
      return byteArrayOutputStream.toByteArray();
    } finally {
      /*
       * If we fail to unwrap, at least make sure we have the same counter
       * as the ICC, so that we can continue to communicate using secure
       * messaging...
       */
      if (ssc == oldssc) {
        ssc++;
      }
    }
  }

  /**
   * Reads a data object.
   * The {@code 0x87} tag has already been read.
   *
   * @param inputStream the stream to read from
   * @param do85 whether to expect a {@code 0x85} (including an extra 1 length) data object.
   *
   * @return the bytes that were read
   *
   * @throws IOException on error reading from the stream
   * @throws GeneralSecurityException on error decrypting the data
   */
  private byte[] readDO87(DataInputStream inputStream, boolean do85) throws IOException, GeneralSecurityException {
    /* Read length... */
    int length = 0;
    int buf = inputStream.readUnsignedByte();
    if ((buf & 0x00000080) != 0x00000080) {
      /* Short form */
      length = buf;
      if (!do85) {
        buf = inputStream.readUnsignedByte(); /* should be 0x01... */
        if (buf != 0x01) {
          throw new IllegalStateException("DO'87 expected 0x01 marker, found " + Integer.toHexString(buf & 0xFF));
        }
      }
    } else {
      /* Long form */
      int lengthBytesCount = buf & 0x0000007F;
      for (int i = 0; i < lengthBytesCount; i++) {
        length = (length << 8) | inputStream.readUnsignedByte();
      }
      if (!do85) {
        buf = inputStream.readUnsignedByte(); /* should be 0x01... */
        if (buf != 0x01) {
          throw new IllegalStateException("DO'87 expected 0x01 marker");
        }
      }
    }
    if (!do85) {
      length--; /* takes care of the extra 0x01 marker... */
    }
    /* Read, decrypt, unpad the data... */
    byte[] ciphertext = new byte[length];
    inputStream.readFully(ciphertext);
    byte[] paddedData = cipher.doFinal(ciphertext);
    return Util.unpad(paddedData);
  }

  /**
   * Reads a data object.
   * The {@code 0x99} tag has already been read.
   *
   * @param inputStream the stream to read from
   *
   * @return the status word
   *
   * @throws IOException on error reading from the stream
   */
  private short readDO99(DataInputStream inputStream) throws IOException {
    int length = inputStream.readUnsignedByte();
    if (length != 2) {
      throw new IllegalStateException("DO'99 wrong length");
    }
    byte sw1 = inputStream.readByte();
    byte sw2 = inputStream.readByte();
    return (short)(((sw1 & 0x000000FF) << 8) | (sw2 & 0x000000FF));
  }

  /**
   * Reads a data object.
   * The {@code 0x8E} tag has already been read.
   *
   * @param inputStream the stream to read from
   *
   * @return the bytes that were read
   *
   * @throws IOException on error
   */
  private byte[] readDO8E(DataInputStream inputStream) throws IOException {
    int length = inputStream.readUnsignedByte();
    if (length != 8 && length != 16) {
      throw new IllegalStateException("DO'8E wrong length for MAC: " + length);
    }
    byte[] cc = new byte[length];
    inputStream.readFully(cc);
    return cc;
  }

  /**
   * Checks the message authentication code.
   *
   * @param rapdu the data of a response APDU
   * @param cc the message authentication code
   *
   * @return a boolean indicating whether the message authentication code was ok
   *
   * @throws GeneralSecurityException on error
   */
  private boolean checkMac(byte[] rapdu, byte[] cc) throws GeneralSecurityException {
    try {
      ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
      DataOutputStream dataOutputStream = new DataOutputStream(byteArrayOutputStream);
      dataOutputStream.write(getSSCAsBytes(ssc));
      byte[] paddedData = Util.pad(rapdu, 0, rapdu.length - 2 - 8 - 2, 16);
      dataOutputStream.write(paddedData, 0, paddedData.length);
      dataOutputStream.flush();
      dataOutputStream.close();
      mac.init(ksMac);
      byte[] cc2 = mac.doFinal(byteArrayOutputStream.toByteArray());

      if (cc2.length > 8 && cc.length == 8) {
        byte[] newCC2 = new byte[8];
        System.arraycopy(cc2, 0, newCC2, 0, newCC2.length);
        cc2 = newCC2;
      }

      return Arrays.equals(cc, cc2);
    } catch (IOException ioe) {
      LOGGER.log(Level.WARNING, "Exception checking MAC", ioe);
      return false;
    }
  }

  /**
   * Returns the IV by encrypting the send sequence counter.
   *
   * AES uses IV = E K_Enc , SSC), see ICAO SAC TR Section 4.6.3.
   *
   * @param ssc the SSC
   *
   * @return the initialization vector specification
   *
   * @throws GeneralSecurityException on error
   */
  private IvParameterSpec getIV(long ssc) throws GeneralSecurityException {
    byte[] sscBytes = getSSCAsBytes(ssc);
    byte[] encryptedSSC = sscIVCipher.doFinal(sscBytes);
    return new IvParameterSpec(encryptedSSC);
  }

  /**
   * Returns the IV by encrypting the send sequence counter.
   *
   * AES uses IV = E K_Enc , SSC), see ICAO SAC TR Section 4.6.3.
   *
   * @param sscBytes the SSC as blocksize aligned byte array
   *
   * @return the initialization vector specification
   *
   * @throws GeneralSecurityException on error
   */
  private IvParameterSpec getIV(byte[] sscBytes) throws GeneralSecurityException {
    byte[] encryptedSSC = sscIVCipher.doFinal(sscBytes);
    return new IvParameterSpec(encryptedSSC);
  }

  /**
   * Returns the SSC as bytes, making sure the 128 bit (16 byte) block-size is used.
   *
   * @param ssc the send sequence counter
   *
   * @return the ssc as a 16 byte array
   */
  private static byte[] getSSCAsBytes(long ssc) {
    try {
      ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream(16);
      byteArrayOutputStream.write(0x00);
      byteArrayOutputStream.write(0x00);
      byteArrayOutputStream.write(0x00);
      byteArrayOutputStream.write(0x00);
      byteArrayOutputStream.write(0x00);
      byteArrayOutputStream.write(0x00);
      byteArrayOutputStream.write(0x00);
      byteArrayOutputStream.write(0x00);

      /* A long will take 8 bytes. */
      DataOutputStream dataOutputStream = new DataOutputStream(byteArrayOutputStream);
      dataOutputStream.writeLong(ssc);
      dataOutputStream.close();
      return byteArrayOutputStream.toByteArray();
    } catch (IOException ioe) {
      LOGGER.log(Level.WARNING, "Exception", ioe);
    }
    return null;
  }
}
