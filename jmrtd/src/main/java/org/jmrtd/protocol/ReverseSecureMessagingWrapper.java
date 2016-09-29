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

package org.jmrtd.protocol;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.jmrtd.Util;

import net.sf.scuba.smartcards.CommandAPDU;
import net.sf.scuba.smartcards.ISO7816;
import net.sf.scuba.smartcards.ResponseAPDU;
import net.sf.scuba.smartcards.ReverseAPDUWrapper;
import net.sf.scuba.tlv.TLVInputStream;
import net.sf.scuba.tlv.TLVOutputStream;

/**
 * A card side secure messaging wrapper.
 * Unwraps Command APDUs received from the terminal,
 * wraps Response APDUs to be sent back to the terminal.
 * 
 * @author The JMRTD team (info@jmrtd.org)
 * 
 * @version $Revision$
 * 
 * @since 0.5.10
 */
public abstract class ReverseSecureMessagingWrapper implements ReverseAPDUWrapper {

  private static final long serialVersionUID = 5005702227790003353L;

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  /** Encryption key. */
  private SecretKey ksEnc;

  /** Message authentication key. */
  private SecretKey ksMac;
  
  /** Encryption cipher. */
  private Cipher cipher;
  
  /** Message authentication cipher. */
  private Mac mac;
  
  /** The Send Sequence Counter. */
  private long ssc;

  /**
   * Creates a secure messaging wrapper.
   * 
   * @param ksEnc the key to use for encrypting and decrypting APDU payloads
   * @param ksMac the key to use for generating and checking APDU message authentication codes
   * @param cipherAlg the encryption cipher algorithm
   * 
   * @param ssc the initial send sequence counter value
   * 
   * @throws GeneralSecurityException on failure to configure the underlying cryptographic primitives
   */

  public ReverseSecureMessagingWrapper(SecretKey ksEnc, SecretKey ksMac, String cipherAlg, String macAlg, long ssc) throws GeneralSecurityException {
    this.ksEnc = ksEnc;
    this.ksMac = ksMac;
    this.ssc = ssc;
    
    this.cipher = Cipher.getInstance(cipherAlg);
    /* NOTE: Will be initialized later. */
    
    this.mac = Mac.getInstance(macAlg);
    /* NOTE: Will be initialized later. */
  }
  
  /**
   * Gets the send sequence counter.
   * 
   * @return the current value of the send sequence counter
   */
  public long getSendSequenceCounter() {
    return ssc;
  }
  
  /**
   * Gets the initialization vector.
   * 
   * @return the initialization vector
   */
  protected abstract IvParameterSpec getIV();
  
  /**
   * Unwraps a Command APDU received from the terminal.
   * 
   * @param wrappedCommandAPDU a wrapped Command APDU
   */
  @Override
  public CommandAPDU unwrap(CommandAPDU wrappedCommandAPDU) {
    ssc++;
    try {
      return unwrapCommandAPDU(wrappedCommandAPDU, ksEnc, ksMac);
    } catch (IOException ioe) {
      throw new IllegalStateException(ioe.getMessage());
    } catch (GeneralSecurityException gse) {
      throw new IllegalStateException(gse.getMessage());      
    }
  }
  
  /**
   * Wraps a Response APDU to be sent back to the terminal.
   * 
   * @param responseAPDU a Response APDU
   */
  @Override
  public ResponseAPDU wrap(ResponseAPDU responseAPDU) {
    ssc++;
    try {
      return wrapResponseAPDU(responseAPDU, ksEnc, ksMac);
    } catch (IOException ioe) {
      throw new IllegalStateException(ioe.getMessage());
    } catch (GeneralSecurityException gse) {
      throw new IllegalStateException(gse.getMessage());
    }
  }
  
  private CommandAPDU unwrapCommandAPDU(CommandAPDU wrappedCommandAPDU, SecretKey ksEnc, SecretKey ksMac) throws IOException, GeneralSecurityException {
    int cla = wrappedCommandAPDU.getCLA();
    int ins = wrappedCommandAPDU.getINS();
    int p1 = wrappedCommandAPDU.getP1();
    int p2 = wrappedCommandAPDU.getP2();
    
    byte[] maskedHeader = new byte[] { (byte)cla, (byte)ins, (byte)p1, (byte)p2 };
    byte[] paddedMaskedHeader = Util.pad(maskedHeader, 8);
    
    byte[] wrappedData = wrappedCommandAPDU.getData();
    TLVInputStream tlvInputStream = new TLVInputStream(new ByteArrayInputStream(wrappedData));
    
    try {
      boolean isFinished = false;
      int le = -1;
      byte[] data = null;
      byte[] cc = null;
      while (!isFinished) {
        int tag = tlvInputStream.readTag();
        int length = tlvInputStream.readLength();
        switch (tag) {
          case ISO7816.TAG_SM_EXPECTED_LENGTH:
            byte[] leBytes = tlvInputStream.readValue();
            le = 0;
            for (int i = 0; i < leBytes.length; i++) {
              le = (le << 8) | (leBytes[i] & 0xFF);
            }
            break;
          case ISO7816.TAG_SM_ENCRYPTED_DATA:
            cipher.init(Cipher.DECRYPT_MODE, ksEnc,  getIV());
            byte[] cipherText = tlvInputStream.readValue();
            data = cipher.doFinal(cipherText);
            data = Util.unpad(data);
            break;
          case ISO7816.TAG_SM_ENCRYPTED_DATA_WITH_PADDING_INDICATOR:
            cipher.init(Cipher.DECRYPT_MODE, ksEnc,  getIV());
            byte[] cipherTextPrefixedWithOne = tlvInputStream.readValue();
            byte[] cipherTextWithoutPrefixed = new byte[length - 1];
            System.arraycopy(cipherTextPrefixedWithOne, 1, cipherTextWithoutPrefixed, 0, length - 1);
            data = cipher.doFinal(cipherTextWithoutPrefixed);
            data = Util.unpad(data);
            break;
          case ISO7816.TAG_SM_CRYPTOGRAPHIC_CHECKSUM:
            cc = tlvInputStream.readValue();
            isFinished = true;
            break;
          default:
            LOGGER.warning("Skipping unsupported tag " + Integer.toHexString(tag));
            tlvInputStream.skip(length);
            break;
        }
      }    
      
      /* TODO: Compute checksum and compare to cc. */
      
      CommandAPDU commandAPDU = null;
      if (le < 0) {
        commandAPDU = new CommandAPDU(cla ^ 0x0C, ins, p1, p2, data);
      } else {
        commandAPDU = new CommandAPDU(cla ^ 0x0C, ins, p1, p2, data, le);
      }
      return commandAPDU;
    } finally {
      tlvInputStream.close();
    }
  }
  
  private ResponseAPDU wrapResponseAPDU(ResponseAPDU responseAPDU, SecretKey ksEnc, SecretKey ksMac) throws IOException, GeneralSecurityException {
    byte[] data = Util.pad(responseAPDU.getData(), 8);
    
    cipher.init(Cipher.ENCRYPT_MODE, ksEnc, getIV());
    byte[] cipherText = cipher.doFinal(data);
    
    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
    TLVOutputStream tlvOutputStream = new TLVOutputStream(byteArrayOutputStream);
    
    try {
      /* Data. */
      tlvOutputStream.writeTag(ISO7816.TAG_SM_ENCRYPTED_DATA_WITH_PADDING_INDICATOR);
      tlvOutputStream.writeLength(1 + cipherText.length);
      tlvOutputStream.write(0x01);
      tlvOutputStream.write(cipherText);
      tlvOutputStream.writeValueEnd(); /* TAG_SM_ENCRYPTED_DATA_WITH_PADDING_INDICATOR */
      
      /* Status word. */
      tlvOutputStream.writeTag(ISO7816.TAG_SM_STATUS_WORD);
      tlvOutputStream.writeLength(2);
      tlvOutputStream.write(responseAPDU.getSW1());
      tlvOutputStream.write(responseAPDU.getSW2());
      tlvOutputStream.writeValueEnd(); /* TAG_SM_STATUS_WORD */
      
      /* The data and the status word, with added padding. */
      byte[] paddedData = Util.pad(byteArrayOutputStream.toByteArray(), 8);
      
      /* Compute Mac over padded data. */
      mac.init(ksMac);    
      ByteArrayOutputStream dataToBeMaccedByteArrayOutputStream = new ByteArrayOutputStream();
      DataOutputStream dataToBeMaccedDataOutputStream = new DataOutputStream(dataToBeMaccedByteArrayOutputStream);
      try {
        dataToBeMaccedDataOutputStream.writeLong(getSendSequenceCounter());
        dataToBeMaccedDataOutputStream.write(paddedData, 0, paddedData.length);
        byte[] cc = mac.doFinal(dataToBeMaccedByteArrayOutputStream.toByteArray());
        
        /* NOTE: Length should be 8 bytes. With AES (blocksize 128) we will get 16 instead. */
        if (cc.length > 8) {
          byte[] truncatedCC = new byte[8];
          System.arraycopy(cc, 0, truncatedCC, 0, 8);
          cc = truncatedCC;
        }
        
        tlvOutputStream.writeTag(ISO7816.TAG_SM_CRYPTOGRAPHIC_CHECKSUM);
        tlvOutputStream.writeValue(cc);
      } finally {
        dataToBeMaccedDataOutputStream.close();
      }
      
      writeStatusWord(ISO7816.SW_NO_ERROR, byteArrayOutputStream);
      
      return new ResponseAPDU(byteArrayOutputStream.toByteArray());
    } finally {
      tlvOutputStream.close();
    }
  }
  
  private void writeStatusWord(short sw, OutputStream outputStream) throws IOException {
    outputStream.write((sw & 0xFF00) >> 8);
    outputStream.write(sw & 0xFF);
  }
}
