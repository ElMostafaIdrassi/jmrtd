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
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import net.sf.scuba.smartcards.CommandAPDU;
import net.sf.scuba.smartcards.ISO7816;
import net.sf.scuba.smartcards.ResponseAPDU;
import net.sf.scuba.tlv.TLVInputStream;
import net.sf.scuba.tlv.TLVOutputStream;
import net.sf.scuba.util.Hex;

/**
 * A card side secure messaging wrapper that uses triple DES.
 * Unwraps Command APDUs received from the terminal,
 * wraps Response APDUs to be sent back to the terminal.
 * 
 * @author The JMRTD team (info@jmrtd.org)
 * 
 * @version $Revision$
 * 
 * @since 0.5.10
 */
public class ReverseDESedeWrapper implements ReverseSecureMessagingWrapper {
  
  private static final long serialVersionUID = -1427994718980505261L;
  
  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");
  
  /** Initialization vector consisting of 8 zero bytes. */
  public static final IvParameterSpec ZERO_IV_PARAM_SPEC = new IvParameterSpec(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 });
  
  private Cipher cipher;
  private Mac mac;
  
  private SecretKey ksEnc;
  private SecretKey ksMac;
  
  /** The Send Sequence Counter. */
  private long ssc;
  
  /**
   * Creates a secure messaging wrapper.
   * The send sequence counter will initially be set to {@code 0}.
   * 
   * @param ksEnc the key to use for encrypting and decrypting APDU payloads
   * @param ksMac the key to use for generating and checking APDU message authentication codes
   * 
   * @throws GeneralSecurityException on failure to configure the underlying cryptographic primitives
   */
  public ReverseDESedeWrapper(SecretKey ksEnc, SecretKey ksMac) throws GeneralSecurityException {
    this(ksEnc, ksMac, 0L);
  }
  
  /**
   * Creates a secure messaging wrapper.
   * 
   * @param ksEnc the key to use for encrypting and decrypting APDU payloads
   * @param ksMac the key to use for generating and checking APDU message authentication codes
   * 
   * @param ssc the initial send sequence counter value
   * 
   * @throws GeneralSecurityException on failure to configure the underlying cryptographic primitives
   */
  public ReverseDESedeWrapper(SecretKey ksEnc, SecretKey ksMac, long ssc) throws GeneralSecurityException {
    this(ksEnc, ksMac, "DESede/CBC/NoPadding", "ISO9797Alg3Mac", ssc);
  }
  
  private ReverseDESedeWrapper(SecretKey ksEnc, SecretKey ksMac, String cipherAlg, String macAlg, long ssc) throws GeneralSecurityException {
    this.ksEnc = ksEnc;
    this.ksMac = ksMac;
    this.ssc = ssc;
    cipher = Cipher.getInstance(cipherAlg);
    mac = Mac.getInstance(macAlg);
  }
  
  /**
   * Gets the send sequence counter.
   * 
   * @return the current value of the send sequence counter
   */
  @Override
  public long getSendSequenceCounter() {
    return ssc;
  }
  
  /**
   * Unwraps a Command APDU received from the terminal.
   * 
   * @param wrappedCommandAPDU a wrapped Command APDU
   */
  public CommandAPDU unwrap(CommandAPDU wrappedCommandAPDU) {
    ssc++;
    try {
      return unwrapCommandAPDU(wrappedCommandAPDU, ksEnc, ksMac, ssc);
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
  public ResponseAPDU wrap(ResponseAPDU responseAPDU) {
    ssc++;
    try {
      return wrapResponseAPDU(responseAPDU, ksEnc, ksMac, ssc);
    } catch (IOException ioe) {
      throw new IllegalStateException(ioe.getMessage());
    } catch (GeneralSecurityException gse) {
      throw new IllegalStateException(gse.getMessage());
    }
  }
  
  /* PRIVATE */
  
  private CommandAPDU unwrapCommandAPDU(CommandAPDU wrappedCommandAPDU, SecretKey ksEnc, SecretKey ksMac, long ssc) throws IOException, GeneralSecurityException {
    int cla = wrappedCommandAPDU.getCLA();
    int ins = wrappedCommandAPDU.getINS();
    int p1 = wrappedCommandAPDU.getP1();
    int p2 = wrappedCommandAPDU.getP2();
    
    byte[] maskedHeader = new byte[] { (byte)cla, (byte)ins, (byte)p1, (byte)p2 };
    byte[] paddedMaskedHeader = Util.padWithMRZ(maskedHeader);
    
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
            cipher.init(Cipher.DECRYPT_MODE, ksEnc, ZERO_IV_PARAM_SPEC);
            byte[] cipherText = tlvInputStream.readValue();
            data = cipher.doFinal(cipherText);
            data = Util.unpad(data);
            break;
          case ISO7816.TAG_SM_ENCRYPTED_DATA_WITH_PADDING_INDICATOR:
            cipher.init(Cipher.DECRYPT_MODE, ksEnc, ZERO_IV_PARAM_SPEC);
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
  
  private ResponseAPDU wrapResponseAPDU(ResponseAPDU responseAPDU, SecretKey ksEnc, SecretKey ksMac, long ssc) throws IOException, GeneralSecurityException {
    byte[] data = Util.padWithMRZ(responseAPDU.getData());
    
    cipher.init(Cipher.ENCRYPT_MODE, ksEnc, ZERO_IV_PARAM_SPEC);
    byte[] cipherText = cipher.doFinal(data);
    
    /*
     *  case (byte)0x87: data = readDO87(inputStream, false); break;
     *  case (byte)0x85: data = readDO87(inputStream, true); break;
     *  case (byte)0x99: sw = readDO99(inputStream); break;
     *  case (byte)0x8E: cc = readDO8E(inputStream); isFinished = true; break;
     */
    /* ??? */
    
    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
    TLVOutputStream tlvOutputStream = new TLVOutputStream(byteArrayOutputStream);
    
    try {
      
      /* Data. */
      tlvOutputStream.writeTag(ISO7816.TAG_SM_ENCRYPTED_DATA_WITH_PADDING_INDICATOR);
      tlvOutputStream.writeLength(1 + cipherText.length);
      tlvOutputStream.write(0x01);
      tlvOutputStream.write(cipherText);
      tlvOutputStream.writeValueEnd(); /* 0x87 */
      
      /* Status word. */
      tlvOutputStream.writeTag(ISO7816.TAG_SM_STATUS_WORD);
      tlvOutputStream.writeLength(2);
      tlvOutputStream.write(responseAPDU.getSW1());
      tlvOutputStream.write(responseAPDU.getSW2());
      tlvOutputStream.writeValueEnd(); /* 0x99 */
      
      /* The data and the status word, with added padding. */
      byte[] paddedData = Util.padWithMRZ(byteArrayOutputStream.toByteArray());
      
      /* Compute Mac over padded data. */
      mac.init(ksMac);    
      ByteArrayOutputStream dataToBeMaccedByteArrayOutputStream = new ByteArrayOutputStream();
      DataOutputStream dataToBeMaccedDataOutputStream = new DataOutputStream(dataToBeMaccedByteArrayOutputStream);
      try {
        dataToBeMaccedDataOutputStream.writeLong(ssc);
        dataToBeMaccedDataOutputStream.write(paddedData, 0, paddedData.length);
        byte[] cc = mac.doFinal(dataToBeMaccedByteArrayOutputStream.toByteArray());
        /* NOTE: Length should be 8. */
        
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
