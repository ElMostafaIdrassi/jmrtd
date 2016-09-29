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

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 * A card side secure messaging wrapper that uses AES.
 * Unwraps Command APDUs received from the terminal,
 * wraps Response APDUs to be sent back to the terminal.
 * 
 * @author The JMRTD team (info@jmrtd.org)
 * 
 * @version $Revision$
 * 
 * @since 0.5.10
 */
public class ReverseAESSecureMessagingWrapper extends ReverseSecureMessagingWrapper {
  
  private static final long serialVersionUID = -1427994718980505261L;
  
  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");
  
  /** The cipher used in updating the SSC. */
  private Cipher sscIVCipher;
  
  /**
   * Creates a secure messaging wrapper based on AES.
   * 
   * @param ksEnc the key to use for encrypting and decrypting APDU payloads
   * @param ksMac the key to use for generating and checking APDU message authentication codes
   * @param ssc the initial send sequence counter value
   * 
   * @throws GeneralSecurityException on failure to configure the underlying cryptographic primitives
   */
  public ReverseAESSecureMessagingWrapper(SecretKey ksEnc, SecretKey ksMac, long ssc) throws GeneralSecurityException {
    super(ksEnc, ksMac, "AES/CBC/NoPadding", "AESCMAC", ssc);    
    sscIVCipher = Cipher.getInstance("AES/ECB/NoPadding");
    sscIVCipher.init(Cipher.ENCRYPT_MODE, ksEnc);
  }
    
  /**
   * Gets the IV by encrypting the SSC.
   *
   * AES secure messaging uses IV = E K_Enc , SSC), see ICAO SAC TR Section 4.6.3.
   * 
   * @return the initialization vector
   */
  protected IvParameterSpec getIV() {
    try {
      byte[] sscBytes = getSSCAsBytes(getSendSequenceCounter());
      byte[] encryptedSSC = sscIVCipher.doFinal(sscBytes);
      IvParameterSpec ivParams = new IvParameterSpec(encryptedSSC);
      return ivParams;
    } catch (GeneralSecurityException gse) {
      LOGGER.log(Level.SEVERE, "Unexpected exception", gse);
      throw new IllegalStateException(gse.getMessage());
    }
  }
  
  /**
   * Gets the SSC as bytes.
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
      LOGGER.warning("Exception: " + ioe.getMessage());
    }
    return null;
  }
}
