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

import java.security.GeneralSecurityException;
import java.util.logging.Logger;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

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
public class ReverseDESedeSecureMessagingWrapper extends ReverseSecureMessagingWrapper {
  
  private static final long serialVersionUID = -1427994718980505261L;
  
  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");
  
  /** Initialization vector consisting of 8 zero bytes. */
  public static final IvParameterSpec ZERO_IV_PARAM_SPEC = new IvParameterSpec(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 });
  
  /**
   * Creates a secure messaging wrapper.
   * The send sequence counter will initially be set to {@code 0}.
   * 
   * @param ksEnc the key to use for encrypting and decrypting APDU payloads
   * @param ksMac the key to use for generating and checking APDU message authentication codes
   * 
   * @throws GeneralSecurityException on failure to configure the underlying cryptographic primitives
   */
  public ReverseDESedeSecureMessagingWrapper(SecretKey ksEnc, SecretKey ksMac) throws GeneralSecurityException {
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
  public ReverseDESedeSecureMessagingWrapper(SecretKey ksEnc, SecretKey ksMac, long ssc) throws GeneralSecurityException {
    super(ksEnc, ksMac, "DESede/CBC/NoPadding", "ISO9797Alg3Mac", ssc);
  }
  
  protected IvParameterSpec getIV() {
    return ZERO_IV_PARAM_SPEC;
  }
}
