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
 * $Id: $
 */

package org.jmrtd.protocol;

import java.io.Serializable;
import java.security.PublicKey;

public class AAResult implements Serializable {

  private static final long serialVersionUID = 8800803919646625713L;

  private PublicKey publicKey;
  private String digestAlgorithm;
  private String signatureAlgorithm;
  private byte[] challenge;
  private byte[] response;

  public AAResult(PublicKey publicKey, String digestAlgorithm, String signatureAlgorithm, byte[] challenge, byte[] response) {
    this.publicKey = publicKey;
    this.digestAlgorithm = digestAlgorithm;
    this.signatureAlgorithm = signatureAlgorithm;
    this.challenge = challenge;
    this.response = response;
  }

  public byte[] getChallenge() {
    return challenge;
  }
  
  public byte[] getResponse() {
    return response;
  }

  public PublicKey getPublicKey() {
    return publicKey;
  }

  public String getDigestAlgorithm() {
    return digestAlgorithm;
  }

  public String getSignatureAlgorithm() {
    return signatureAlgorithm;
  }
}
