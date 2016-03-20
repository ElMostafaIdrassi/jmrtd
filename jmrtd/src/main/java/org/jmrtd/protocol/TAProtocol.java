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

import java.io.ByteArrayOutputStream;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.List;

import org.jmrtd.PassportService;
import org.jmrtd.SecureMessagingWrapper;
import org.jmrtd.Util;
import org.jmrtd.cert.CVCAuthorizationTemplate.Role;
import org.jmrtd.lds.icao.MRZInfo;
import org.jmrtd.cert.CVCPrincipal;
import org.jmrtd.cert.CardVerifiableCertificate;

import net.sf.scuba.smartcards.CardServiceException;
import net.sf.scuba.tlv.TLVOutputStream;

/**
 * The EAC Terminal Authentication protocol.
 * 
 * @author The JMRTD team (info@jmrtd.org)
 * 
 * @version $Revision: $
 *
 * @since 0.5.6
 */
public class TAProtocol {
  
  private final int TAG_CVCERTIFICATE_SIGNATURE = 0x5F37;
  
  private PassportService service;
  private SecureMessagingWrapper wrapper;
  
  public TAProtocol(PassportService service, SecureMessagingWrapper wrapper) {
    this.service = service;
    this.wrapper = wrapper;
  }
  
  /* From BSI-03110 v1.1, B.2:
   *
   * <pre>
   * The following sequence of commands SHALL be used to implement Terminal Authentication:
   *  1. MSE:Set DST
   *  2. PSO:Verify Certificate
   *  3. MSE:Set AT
   *  4. Get Challenge
   *  5. External Authenticate
   * Steps 1 and 2 are repeated for every CV certificate to be verified
   * (CVCA Link Certificates, DV Certificate, IS Certificate).
   * </pre>
   */
  /**
   * Perform TA (Terminal Authentication) part of EAC (version 1). For details see
   * TR-03110 ver. 1.11. In short, we feed the sequence of terminal
   * certificates to the card for verification, get a challenge from the
   * card, sign it with terminal private key, and send back to the card
   * for verification.
   *
   * @param caReference reference issuer
   * @param terminalCertificates terminal certificate chain
   * @param terminalKey terminal private key
   * @param taAlg algorithm
   * @param chipAuthenticationResult the chip authentication result
   * @param documentNumber the document number
   *
   * @return the challenge from the card
   *
   * @throws CardServiceException on error
   */
  public synchronized TAResult doTA(CVCPrincipal caReference, List<CardVerifiableCertificate> terminalCertificates,
      PrivateKey terminalKey, String taAlg, CAResult chipAuthenticationResult, String documentNumber) throws CardServiceException {
    try {
      if (terminalCertificates == null || terminalCertificates.size() < 1) {
        throw new IllegalArgumentException("Need at least 1 certificate to perform TA, found: " + terminalCertificates);
      }
      
      byte[] caKeyHash = chipAuthenticationResult.getKeyHash();
      /* The key hash that resulted from CA. */
      if (caKeyHash == null) {
        throw new IllegalArgumentException("CA key hash is null");
      }
      
      /* FIXME: check that terminalCertificates holds a (inverted, i.e. issuer before subject) chain. */
      
      /* Check if first cert is/has the expected CVCA, and remove it from chain if it is the CVCA. */
      CardVerifiableCertificate firstCert = terminalCertificates.get(0);
      Role firstCertRole = firstCert.getAuthorizationTemplate().getRole();
      if (Role.CVCA.equals(firstCertRole)) {
        CVCPrincipal firstCertHolderReference = firstCert.getHolderReference();
        if (caReference != null && !caReference.equals(firstCertHolderReference)) {
          throw new CardServiceException("First certificate holds wrong authority, found " + firstCertHolderReference.getName() + ", expected " + caReference.getName());
        }
        if (caReference == null) {
          caReference = firstCertHolderReference;
        }
        terminalCertificates.remove(0);
      }
      CVCPrincipal firstCertAuthorityReference = firstCert.getAuthorityReference();
      if (caReference != null && !caReference.equals(firstCertAuthorityReference)) {
        throw new CardServiceException("First certificate not signed by expected CA, found " + firstCertAuthorityReference.getName() + ",  expected " + caReference.getName());
      }
      if (caReference == null) {
        caReference = firstCertAuthorityReference;
      }
      
      /* Check if the last cert is an IS cert. */
      CardVerifiableCertificate lastCert = terminalCertificates.get(terminalCertificates.size() - 1);
      Role lastCertRole = lastCert.getAuthorizationTemplate().getRole();
      if (!Role.IS.equals(lastCertRole)) {
        throw new CardServiceException("Last certificate in chain (" + lastCert.getHolderReference().getName() + ") does not have role IS, but has role " + lastCertRole);
      }
      CardVerifiableCertificate terminalCert = lastCert;
      
      /* Have the MRTD check our chain. */
      for (CardVerifiableCertificate cert: terminalCertificates) {
        try {
          CVCPrincipal authorityReference = cert.getAuthorityReference();
          
          /* Step 1: MSE:SetDST */
          /* Manage Security Environment: Set for verification: Digital Signature Template,
           * indicate authority of cert to check.
           */
          byte[] authorityRefBytes = Util.wrapDO((byte) 0x83, authorityReference.getName().getBytes("ISO-8859-1"));
          service.sendMSESetDST(wrapper, authorityRefBytes);
          
          /* Cert body is already in TLV format. */
          byte[] body = cert.getCertBodyData();
          
          /* Signature not yet in TLV format, prefix it with tag and length. */
          byte[] signature = cert.getSignature();
          ByteArrayOutputStream sigOut = new ByteArrayOutputStream();
          TLVOutputStream tlvSigOut = new TLVOutputStream(sigOut);
          tlvSigOut.writeTag(TAG_CVCERTIFICATE_SIGNATURE);
          tlvSigOut.writeValue(signature);
          tlvSigOut.close();
          signature = sigOut.toByteArray();
          
          /* Step 2: PSO:Verify Certificate */
          service.sendPSOExtendedLengthMode(wrapper, body, signature);          
        } catch (CardServiceException cse) {
          throw cse;
        } catch (Exception e) {
          /* FIXME: Does this mean we failed to authenticate? -- MO */
          throw new CardServiceException(e.getMessage());
        }
      }
      
      if (terminalKey == null) {
        throw new CardServiceException("No terminal key");
      }
      
      /* Step 3: MSE Set AT */
      CVCPrincipal holderRef = terminalCert.getHolderReference();
      byte[] holderRefBytes = Util.wrapDO((byte) 0x83, holderRef.getName().getBytes("ISO-8859-1"));
      /* Manage Security Environment: Set for external authentication: Authentication Template */
      service.sendMSESetATExtAuth(wrapper, holderRefBytes);
      
      /* Step 4: send get challenge */
      byte[] rPICC = service.sendGetChallenge(wrapper);
      
      /* Step 5: external authenticate. */
      /* FIXME: idPICC should be public key in case of PACE. See BSI TR 03110 v2.03 4.4. */
      byte[] idPICC = new byte[documentNumber.length() + 1];
      System.arraycopy(documentNumber.getBytes("ISO-8859-1"), 0, idPICC, 0, documentNumber.length());
      idPICC[idPICC.length - 1] = (byte)MRZInfo.checkDigit(documentNumber);
      
      ByteArrayOutputStream dtbs = new ByteArrayOutputStream();
      dtbs.write(idPICC);
      dtbs.write(rPICC);
      dtbs.write(caKeyHash);
      dtbs.close();
      byte[] dtbsBytes = dtbs.toByteArray();
      
      String sigAlg = terminalCert.getSigAlgName();
      if (sigAlg == null) {
        throw new IllegalStateException("ERROR: Could not determine signature algorithm for terminal certificate " + terminalCert.getHolderReference().getName());
      }
      Signature sig = Signature.getInstance(sigAlg);
      sig.initSign(terminalKey);
      sig.update(dtbsBytes);
      byte[] signedData = sig.sign();
      if (sigAlg.toUpperCase().endsWith("ECDSA")) {
        int keySize = ((org.bouncycastle.jce.interfaces.ECPrivateKey)terminalKey).getParameters().getCurve().getFieldSize() / 8;
        signedData = Util.getRawECDSASignature(signedData, keySize);
      }
      service.sendMutualAuthenticate(wrapper, signedData);
      return new TAResult(chipAuthenticationResult, caReference, terminalCertificates, terminalKey, documentNumber, rPICC);
    } catch (CardServiceException cse) {
      throw cse;
    } catch (Exception e) {
      throw new CardServiceException(e.toString());
    }
  }
}
