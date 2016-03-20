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
 * $Id:PassportService.java 352 2008-05-19 06:55:21Z martijno $
 */

package org.jmrtd;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;
import java.text.SimpleDateFormat;
import java.util.List;
import java.util.logging.Logger;

import javax.crypto.SecretKey;

import org.jmrtd.cert.CVCPrincipal;
import org.jmrtd.cert.CardVerifiableCertificate;
import org.jmrtd.protocol.AAProtocol;
import org.jmrtd.protocol.AAResult;
import org.jmrtd.protocol.BACProtocol;
import org.jmrtd.protocol.BACResult;
import org.jmrtd.protocol.CAProtocol;
import org.jmrtd.protocol.CAResult;
import org.jmrtd.protocol.PACEProtocol;
import org.jmrtd.protocol.PACEResult;
import org.jmrtd.protocol.TAProtocol;
import org.jmrtd.protocol.TAResult;

import net.sf.scuba.smartcards.APDUWrapper;
import net.sf.scuba.smartcards.CardFileInputStream;
import net.sf.scuba.smartcards.CardService;
import net.sf.scuba.smartcards.CardServiceException;

/**
 * Card service for reading files (such as data groups) and using the BAC and AA
 * protocols on the passport. Defines secure messaging. Defines active
 * authentication.
 *
 * Based on Doc 9303.
 * Originally based on ICAO-TR-PKI and ICAO-TR-LDS.
 *
 * Usage:
 *
 * <pre>
 *        open() ==&gt;&lt;br /&gt;
 *        sendSelectApplet() ==&gt;&lt;br /&gt;
 *        doBAC(...) ==&gt;&lt;br /&gt;
 *        doAA() ==&gt;&lt;br /&gt;
 *        getInputStream(...)&lt;sup&gt;*&lt;/sup&gt; ==&gt;&lt;br /&gt;
 *        close()
 * </pre>
 *
 * @author Cees-Bart Breunesse (ceesb@cs.ru.nl)
 * @author Wojciech Mostowski (woj@cs.ru.nl)
 * @author Martijn Oostdijk (martijn.oostdijk@gmail.com)
 *
 * @version $Revision:352 $
 */
public class PassportService extends PassportApduService implements Serializable {
  
  private static final long serialVersionUID = 1751933705552226972L;
  
  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");
  
  /** Data group 1 contains the MRZ. */
  public static final short EF_DG1 = 0x0101;
  
  /** Data group 2 contains face image data. */
  public static final short EF_DG2 = 0x0102;
  
  /** Data group 3 contains finger print data. */
  public static final short EF_DG3 = 0x0103;
  
  /** Data group 4 contains iris data. */
  public static final short EF_DG4 = 0x0104;
  
  /** Data group 5 contains displayed portrait. */
  public static final short EF_DG5 = 0x0105;
  
  /** Data group 6 is RFU. */
  public static final short EF_DG6 = 0x0106;
  
  /** Data group 7 contains displayed signature. */
  public static final short EF_DG7 = 0x0107;
  
  /** Data group 8 contains data features. */
  public static final short EF_DG8 = 0x0108;
  
  /** Data group 9 contains structure features. */
  public static final short EF_DG9 = 0x0109;
  
  /** Data group 10 contains substance features. */
  public static final short EF_DG10 = 0x010A;
  
  /** Data group 11 contains additional personal details. */
  public static final short EF_DG11 = 0x010B;
  
  /** Data group 12 contains additional document details. */
  public static final short EF_DG12 = 0x010C;
  
  /** Data group 13 contains optional details. */
  public static final short EF_DG13 = 0x010D;
  
  /** Data group 14 contains security infos. */
  public static final short EF_DG14 = 0x010E;
  
  /** Data group 15 contains the public key used for Active Authentication. */
  public static final short EF_DG15 = 0x010F;
  
  /** Data group 16 contains person(s) to notify. */
  public static final short EF_DG16 = 0x0110;
  
  /** Card Access. */
  public static final short EF_CARD_ACCESS = 0x011C;
  
  /** Card Security. */
  public static final short EF_CARD_SECURITY = 0x011D;
  
  /** The security document. */
  public static final short EF_SOD = 0x011D;
  
  /** The data group presence list. */
  public static final short EF_COM = 0x011E;
  
  /**
   * File with the EAC CVCA references. Note: this can be overridden by a file
   * identifier in the DG14 file (TerminalAuthenticationInfo). So check that
   * one first. Also, this file does not have a header tag, like the others.
   */
  public static final short EF_CVCA = 0x011C;
  
  /** Short file identifiers for the DGs */
  public static final byte
  SF_DG1 = 0x01,
  SF_DG2 = 0x02,
  SF_DG3 = 0x03,
  SF_DG4 = 0x04,
  SF_DG5 = 0x05,
  SF_DG6 = 0x06,
  SF_DG7 = 0x07,
  SF_DG8 = 0x08,
  SF_DG9 = 0x09,
  SF_DG10 = 0x0A,
  SF_DG11 = 0x0B,
  SF_DG12 = 0x0C,
  SF_DG13 = 0x0D,
  SF_DG14 = 0x0E,
  SF_DG15 = 0x0F,
  SF_DG16 = 0x10,
  SF_COM = 0x1E,
  SF_SOD = 0x1D,
  SF_CVCA = 0x1C;
  
  /** YYMMDD format. */
  public static final SimpleDateFormat SDF = new SimpleDateFormat("yyMMdd");
  
  /** The default maximal blocksize used for unencrypted APDUs. */
  public static final int DEFAULT_MAX_BLOCKSIZE = 224;
  
  private static final Provider BC_PROVIDER = JMRTDSecurityProvider.getBouncyCastleProvider();
  
  private static final int SESSION_STOPPED_STATE = 0;
  
  private static final int SESSION_STARTED_STATE = 1;
  
  /*
   * TODO: this should be bit masks, e.g. AA and EAC should be settable both at the same time
   * Better yet, distinguish between access control (BAC, PACE, TA) and verification (AA, CA)
   * should probably not be part of this state machine at all.
   */
  private static final int BAC_AUTHENTICATED_STATE = 2;
  
  //	private static final int AA_AUTHENTICATED_STATE = 3;
  
  private static final int CA_AUTHENTICATED_STATE = 4;
  
  private static final int TA_AUTHENTICATED_STATE = 5;
  
  /**
   * The file read block size, some passports cannot handle large values
   *
   * @deprecated hack
   */
  public int maxBlockSize;
  
  private int state;
  
  /**
   * @deprecated visibility will be set to private
   */
  protected SecureMessagingWrapper wrapper;
  
  private MRTDFileSystem fs;
  
  /**
   * Creates a new passport service for accessing the passport.
   *
   * @param service another service which will deal with sending the apdus to the card
   *
   * @throws CardServiceException
   *             when the available JCE providers cannot provide the necessary
   *             cryptographic primitives:
   *             <ul>
   *                 <li>Cipher: "DESede/CBC/Nopadding"</li>
   *                 <li>Mac: "ISO9797Alg3Mac"</li>
   *             </ul>
   */
  public PassportService(CardService service) throws CardServiceException {
    this(service, DEFAULT_MAX_BLOCKSIZE);
  }
  
  /**
   * Creates a new passport service for accessing the passport.
   *
   * @param service another service which will deal with sending the APDUs to the card
   * @param maxBlockSize maximum size for plain text APDUs
   *
   * @throws CardServiceException
   *             when the available JCE providers cannot provide the necessary
   *             cryptographic primitives:
   *             <ul>
   *                 <li>Cipher: "DESede/CBC/Nopadding"</li>
   *                 <li>Mac: "ISO9797Alg3Mac"</li>
   *             </ul>
   */
  public PassportService(CardService service, int maxBlockSize) throws CardServiceException {
    super(service);
    this.maxBlockSize = maxBlockSize;
    fs = new MRTDFileSystem(this);
    
    state = SESSION_STOPPED_STATE;
    LOGGER.info("DEBUG: isExtendedAPDULengthSupported: " + isExtendedAPDULengthSupported());
  }
  
  /**
   * Opens a session to the card. As of 0.4.10 this no longer auto selects the passport application,
   * caller is responsible to call #sendSelectApplet(boolean) now.
   *
   * @throws CardServiceException on error
   */
  public void open() throws CardServiceException {
    if (isOpen()) {
      return;
    }
    synchronized(this) {
      super.open();
      state = SESSION_STARTED_STATE;
    }
  }
  
  /**
   * Selects the MRTD card side applet. If PACE has been executed successfully previously, then the card has authenticated
   * us and a secure messaging channel has been established. If not, then the caller should request BAC execution as a next
   * step.
   *
   * @param hasPACESucceeded indicates whether PACE has been executed successfully (in which case a secure messaging channel has been established)
   *
   * @throws CardServiceException on error
   */
  public void sendSelectApplet(boolean hasPACESucceeded) throws CardServiceException {
    if (hasPACESucceeded) {
      /* Use SM as set up by doPACE() */
      LOGGER.info("DEBUG: wrapper = " + wrapper);
      sendSelectApplet(wrapper, APPLET_AID);
    } else {
      /* Use plain messaging to select the applet, caller will have to do doBAC. */
      sendSelectApplet(null, APPLET_AID);
    }
  }
  
  /**
   * Whether this service is open.
   *
   * @return a boolean
   */
  public boolean isOpen() {
    return (state != SESSION_STOPPED_STATE);
  }
  
  /**
   * Selects a file.
   *
   * @param fid a file identifier
   */
  public synchronized void sendSelectFile(short fid) throws CardServiceException {
    sendSelectFile(wrapper, fid);
  }
  
  /**
   * Sends a <code>READ BINARY</code> command to the passport, use wrapper when secure channel set up.
   *
   * @param offset offset into the file
   * @param le the expected length of the file to read
   * @param longRead whether to use extended length APDUs
   *
   * @return a byte array of length <code>le</code> with (the specified part of) the contents of the currently selected file
   *
   * @throws CardServiceException on tranceive error
   */
  public synchronized byte[] sendReadBinary(int offset, int le, boolean longRead) throws CardServiceException {
    return sendReadBinary(wrapper, offset, le, longRead);
  }
  
  /**
   * Performs the <i>Basic Access Control</i> protocol.
   *
   * @param bacKey the key based on the document number,
   *               the card holder's birth date,
   *               and the document's expiry date
   *
   * @throws CardServiceException if authentication failed
   */
  public synchronized void doBAC(BACKeySpec bacKey) throws CardServiceException {
    BACResult bacResult = (new BACProtocol(this)).doBAC(bacKey);
    wrapper = bacResult.getWrapper();
    state = BAC_AUTHENTICATED_STATE;
  }
  
  /**
   * Performs the <i>Basic Access Control</i> protocol.
   * It does BAC using kEnc and kMac keys, usually calculated
   * from the document number, the card holder's date of birth,
   * and the card's date of expiry.
   *
   * @param kEnc static 3DES key required for BAC
   * @param kMac static 3DES key required for BAC
   *
   * @throws CardServiceException if authentication failed
   * @throws GeneralSecurityException on security primitives related problems
   */
  public synchronized void doBAC(SecretKey kEnc, SecretKey kMac) throws CardServiceException, GeneralSecurityException {
    BACResult bacResult = (new BACProtocol(this)).doBAC(kEnc, kMac);
    wrapper = bacResult.getWrapper();
    state = BAC_AUTHENTICATED_STATE;
  }
  
  /**
   * Performs the PACE 2.0 / SAC protocol.
   *
   * @param keySpec the MRZ
   * @param oid as specified in the PACEInfo, indicates GM or IM or CAM, DH or ECDH, cipher, digest, length
   * @param params explicit static domain parameters the domain params for DH or ECDH
   *
   * @throws PACEException on error
   */
  public synchronized void doPACE(KeySpec keySpec, String oid,  AlgorithmParameterSpec params) throws PACEException {
    PACEResult paceResult = (new PACEProtocol(this, wrapper)).doPACE(keySpec, oid, params);
    wrapper = paceResult.getWrapper();
  }
  
  /**
   * Perform CA (Chip Authentication) part of EAC (version 1). For details see TR-03110
   * ver. 1.11. In short, we authenticate the chip with (EC)DH key agreement
   * protocol and create new secure messaging keys.
   *
   * @param keyId passport's public key id (stored in DG14), -1 if none
   * @param publicKey passport's public key (stored in DG14)
   *
   * @return the chip authentication result
   *
   * @throws CardServiceException if CA failed or some error occurred
   */
  public synchronized CAResult doCA(BigInteger keyId, PublicKey publicKey) throws CardServiceException {
    CAResult caResult = (new CAProtocol(this, wrapper)).doCA(keyId, publicKey);
    wrapper = caResult.getWrapper();
    state = CA_AUTHENTICATED_STATE;
    return caResult;
  }
  
  /* From BSI-03110 v1.1, B.2:
   *
   * <pre>
   * The following sequence of commands SHALL be used to implement Terminal Authentication:
   * 	1. MSE:Set DST
   * 	2. PSO:Verify Certificate
   * 	3. MSE:Set AT
   * 	4. Get Challenge
   * 	5. External Authenticate
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
    TAResult taResult = (new TAProtocol(this, wrapper)).doTA(caReference, terminalCertificates, terminalKey, taAlg, chipAuthenticationResult, documentNumber);
    state = TA_AUTHENTICATED_STATE;
    return taResult;
  }
  
  /**
   * Performs the <i>Active Authentication</i> protocol.
   *
   * @param publicKey the public key to use (usually read from the card)
   * @param digestAlgorithm the digest algorithm to use, or null
   * @param signatureAlgorithm signature algorithm
   * @param challenge challenge
   *
   * @return a boolean indicating whether the card was authenticated
   *
   * @throws CardServiceException on error
   */
  public byte[] doAA(PublicKey publicKey, String digestAlgorithm, String signatureAlgorithm, byte[] challenge) throws CardServiceException {
    AAResult aaResult = (new AAProtocol(this, wrapper)).doAA(publicKey, digestAlgorithm, signatureAlgorithm, challenge);
    return aaResult.getResponse();
  }
  
  /**
   * Closes this service.
   */
  public void close() {
    try {
      wrapper = null;
      super.close();
    } finally {
      state = SESSION_STOPPED_STATE;
    }
  }
  
  /**
   * Gets the wrapper. Returns <code>null</code> until BAC has been
   * performed.
   *
   * @return the wrapper
   */
  public APDUWrapper getWrapper() {
    return wrapper;
  }
  
  /**
   * @deprecated hack
   *
   * @param wrapper wrapper
   */
  public void setWrapper(SecureMessagingWrapper wrapper) {
    this.wrapper = wrapper;
  }
  
  /**
   * Gets the file as an input stream indicated by a file identifier.
   * The resulting input stream will send APDUs to the card.
   *
   * @param fid ICAO file identifier
   *
   * @return the file as an input stream
   *
   * @throws CardServiceException if the file cannot be read
   */
  public synchronized CardFileInputStream getInputStream(short fid) throws CardServiceException {
    synchronized(fs) {
      fs.selectFile(fid);
      return new CardFileInputStream(maxBlockSize, fs);
    }
  }
}
