/*
 * JMRTD - A Java API for accessing machine readable travel documents.
 *
 * Copyright (C) 2006 - 2026  The JMRTD team
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

package org.jmrtd.protocol;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jmrtd.APDULevelEACTACapable;
import org.jmrtd.cert.CVCAuthorizationTemplate;
import org.jmrtd.cert.CVCAuthorizationTemplate.Permission;
import org.jmrtd.cert.CVCAuthorizationTemplate.Role;
import org.jmrtd.cert.CVCPrincipal;
import org.jmrtd.cert.CVCertificateBuilder;
import org.jmrtd.cert.CardVerifiableCertificate;
import org.junit.BeforeClass;
import org.junit.Test;

import net.sf.scuba.smartcards.APDUWrapper;
import net.sf.scuba.smartcards.CardServiceException;

/**
 * Tests CVCA rollover chain handling in Terminal Authentication.
 */
public class EACTAProtocolTest {

  private static CVCPrincipal firstCVCA;
  private static CVCPrincipal secondCVCA;
  private static CVCPrincipal thirdCVCA;

  private static CardVerifiableCertificate firstCVCACertificate;
  private static CardVerifiableCertificate firstLinkCertificate;
  private static CardVerifiableCertificate secondLinkCertificate;
  private static CardVerifiableCertificate dvCertificate;
  private static CardVerifiableCertificate terminalCertificate;
  private static KeyPair terminalKeyPair;

  @BeforeClass
  public static void createCertificates() throws Exception {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }

    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(1024);
    Date validFrom = new SimpleDateFormat("yyyyMMdd").parse("20200101");
    Date validTo = new SimpleDateFormat("yyyyMMdd").parse("20301231");
    String algorithm = "SHA256withRSA";
    CVCAuthorizationTemplate cvcaTemplate = new CVCAuthorizationTemplate(
        Role.CVCA, Permission.READ_ACCESS_DG3_AND_DG4);
    CVCAuthorizationTemplate dvTemplate = new CVCAuthorizationTemplate(
        Role.DV_D, Permission.READ_ACCESS_DG3_AND_DG4);
    CVCAuthorizationTemplate isTemplate = new CVCAuthorizationTemplate(
        Role.IS, Permission.READ_ACCESS_DG3_AND_DG4);

    firstCVCA = new CVCPrincipal("UTCVCA00001");
    KeyPair firstCVCAKeyPair = keyPairGenerator.generateKeyPair();
    firstCVCACertificate = CVCertificateBuilder.createCertificate(
        firstCVCAKeyPair.getPublic(), firstCVCAKeyPair.getPrivate(),
        algorithm, firstCVCA, firstCVCA, cvcaTemplate,
        validFrom, validTo, "BC");

    secondCVCA = new CVCPrincipal("UTCVCA00002");
    KeyPair secondCVCAKeyPair = keyPairGenerator.generateKeyPair();
    firstLinkCertificate = CVCertificateBuilder.createCertificate(
        secondCVCAKeyPair.getPublic(), firstCVCAKeyPair.getPrivate(),
        algorithm, firstCVCA, secondCVCA, cvcaTemplate,
        validFrom, validTo, "BC");

    thirdCVCA = new CVCPrincipal("UTCVCA00003");
    KeyPair thirdCVCAKeyPair = keyPairGenerator.generateKeyPair();
    secondLinkCertificate = CVCertificateBuilder.createCertificate(
        thirdCVCAKeyPair.getPublic(), secondCVCAKeyPair.getPrivate(),
        algorithm, secondCVCA, thirdCVCA, cvcaTemplate,
        validFrom, validTo, "BC");

    CVCPrincipal dv = new CVCPrincipal("UTDV00001");
    KeyPair dvKeyPair = keyPairGenerator.generateKeyPair();
    dvCertificate = CVCertificateBuilder.createCertificate(
        dvKeyPair.getPublic(), thirdCVCAKeyPair.getPrivate(),
        algorithm, thirdCVCA, dv, dvTemplate,
        validFrom, validTo, "BC");

    CVCPrincipal terminal = new CVCPrincipal("UTIS00001");
    terminalKeyPair = keyPairGenerator.generateKeyPair();
    terminalCertificate = CVCertificateBuilder.createCertificate(
        terminalKeyPair.getPublic(), dvKeyPair.getPrivate(),
        algorithm, dv, terminal, isTemplate,
        validFrom, validTo, "BC");
  }

  @Test
  public void sendsDVAndTerminalCertificateForCurrentCVCA() throws Exception {
    assertCertificatesSent(
        thirdCVCA,
        Arrays.asList(dvCertificate, terminalCertificate),
        dvCertificate, terminalCertificate);
  }

  @Test
  public void sendsLeadingLinkCertificateForPreviousCVCA() throws Exception {
    assertCertificatesSent(
        secondCVCA,
        Arrays.asList(
            secondLinkCertificate, dvCertificate, terminalCertificate),
        secondLinkCertificate, dvCertificate, terminalCertificate);
  }

  @Test
  public void sendsMultipleLinkCertificatesForOlderCVCA() throws Exception {
    assertCertificatesSent(
        firstCVCA,
        Arrays.asList(
            firstLinkCertificate,
            secondLinkCertificate,
            dvCertificate,
            terminalCertificate),
        firstLinkCertificate,
        secondLinkCertificate,
        dvCertificate,
        terminalCertificate);
  }

  @Test
  public void omitsSelfSignedTrustAnchorWithoutMutatingInput() throws Exception {
    List<CardVerifiableCertificate> input =
        Collections.unmodifiableList(Arrays.asList(
            firstCVCACertificate,
            firstLinkCertificate,
            secondLinkCertificate,
            dvCertificate,
            terminalCertificate));

    RecordingEACTAService service = execute(firstCVCA, input);

    assertEquals(5, input.size());
    assertSentBodies(
        service,
        firstLinkCertificate,
        secondLinkCertificate,
        dvCertificate,
        terminalCertificate);
  }

  private static void assertCertificatesSent(
      CVCPrincipal caReference,
      List<CardVerifiableCertificate> certificates,
      CardVerifiableCertificate... expected) throws Exception {
    RecordingEACTAService service = execute(caReference, certificates);
    assertSentBodies(service, expected);
  }

  private static RecordingEACTAService execute(
      CVCPrincipal caReference,
      List<CardVerifiableCertificate> certificates) throws Exception {
    RecordingEACTAService service = new RecordingEACTAService();
    EACTAProtocol protocol = new EACTAProtocol(service, null);
    EACCAResult chipAuthenticationResult = new EACCAResult(
        null, null, new byte[] { 1, 2, 3, 4 }, null, null, null);

    EACTAResult result = protocol.doTA(
        caReference,
        certificates,
        terminalKeyPair.getPrivate(),
        null,
        chipAuthenticationResult,
        new byte[] { 5, 6, 7, 8 });

    assertEquals(caReference, result.getCAReference());
    assertEquals(service.certificateBodies.size(),
        result.getCVCertificates().size());
    return service;
  }

  private static void assertSentBodies(
      RecordingEACTAService service,
      CardVerifiableCertificate... expected) throws Exception {
    assertEquals(expected.length, service.certificateBodies.size());
    for (int i = 0; i < expected.length; i++) {
      assertArrayEquals(
          expected[i].getCertBodyData(),
          service.certificateBodies.get(i));
    }
  }

  private static final class RecordingEACTAService
      implements APDULevelEACTACapable {

    private final List<byte[]> certificateBodies =
        new ArrayList<byte[]>();

    @Override
    public void sendMSESetDST(APDUWrapper wrapper, byte[] data)
        throws CardServiceException {
      /* Nothing to do. */
    }

    @Override
    public void sendPSOExtendedLengthMode(
        APDUWrapper wrapper,
        byte[] certBodyData,
        byte[] certSignatureData) throws CardServiceException {
      certificateBodies.add(certBodyData.clone());
    }

    @Override
    public void sendMSESetATExtAuth(APDUWrapper wrapper, byte[] data)
        throws CardServiceException {
      /* Nothing to do. */
    }

    @Override
    public byte[] sendGetChallenge(APDUWrapper wrapper)
        throws CardServiceException {
      return new byte[8];
    }

    @Override
    public void sendMutualAuthenticate(
        APDUWrapper wrapper, byte[] signature)
        throws CardServiceException {
      /* Nothing to do. */
    }
  }
}
