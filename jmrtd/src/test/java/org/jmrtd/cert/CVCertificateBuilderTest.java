/*
 * JMRTD - A Java API for accessing machine readable travel documents.
 *
 * Copyright (C) 2006 - 2026  The JMRTD team
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
 */

package org.jmrtd.cert;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Date;

import org.jmrtd.Util;
import org.jmrtd.cert.CVCAuthorizationTemplate;
import org.jmrtd.cert.CVCAuthorizationTemplate.Permission;
import org.jmrtd.cert.CVCAuthorizationTemplate.Role;
import org.jmrtd.cert.CVCPrincipal;
import org.jmrtd.cert.CVCertificateBuilder;
import org.jmrtd.cert.CardVerifiableCertificate;
import org.junit.BeforeClass;
import org.junit.Test;

public class CVCertificateBuilderTest {

  @BeforeClass
  public static void setUp() {
    Security.addProvider(Util.getBouncyCastleProvider());
  }

  @Test
  public void testCreateCertificateSuccess() throws Exception {
    KeyPairGenerator rsaGenerator = KeyPairGenerator.getInstance("RSA");
    rsaGenerator.initialize(1024);
    KeyPair keyPair = rsaGenerator.generateKeyPair();
    PublicKey publicKey = keyPair.getPublic();
    PrivateKey privateKey = keyPair.getPrivate();

    CVCPrincipal caRef = new CVCPrincipal("NLDVCS00001");
    CVCPrincipal holderRef = new CVCPrincipal("NLIS00001");

    CVCAuthorizationTemplate authZTemplate = new CVCAuthorizationTemplate(Role.IS, Permission.READ_ACCESS_DG3_AND_DG4);

    Date validFrom = new Date(System.currentTimeMillis() - 10000);
    Date validTo = new Date(System.currentTimeMillis() + 10000);

    CardVerifiableCertificate cert = CVCertificateBuilder.createCertificate(
        publicKey,
        privateKey,
        "SHA256WithRSA",
        caRef,
        holderRef,
        authZTemplate,
        validFrom,
        validTo,
        Util.getBouncyCastleProvider().getName()
    );

    assertNotNull(cert);
    assertEquals(caRef, cert.getAuthorityReference());
    assertEquals(holderRef, cert.getHolderReference());
    assertEquals(publicKey, cert.getPublicKey());
    assertEquals("SHA256withRSA".toUpperCase(), cert.getSigAlgName().toUpperCase());
    assertEquals(authZTemplate, cert.getAuthorizationTemplate());
  }

  @Test
  public void testRoleAndAccessRightMapping() throws Exception {
    KeyPairGenerator rsaGenerator = KeyPairGenerator.getInstance("RSA");
    rsaGenerator.initialize(1024);
    KeyPair keyPair = rsaGenerator.generateKeyPair();
    PublicKey publicKey = keyPair.getPublic();
    PrivateKey privateKey = keyPair.getPrivate();

    CVCPrincipal caRef = new CVCPrincipal("NLDVCS00001");
    CVCPrincipal holderRef = new CVCPrincipal("NLIS00001");
    Date validFrom = new Date();
    Date validTo = new Date();

    // Verify all Role and Permission enum combinations translate and generate successfully without exception
    for (Role role : Role.values()) {
      for (Permission permission : Permission.values()) {
        CVCAuthorizationTemplate template = new CVCAuthorizationTemplate(role, permission);
        CardVerifiableCertificate cert = CVCertificateBuilder.createCertificate(
            publicKey,
            privateKey,
            "SHA256WithRSA",
            caRef,
            holderRef,
            template,
            validFrom,
            validTo,
            Util.getBouncyCastleProvider().getName()
        );
        assertNotNull(cert);
        assertEquals(role, cert.getAuthorizationTemplate().getRole());
        assertEquals(permission, cert.getAuthorizationTemplate().getAccessRight());
      }
    }
  }
}
