package org.jmrtd.test.lds;

import java.math.BigInteger;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.logging.Logger;

import javax.crypto.spec.DHParameterSpec;

import org.jmrtd.Util;
import org.jmrtd.lds.PACEInfo;

import junit.framework.TestCase;

public class PACEInfoTest extends TestCase {

  private static final Provider BC_PROVIDER = Util.getBouncyCastleProvider();

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  //	PARAM_ID_GFP_1024_160 = 0,
  //	PARAM_ID_GFP_2048_224 = 1,
  //	PARAM_ID_GFP_2048_256 = 2,
  //	/* RFU 3 - 7 */
  //	PARAM_ID_ECP_NIST_P192_R1 = 8,
  //	PARAM_ID_ECP_BRAINPOOL_P192_R1 = 9,
  //	PARAM_ID_ECP_NIST_P224_R1 = 10,
  //	PARAM_ID_ECP_BRAINPOOL_P224_R1 = 11,
  //	PARAM_ID_ECP_NST_P256_R1 = 12,
  //	PARAM_ID_ECP_BRAINPOOL_P256_R1 = 13,
  //	PARAM_ID_ECP_BRAINPOOL_P320_R1 = 14,
  //	PARAM_ID_ECP_NIST_P384_R1 = 15,
  //	PARAM_ID_ECP_BRAINPOOL_P384_R1 = 16,
  //	PARAM_ID_ECP_BRAINPOOL_P512_R1 = 17,
  //	PARAM_ID_ECP_NIST_P512_R1 = 18;

  public void testPACEInfo() {
    PACEInfo paceInfo = new PACEInfo(PACEInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_256, 2, PACEInfo.PARAM_ID_ECP_NIST_P256_R1);
    
    assertEquals(PACEInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_256, paceInfo.getObjectIdentifier());
    assertEquals("id-PACE-ECDH-GM-AES-CBC-CMAC-256", paceInfo.getProtocolOIDString());
    assertEquals(PACEInfo.PARAM_ID_ECP_NIST_P256_R1, paceInfo.getParameterId().intValue()); // 12
    assertEquals(12, paceInfo.getParameterId().intValue()); // ID-ECP-NST-P256-R1
    assertEquals(2, paceInfo.getVersion());
    
    PACEInfo anotherPACEInfo = new PACEInfo(PACEInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_256, 2, PACEInfo.PARAM_ID_ECP_NIST_P256_R1);
    assertEquals(paceInfo.hashCode(), anotherPACEInfo.hashCode());
    assertEquals(paceInfo, anotherPACEInfo);
    assertEquals(paceInfo.toString(), anotherPACEInfo.toString());
  }
  
  public void testToParameterSpecNotNull() {

    //		Enumeration names = ECNamedCurveTable.getNames();
    //		while (names.hasMoreElements()) {
    //			LOGGER.info(names.nextElement());
    //		}

    testToParameterSpecNotNull(0);
    testToParameterSpecNotNull(1);
    testToParameterSpecNotNull(2);
    testToParameterSpecNotNull(8);
    testToParameterSpecNotNull(9);
    testToParameterSpecNotNull(10);
    testToParameterSpecNotNull(11);
    testToParameterSpecNotNull(12);
    testToParameterSpecNotNull(13);
    testToParameterSpecNotNull(14);
    testToParameterSpecNotNull(15);
    testToParameterSpecNotNull(16);
    testToParameterSpecNotNull(17);
    testToParameterSpecNotNull(18);
  }	

  public void testToParameterSpecNotNull(int stdDomainParams) {
    AlgorithmParameterSpec paramSpec = PACEInfo.toParameterSpec(BigInteger.valueOf(stdDomainParams));
    assertNotNull(paramSpec);
  }

  public void testToParameterSpecDHParameterSpecOrECParameterSpec() {

    //		Enumeration names = ECNamedCurveTable.getNames();
    //		while (names.hasMoreElements()) {
    //			LOGGER.info(names.nextElement());
    //		}

    testGetParameterSpecDHParameterSpecOrECParameterSpec(0);
    testGetParameterSpecDHParameterSpecOrECParameterSpec(1);
    testGetParameterSpecDHParameterSpecOrECParameterSpec(2);
    testGetParameterSpecDHParameterSpecOrECParameterSpec(8);
    testGetParameterSpecDHParameterSpecOrECParameterSpec(9);
    testGetParameterSpecDHParameterSpecOrECParameterSpec(10);
    testGetParameterSpecDHParameterSpecOrECParameterSpec(11);
    testGetParameterSpecDHParameterSpecOrECParameterSpec(12);
    testGetParameterSpecDHParameterSpecOrECParameterSpec(13);
    testGetParameterSpecDHParameterSpecOrECParameterSpec(14);
    testGetParameterSpecDHParameterSpecOrECParameterSpec(15);
    testGetParameterSpecDHParameterSpecOrECParameterSpec(16);
    testGetParameterSpecDHParameterSpecOrECParameterSpec(17);
    testGetParameterSpecDHParameterSpecOrECParameterSpec(18);
  }	

  public void testGetParameterSpecDHParameterSpecOrECParameterSpec(int stdDomainParams) {
    AlgorithmParameterSpec paramSpec = PACEInfo.toParameterSpec(BigInteger.valueOf(stdDomainParams));
    assertTrue(paramSpec instanceof DHParameterSpec || paramSpec instanceof ECParameterSpec);		
  }

  public void testECDHPrime() {
    AlgorithmParameterSpec paramSpec = PACEInfo.toParameterSpec(PACEInfo.PARAM_ID_ECP_NIST_P256_R1);
    LOGGER.info("DEBUG: paramSpec: " + paramSpec.getClass().getCanonicalName());
    assertTrue(paramSpec instanceof ECParameterSpec);
  }
}
