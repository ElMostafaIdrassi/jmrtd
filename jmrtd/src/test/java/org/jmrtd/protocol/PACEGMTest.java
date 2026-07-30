package org.jmrtd.protocol;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.logging.Logger;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.jmrtd.Util;
import org.jmrtd.lds.PACEInfo;
import org.jmrtd.protocol.PACEProtocol;
import org.junit.Test;

public class PACEGMTest {

  private static final Logger LOGGER = Logger.getLogger("");

  private static final byte[] ZERO_04_64 = {
      0x04,
      0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,
      0,0,0,0
  };

  private static final byte[] ZERO_32 =
    {
        0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,
        0,0
    };

  @Test
  public void testP() throws Exception {
    String oid = "0.4.0.127.0.7.2.2.4.2.1";

    KeyFactory k = KeyFactory.getInstance("EC");
    ECPublicKey p = (ECPublicKey)k.generatePublic(new ECPublicKeySpec(new ECPoint(BigInteger.ZERO, BigInteger.ZERO), Util.toECNamedCurveSpec(ECNamedCurveTable.getParameterSpec("secp256r1"))));
    byte[] encodedPublicKey = PACEProtocol.encodePublicKeyForSmartCard(p);
    SecretKeyFactory skf = SecretKeyFactory.getInstance("DESede");
    int keyLength = PACEInfo.toKeyLength(oid);

    SecretKey macKey = Util.deriveKey(ZERO_32, "DESede", keyLength, Util.MAC_MODE);
    byte[] token = PACEProtocol.generateAuthenticationToken("0.4.0.127.0.7.2.2.4.2.1", macKey, p);
  }
}
