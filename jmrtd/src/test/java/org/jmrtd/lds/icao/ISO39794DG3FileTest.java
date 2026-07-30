package org.jmrtd.lds.icao;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jmrtd.lds.iso39794.FingerImageDataBlock;
import org.junit.Test;

public class ISO39794DG3FileTest {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd.lds");

  @Test
  public void testISOSampleFingerImageDataBlock() {
    testFingerImageDataBlock("/lds/dg3/iso39794/sample-39794-4-ed-1-v1.der");
  }

  private void testFingerImageDataBlock(String resource) {
    try {
      InputStream inputStream = ISO39794DG3FileTest.class.getResourceAsStream(resource);
      assertNotNull(inputStream);
      FingerImageDataBlock dataBlock = new FingerImageDataBlock(inputStream);
      testDecodeEncode(dataBlock);
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception while testing " + resource, e);
      fail(e.getMessage());
    }
  }

  private void testDecodeEncode(FingerImageDataBlock fingerImageDataBlock) {
    try {
      byte[] encoded = fingerImageDataBlock.getEncoded();
      FingerImageDataBlock reconstructed = new FingerImageDataBlock(
          fingerImageDataBlock.getStandardBiometricHeader(), new ByteArrayInputStream(encoded));
      assertEquals(fingerImageDataBlock, reconstructed);

      byte[] reEncoded = reconstructed.getEncoded();
      assertEquals(encoded.length, reEncoded.length);
      assertTrue(Arrays.equals(encoded, reEncoded));
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }
}
