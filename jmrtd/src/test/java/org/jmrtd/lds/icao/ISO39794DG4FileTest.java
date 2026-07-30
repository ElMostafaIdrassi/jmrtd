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

import org.jmrtd.lds.DG4FileTest;
import org.jmrtd.lds.iso39794.IrisImageDataBlock;
import org.junit.Test;

public class ISO39794DG4FileTest {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd.lds");

  @Test
  public void testLegacyDG4FixtureContainsTwoIrisRecords() {
    DG4File dg4File = DG4FileTest.getTestObject();
    assertEquals(2, dg4File.getIrisInfos().size());
  }

  @Test
  public void testISOSampleIrisImageDataBlock() {
    testIrisImageDataBlock("/lds/dg4/iso39794/sample-39794-6-ed-1-v1.der");
  }

  private void testIrisImageDataBlock(String resource) {
    try {
      InputStream inputStream = ISO39794DG4FileTest.class.getResourceAsStream(resource);
      assertNotNull(inputStream);
      IrisImageDataBlock dataBlock = new IrisImageDataBlock(inputStream);
      testDecodeEncode(dataBlock);
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception while testing " + resource, e);
      fail(e.getMessage());
    }
  }

  private void testDecodeEncode(IrisImageDataBlock irisImageDataBlock) {
    try {
      byte[] encoded = irisImageDataBlock.getEncoded();
      IrisImageDataBlock reconstructed = new IrisImageDataBlock(
          irisImageDataBlock.getStandardBiometricHeader(), new ByteArrayInputStream(encoded));
      assertEquals(irisImageDataBlock, reconstructed);

      byte[] reEncoded = reconstructed.getEncoded();
      assertEquals(encoded.length, reEncoded.length);
      assertTrue(Arrays.equals(encoded, reEncoded));
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }
}
