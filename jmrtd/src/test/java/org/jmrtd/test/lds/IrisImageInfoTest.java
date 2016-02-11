package org.jmrtd.test.lds;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import javax.imageio.ImageIO;

import org.jmrtd.lds.IrisImageInfo;
import org.jmrtd.lds.IrisInfo;

import junit.framework.TestCase;

public class IrisImageInfoTest extends TestCase {
  
  public void testToString() {
    try {
      IrisImageInfo info = createTestObject();
      assertNotNull(info);
      String asString = info.toString();
      assertNotNull(asString);
      assertTrue(asString.startsWith("IrisImageInfo"));
    } catch (Exception e) {
      e.printStackTrace();
      fail(e.toString());
    }
  }
  
  public void testLength() {
    IrisImageInfo irisImageInfo = createTestObject();
    int imageLength = irisImageInfo.getImageLength();
    int recordLength = (int)irisImageInfo.getRecordLength();
    assertTrue(imageLength < recordLength);
  }
  
  public static IrisImageInfo createTestObject() {
    try {
      BufferedImage image = new BufferedImage(300, 200, BufferedImage.TYPE_BYTE_GRAY);
      ByteArrayOutputStream encodedImageOut = new ByteArrayOutputStream();
      ImageIO.write(image, "jpg", encodedImageOut);
      encodedImageOut.flush();
      byte[] imageBytes = encodedImageOut.toByteArray();
      IrisImageInfo irisImageInfo = new IrisImageInfo(1, image.getWidth(), image.getHeight(), new ByteArrayInputStream(imageBytes), imageBytes.length, IrisInfo.IMAGEFORMAT_MONO_JPEG);
      return irisImageInfo;
    } catch (IOException e) {
      e.printStackTrace();
      fail(e.getMessage());
      return null;
    }
  }
}
