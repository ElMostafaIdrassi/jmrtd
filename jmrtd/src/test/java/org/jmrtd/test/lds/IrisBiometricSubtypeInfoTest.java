package org.jmrtd.test.lds;

import java.util.Arrays;
import java.util.List;

import org.jmrtd.lds.iso19794.IrisBiometricSubtypeInfo;
import org.jmrtd.lds.iso19794.IrisImageInfo;
import org.jmrtd.lds.iso19794.IrisInfo;

import junit.framework.TestCase;

public class IrisBiometricSubtypeInfoTest extends TestCase {
  
  public void testCreate() {
    IrisBiometricSubtypeInfo irisSubtypeInfo = createTestObject();
    int subtypeId = irisSubtypeInfo.getBiometricSubtype();
    assertTrue(subtypeId == IrisBiometricSubtypeInfo.EYE_LEFT
        || subtypeId == IrisBiometricSubtypeInfo.EYE_RIGHT
        || subtypeId == IrisBiometricSubtypeInfo.EYE_UNDEF);
    int imageFormat = irisSubtypeInfo.getImageFormat();
    assertTrue(imageFormat >= 0);
  }
  
  public void testToString() {
    try {
      IrisBiometricSubtypeInfo info = createTestObject();
      assertNotNull(info);
      String asString = info.toString();
      assertNotNull(asString);
      assertTrue(asString.startsWith("IrisBiometricSubtypeInfo"));
    } catch (Exception e) {
      e.printStackTrace();
      fail(e.toString());
    }
  }
  
  public static IrisBiometricSubtypeInfo createTestObject() {
    IrisImageInfo irisImageInfo = IrisImageInfoTest.createTestObject();
    List<IrisImageInfo> irisImageInfos = Arrays.asList(new IrisImageInfo[] { irisImageInfo });
    IrisBiometricSubtypeInfo irisSubtypeInfo = new IrisBiometricSubtypeInfo(IrisBiometricSubtypeInfo.EYE_LEFT, IrisInfo.IMAGEFORMAT_MONO_JPEG, irisImageInfos);
    return irisSubtypeInfo;
  }
  
}
