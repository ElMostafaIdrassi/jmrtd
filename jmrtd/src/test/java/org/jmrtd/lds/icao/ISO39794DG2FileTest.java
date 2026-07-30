package org.jmrtd.lds.icao;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.imageio.ImageIO;

import org.jmrtd.cbeff.BiometricDataBlock;
import org.jmrtd.cbeff.BiometricEncodingType;
import org.jmrtd.cbeff.StandardBiometricHeader;
import org.jmrtd.lds.LDSFileUtil;
import org.jmrtd.lds.iso19794.FaceInfo;
import org.jmrtd.lds.iso39794.CoordinateCartesian2DUnsignedShortBlock;
import org.jmrtd.lds.iso39794.DateTimeBlock;
import org.jmrtd.lds.iso39794.ExtendedDataBlock;
import org.jmrtd.lds.iso39794.FaceImageCaptureDevice2DBlock;
import org.jmrtd.lds.iso39794.FaceImageCaptureDevice2DBlock.CaptureDeviceTechnologyId2DCode;
import org.jmrtd.lds.iso39794.FaceImageCaptureDeviceBlock;
import org.jmrtd.lds.iso39794.FaceImageCaptureDeviceSpectral2DBlock;
import org.jmrtd.lds.iso39794.FaceImageDataBlock;
import org.jmrtd.lds.iso39794.FaceImageExpressionBlock;
import org.jmrtd.lds.iso39794.FaceImageIdentityMetadataBlock;
import org.jmrtd.lds.iso39794.FaceImageIdentityMetadataBlock.EyeColourCode;
import org.jmrtd.lds.iso39794.FaceImageIdentityMetadataBlock.GenderCode;
import org.jmrtd.lds.iso39794.FaceImageIdentityMetadataBlock.HairColourCode;
import org.jmrtd.lds.iso39794.FaceImageInformation2DBlock;
import org.jmrtd.lds.iso39794.FaceImageInformation2DBlock.FaceImageKind2DCode;
import org.jmrtd.lds.iso39794.FaceImageInformation2DBlock.ImageColourSpaceCode;
import org.jmrtd.lds.iso39794.FaceImageInformation2DBlock.ImageDataFormatCode;
import org.jmrtd.lds.iso39794.FaceImageInformation2DBlock.ImageFaceMeasurementsBlock;
import org.jmrtd.lds.iso39794.FaceImageInformation2DBlock.ImageSizeBlock;
import org.jmrtd.lds.iso39794.FaceImageInformation2DBlock.LossyTransformationAttemptsCode;
import org.jmrtd.lds.iso39794.FaceImageLandmarkBlock;
import org.jmrtd.lds.iso39794.FaceImageLandmarkKind;
import org.jmrtd.lds.iso39794.FaceImagePoseAngleBlock;
import org.jmrtd.lds.iso39794.FaceImagePoseAngleBlock.AngleDataBlock;
import org.jmrtd.lds.iso39794.FaceImagePostAcquisitionProcessingBlock;
import org.jmrtd.lds.iso39794.FaceImagePropertiesBlock;
import org.jmrtd.lds.iso39794.FaceImageReferenceColourMappingBlock;
import org.jmrtd.lds.iso39794.FaceImageRepresentation2DBlock;
import org.jmrtd.lds.iso39794.FaceImageRepresentationBlock;
import org.jmrtd.lds.iso39794.PADDataBlock;
import org.jmrtd.lds.iso39794.PADDataBlock.PADCaptureContextCode;
import org.jmrtd.lds.iso39794.PADDataBlock.PADCriteriaCategoryCode;
import org.jmrtd.lds.iso39794.PADDataBlock.PADDecisionCode;
import org.jmrtd.lds.iso39794.PADDataBlock.PADSupervisionLevelCode;
import org.jmrtd.lds.iso39794.PADScoreBlock;
import org.jmrtd.lds.iso39794.QualityBlock;
import org.jmrtd.lds.iso39794.RegistryIdBlock;
import org.jmrtd.lds.iso39794.VersionBlock;
import org.junit.Test;

public class ISO39794DG2FileTest {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd.lds");




  @Test
  public void testReconstructSilverMandatoryDataset() throws Exception {
    VersionBlock versionBlock = new VersionBlock(3, 2019);

    BigInteger representationId = BigInteger.ZERO;

    byte[] representationData2DBytes = readResource("/dg2/silver.jp2");

    ImageSizeBlock imageSizeBlock = null;

    ImageDataFormatCode imageDataFormat = ImageDataFormatCode.JPEG2000_LOSSY;
    FaceImageInformation2DBlock imageInformation2DBlock = new FaceImageInformation2DBlock(imageDataFormat,
        null, null, null, null, null, null, imageSizeBlock, null, null, null);
    FaceImageCaptureDevice2DBlock captureDevice2DBlock = null;
    FaceImageRepresentation2DBlock imageRepresentation2DBlock = new FaceImageRepresentation2DBlock(representationData2DBytes, imageInformation2DBlock, captureDevice2DBlock);

    DateTimeBlock captureDateTimeBlock = null;
    List<QualityBlock> qualityBlocks = null;
    List<PADDataBlock> padDataBlocks = null;
    BigInteger faceImageRepresenationBlockSessionId = null;
    BigInteger derivedFrom = null;
    FaceImageCaptureDeviceBlock captureDeviceBlock = null;
    FaceImageIdentityMetadataBlock identityMetadataBlock = null;
    List<FaceImageLandmarkBlock> landmarkBlocks = null;

    FaceImageRepresentationBlock faceImageRepresentationBlock = new FaceImageRepresentationBlock(representationId,
        imageRepresentation2DBlock, captureDateTimeBlock,
        qualityBlocks, padDataBlocks, faceImageRepresenationBlockSessionId, derivedFrom,
        captureDeviceBlock, identityMetadataBlock, landmarkBlocks);

    List<FaceImageRepresentationBlock> representationBlocks = Collections.singletonList(faceImageRepresentationBlock);

    Map<Integer, byte[]> sbhMap = new HashMap<Integer, byte[]>();
    sbhMap.put(0x87, new byte[] { 0x01, 0x01 });
    sbhMap.put(0x88, new byte[] { 0x00, 0x2A });
    StandardBiometricHeader sbh = new StandardBiometricHeader(sbhMap);
    FaceImageDataBlock faceImageDataBlock = new FaceImageDataBlock(versionBlock, representationBlocks, sbh);

    DG2File dg2File = DG2File.createISO39794DG2File(Collections.singletonList(faceImageDataBlock));
    assertNotNull(dg2File);

    DG2File reEncodedDG2File = LDSFileUtil.getDG2File(new ByteArrayInputStream(dg2File.getEncoded()));
    assertNotNull(reEncodedDG2File);

    FaceImageDataBlock a = (FaceImageDataBlock)dg2File.getSubRecords().get(0);
    FaceImageDataBlock b = (FaceImageDataBlock)reEncodedDG2File.getSubRecords().get(0);

    // FileOutputStream fOut = new FileOutputStream("silver_mandatory.bin");
    // fOut.write(dg2File.getEncoded());
    // fOut.flush();
    // fOut.close();
    // Thread.sleep(500);
  }

  @Test
  public void testReconstructSilverAllDataset() throws Exception {
    VersionBlock versionBlock = new VersionBlock(3, 2019);

    BigInteger representationId = BigInteger.ZERO;

    byte[] representationData2DBytes = readResource("/dg2/silver.jp2");

    ImageSizeBlock imageSizeBlock = new ImageSizeBlock(572, 731);

    ImageDataFormatCode imageDataFormat = ImageDataFormatCode.JPEG2000_LOSSY;

    FaceImageKind2DCode faceImageKind2DCode = FaceImageKind2DCode.MRTD;

    FaceImagePostAcquisitionProcessingBlock postAcquisitionProcessingBlock = new FaceImagePostAcquisitionProcessingBlock(
        false, false, false, false, false, false, false, false, false, false, false, false);
    LossyTransformationAttemptsCode lossyTransformationAttemptsCode = LossyTransformationAttemptsCode.ZERO;
    int cameraToSubjectDistance = 3000;
    int sensorDiagonal = 43;
    Integer lensFocalLength = 55;
    ImageFaceMeasurementsBlock imageFaceMeasurementsBlock = new ImageFaceMeasurementsBlock(
        BigInteger.valueOf(300), BigInteger.valueOf(150), BigInteger.valueOf(180), BigInteger.valueOf(500));
    ImageColourSpaceCode imageColourSpaceCode = ImageColourSpaceCode.RGB_24BIT;

    FaceImageReferenceColourMappingBlock referenceColourMappingBlock = new FaceImageReferenceColourMappingBlock(
        "Reference Colour Schema Example".getBytes("UTF-8"),
        Collections.singletonList(new FaceImageReferenceColourMappingBlock.ReferenceColourDefinitionAndValueBlock(
            "Reference Colour Definition Example".getBytes("UTF-8"),
            "Reference Colour Value Example".getBytes("UTF-8"))));
    FaceImageInformation2DBlock imageInformation2DBlock = new FaceImageInformation2DBlock(imageDataFormat, faceImageKind2DCode,
        postAcquisitionProcessingBlock, lossyTransformationAttemptsCode, cameraToSubjectDistance, sensorDiagonal, lensFocalLength,
        imageSizeBlock, imageFaceMeasurementsBlock, imageColourSpaceCode, referenceColourMappingBlock);

    FaceImageCaptureDevice2DBlock captureDevice2DBlock = new FaceImageCaptureDevice2DBlock(
        new FaceImageCaptureDeviceSpectral2DBlock(false, false, false),
        CaptureDeviceTechnologyId2DCode.STATIC_PHOTOGRAPH_FROM_DIGITAL_STILL_IMAGE_CAMERA);
    FaceImageRepresentation2DBlock imageRepresentation2DBlock = new FaceImageRepresentation2DBlock(representationData2DBytes, imageInformation2DBlock, captureDevice2DBlock);

    DateTimeBlock captureDateTimeBlock = new DateTimeBlock(2024, 1, 20, 13, 23, 9, 908);
    QualityBlock qualityBlock = new QualityBlock(new RegistryIdBlock(1, 1), 99);
    PADDataBlock padDataBlock = new PADDataBlock(
        PADDecisionCode.NO_ATTACK,
        Collections.singletonList(new PADScoreBlock(new RegistryIdBlock(1, 1), 99)),
        Collections.singletonList(new ExtendedDataBlock(new RegistryIdBlock(1, 1), "ExtendedDataBlock data".getBytes("UTF-8"))),
        PADCaptureContextCode.ENROLMENT,
        PADSupervisionLevelCode.UNKNOWN,
        5,
        PADCriteriaCategoryCode.COMMON,
        "PAD Parameter".getBytes("UTF-8"),
        Collections.singletonList("Challenge1".getBytes("UTF-8")),
        new DateTimeBlock(2024, 1, 22, 15, 16, 17, 18));
    BigInteger faceImageRepresenationBlockSessionId = BigInteger.valueOf(9);
    BigInteger derivedFrom = BigInteger.valueOf(0);
    FaceImageCaptureDeviceBlock captureDeviceBlock = new FaceImageCaptureDeviceBlock(new RegistryIdBlock(1,  1), Collections.singletonList(new RegistryIdBlock(2, 2)));
    FaceImageIdentityMetadataBlock identityMetadataBlock = new FaceImageIdentityMetadataBlock(GenderCode.FEMALE, EyeColourCode.BLUE, HairColourCode.BROWN, 1786,
        new FaceImagePropertiesBlock(false, false, false, false, false, false, false, false, false, false, false),
        new FaceImageExpressionBlock(true, false, false, false, false, false),
        new FaceImagePoseAngleBlock(new AngleDataBlock(2, 1), new AngleDataBlock(3, 1), new AngleDataBlock(1, 2)));
    FaceImageLandmarkBlock landmarkBlock = new FaceImageLandmarkBlock(
        FaceImageLandmarkKind.MPEGFeaturePointCode.MPEG4_POINT_CODE_02_11,
        new CoordinateCartesian2DUnsignedShortBlock(90, 22));

    FaceImageRepresentationBlock faceImageRepresentationBlock = new FaceImageRepresentationBlock(representationId,
        imageRepresentation2DBlock, captureDateTimeBlock,
        Collections.singletonList(qualityBlock), Collections.singletonList(padDataBlock), faceImageRepresenationBlockSessionId, derivedFrom,
        captureDeviceBlock, identityMetadataBlock, Collections.singletonList(landmarkBlock));

    List<FaceImageRepresentationBlock> representationBlocks = Collections.singletonList(faceImageRepresentationBlock);

    Map<Integer, byte[]> sbhMap = new HashMap<Integer, byte[]>();
    sbhMap.put(0x80, new byte[] { 0x01, 0x01 });
    sbhMap.put(0x81, new byte[] { 0x02 });
    sbhMap.put(0x82, new byte[] { 0x00 });
    sbhMap.put(0x83, new byte[] { 0x21, 0x24, 0x01, 0x05, 0x11, 0x23, 0x45 });
    sbhMap.put(0x85, new byte[] { 0x21, 0x24, 0x01, 0x05, 0x21, 0x29, 0x01, 0x05 });
    sbhMap.put(0x86, new byte[] { 0x01, 0x03, 0x00, 0x01 });
    sbhMap.put(0x87, new byte[] { 0x01, 0x01 });
    sbhMap.put(0x88, new byte[] { 0x00, 0x2A });
    StandardBiometricHeader sbh = new StandardBiometricHeader(sbhMap);
    FaceImageDataBlock faceImageDataBlock = new FaceImageDataBlock(versionBlock, representationBlocks, sbh);

    DG2File dg2File = DG2File.createISO39794DG2File(Collections.singletonList(faceImageDataBlock));
    assertNotNull(dg2File);
//    FileOutputStream fOut = new FileOutputStream("silver_all.bin");
//    fOut.write(dg2File.getEncoded());
//    fOut.flush();
//    fOut.close();
//    Thread.sleep(500);

    DG2File reEncodedDG2File = LDSFileUtil.getDG2File(new ByteArrayInputStream(dg2File.getEncoded()));
    assertNotNull(reEncodedDG2File);

    assertEquals(dg2File, reEncodedDG2File);
  }

  @Test
  public void testCreateDG2() throws Exception {
    FaceImageRepresentationBlock faceImageRepresentationBlock = new FaceImageRepresentationBlock(null, null, null, null, null, null, null, null, null, null);
    FaceImageDataBlock faceImageDataBlock = new FaceImageDataBlock(new VersionBlock(3, 2019), Collections.singletonList(faceImageRepresentationBlock), null);
    StandardBiometricHeader sbh = faceImageDataBlock.getStandardBiometricHeader();
    assertNotNull(sbh);

    //    DG2File dg2File = DG2File.createISO39794DG2File(Collections.singletonList(faceImageDataBlock));
  }

  @Test
  public void testISOSampleFaceImageDataBlock() {
    testFaceImageDataBlock("/lds/dg2/iso39794/sample-39794-5-ed-1-v1.der");
  }

  private static FaceImageDataBlock createSampleFaceImageDataBlock(ImageDataFormatCode formatCode, byte[] representationData2DBytes) {
    VersionBlock versionBlock = new VersionBlock(1, 2019);
    FaceImageRepresentationBlock faceImageRepresentationBlock = createSampleFaceImageRepresentationBlock(formatCode, representationData2DBytes);
    StandardBiometricHeader sbh = null;
    FaceImageDataBlock fidb = new FaceImageDataBlock(versionBlock, Collections.singletonList(faceImageRepresentationBlock), null);
    return fidb;
  }

  private static FaceImageRepresentationBlock createSampleFaceImageRepresentationBlock(ImageDataFormatCode formatCode, byte[] representationData2DBytes) {
    BigInteger representationId = BigInteger.ONE;
    FaceImageRepresentation2DBlock imageRepresentation2DBlock = createSampleFaceImageRepresentation2DBlock(formatCode, representationData2DBytes);
    DateTimeBlock captureDateTimeBlock = null;
    List<QualityBlock> qualityBlocks = null;
    List<PADDataBlock> padDataBlocks = null;
    BigInteger sessionId = null;
    BigInteger derivedFrom = null;
    FaceImageCaptureDeviceBlock captureDeviceBlock = null;
    FaceImageIdentityMetadataBlock identityMetadataBlock = null;
    List<FaceImageLandmarkBlock> landmarkBlocks = null;
    return new FaceImageRepresentationBlock(representationId,
        imageRepresentation2DBlock,
        captureDateTimeBlock, qualityBlocks, padDataBlocks, sessionId, derivedFrom, captureDeviceBlock,
        identityMetadataBlock, landmarkBlocks);
  }

  private static FaceImageRepresentation2DBlock createSampleFaceImageRepresentation2DBlock(ImageDataFormatCode formatCode, byte[] representationData2DBytes) {
    FaceImageInformation2DBlock imageInformation2DBlock =  createSampleFaceImageInformation2DBlock(formatCode);
    FaceImageCaptureDevice2DBlock captureDevice2DBlock = null;
    return new FaceImageRepresentation2DBlock(representationData2DBytes, imageInformation2DBlock, captureDevice2DBlock);
  }

  private static FaceImageInformation2DBlock createSampleFaceImageInformation2DBlock(ImageDataFormatCode imageDataFormatCode) {
    ImageSizeBlock imageSizeBlock = null;
    FaceImageKind2DCode faceImageKind2DCode = null;
    FaceImagePostAcquisitionProcessingBlock postAcquisitionProcessingBlock = null;
    LossyTransformationAttemptsCode lossyTransformationAttemptsCode = null;
    Integer cameraToSubjectDistance = null;
    Integer sensorDiagonal = null;
    Integer lensFocalLength = null;
    ImageFaceMeasurementsBlock imageFaceMeasurementsBlock = null;
    ImageColourSpaceCode imageColourSpaceCode = null;
    FaceImageReferenceColourMappingBlock referenceColourMappingBlock = null;
    return new FaceImageInformation2DBlock(imageDataFormatCode, faceImageKind2DCode,
        postAcquisitionProcessingBlock, lossyTransformationAttemptsCode,
        cameraToSubjectDistance, sensorDiagonal, lensFocalLength, imageSizeBlock, imageFaceMeasurementsBlock,
        imageColourSpaceCode, referenceColourMappingBlock);
  }

  @Test
  public void testDG2File() {
    testDG2File("/lds/dg2/dg2_silver_all_fields.bin", 1);
    //    testDG2File("/lds/dg2/dg2_silver_mandatory_fields.bin", 1);
  }

  private void testFaceImageDataBlock(String resource) {
    try {
      InputStream inputStream = ISO39794DG2FileTest.class.getResourceAsStream(resource);
      assertNotNull(inputStream);
      FaceImageDataBlock dataBlock = new FaceImageDataBlock(inputStream);
      testDecodeEncode(dataBlock, resource);
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  private void testDG2File(String resource, int expectedBDBCount) {
    try {
      InputStream inputStream = ISO39794DG2FileTest.class.getResourceAsStream(resource);
      assertNotNull(inputStream);
      DG2File dg2File = new DG2File(inputStream);
      assertEquals(BiometricEncodingType.ISO_39794, dg2File.getEncodingType());

      List<FaceInfo> faceInfos = dg2File.getFaceInfos();
      assertNotNull(faceInfos);
      assertEquals(0, faceInfos.size());

      List<BiometricDataBlock> records = dg2File.getSubRecords();
      assertNotNull(records);
      assertEquals(expectedBDBCount, records.size());
      for (BiometricDataBlock record: records) {
        assertNotNull(record);
        assertTrue(record instanceof FaceImageDataBlock);
        FaceImageDataBlock faceImageDataBlock = (FaceImageDataBlock)record;

        // [80 -> 0101, 81 -> 02, 82 -> 00, 83 -> 21240105112345, 85 -> 2124010521290105, 86 -> 01030001, 87 -> 0101, 88 -> 002A]
        // [87 -> 0101, 88 -> 002A]
        // [81 -> 02, 82 -> 00, 87 -> 0101, 88 -> 002A]
        // [81 -> 02, 82 -> 00, 87 -> 0101, 88 -> 002A]

        testDecodeEncode(faceImageDataBlock, resource);

        List<FaceImageRepresentationBlock> imageRepresentationBlocks = faceImageDataBlock.getRepresentationBlocks();
        FaceImageRepresentation2DBlock imageRepresentation2DBlock = imageRepresentationBlocks.get(0).getImageRepresentation2DBlock();
        assertEquals("image/jp2", imageRepresentation2DBlock.getRepresentationData2DInputMimeType());

        long imageLength = imageRepresentation2DBlock.getRepresentationData2DInputLength();
        assertTrue(imageLength > 0);

        InputStream imageInputStream = imageRepresentation2DBlock.getRepresentationData2DInputStream();
        byte[] imageBytes = readInputStream(imageInputStream);
        assertEquals(imageLength, imageBytes.length);

        FaceImageInformation2DBlock imageInformation2DBlock = imageRepresentation2DBlock.getImageInformation2DBlock();

        ImageSizeBlock imageSizeBlock = imageInformation2DBlock.getImageSizeBlock();

        if (imageSizeBlock != null) {
          int imageWidth = imageSizeBlock.getWidth();
          assertEquals(572, imageWidth);

          int imageHeight = imageSizeBlock.getHeight();
          assertEquals(731, imageHeight);
        }
      }

      //      byte[] reEncodedDG2Bytes = dg2File.getEncoded();
      //
      //      DG2File decodedDGFile = new DG2File(new ByteArrayInputStream(reEncodedDG2Bytes));


    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  private void testDecodeEncode(FaceImageDataBlock faceImageDataBlock, String resource) {
    try {
      byte[] encoded = faceImageDataBlock.getEncoded();

      FaceImageDataBlock reconstructed = new FaceImageDataBlock(faceImageDataBlock.getStandardBiometricHeader(), new ByteArrayInputStream(encoded));

      assertEquals(faceImageDataBlock, reconstructed);

      byte[] reEncoded = reconstructed.getEncoded();

      assertEquals(encoded.length, reEncoded.length);
      assertTrue(Arrays.equals(encoded, reEncoded));

    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "", e);
      fail(e.getMessage());
    }
  }

  private static byte[] readInputStream(InputStream inputStream) throws IOException {
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    int nRead;
    byte[] data = new byte[16384];
    while ((nRead = inputStream.read(data, 0, data.length)) != -1) {
      buffer.write(data, 0, nRead);
    }
    return buffer.toByteArray();
  }

  private static byte[] readResource(String resource) throws IOException {
    InputStream inputStream = ISO39794DG2FileTest.class.getResourceAsStream(resource);
    assertNotNull(inputStream);
    return readInputStream(inputStream);
  }

  private static byte[] createTrivialJPEGBytes(int width, int height) {
    try {
      BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      ImageIO.write(image, "jpg", out);
      out.flush();
      byte[] bytes = out.toByteArray();
      return bytes;
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
      return null;
    }
  }
}
