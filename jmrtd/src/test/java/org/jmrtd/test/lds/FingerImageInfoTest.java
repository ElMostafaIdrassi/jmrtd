/*
 *  JMRTD Tests.
 *
 *  Copyright (C) 2009  The JMRTD team
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *  
 *  $Id: $
 */

package org.jmrtd.test.lds;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.logging.Logger;

import javax.imageio.ImageIO;

import org.jmrtd.lds.DG3File;
import org.jmrtd.lds.FingerImageInfo;
import org.jmrtd.lds.FingerInfo;
import org.jmrtd.lds.ImageInfo;
import org.jmrtd.test.ResourceUtil;

import junit.framework.TestCase;
import net.sf.scuba.util.Hex;

public class FingerImageInfoTest extends TestCase {

	private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

	public FingerImageInfoTest(String name) {
		super(name);
	}

	public void testToString() {
		try {
			FingerImageInfo imageInfo = createRightIndexFingerTestObject();
			assertNotNull(imageInfo);
			String asString = imageInfo.toString();
			assertNotNull(asString);
		} catch (Exception e) {
			e.printStackTrace();
			fail(e.toString());
		}
	}

	public void testNonNullEncoded() {
		FingerImageInfo imageInfo = createRightIndexFingerTestObject();
		assertNotNull(imageInfo);
		byte[] encoded = imageInfo.getEncoded();
		assertNotNull(encoded);
	}

	public void testEncodeDecode() {
		FingerImageInfo testObject = createRightIndexFingerTestObject();
		testEncodeDecode(testObject);
	}

	public void testBSI() {
		try {
			byte[] imageBytes = ResourceUtil.getBytes("/lds/wsq/fp.wsq");
			//			BufferedImage image = ImageIO.read(new ByteArrayInputStream(imageBytes));
			//			LOGGER.info("DEBUG: image.getWidth() = " + image.getWidth());
			//			LOGGER.info("DEBUG: image.getHeight() = " + image.getHeight());
		} catch (Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		}
	}

	public void testCreateExtract() {
		try {
			FingerImageInfo fingerImageInfo = createNonEmptyTestObject();
			assertTrue(fingerImageInfo.getImageLength() > 0);
			assertTrue(fingerImageInfo.getWidth() > 0);
			assertTrue(fingerImageInfo.getHeight() > 0);
		} catch (Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		}
	}

	public void testEncodeDecode(FingerImageInfo original) {
		try {
			String mimeType = original.getMimeType();
			int compressionAlg = 0;

			if ("image/x-wsq".equals(mimeType)) { compressionAlg = FingerInfo.COMPRESSION_WSQ; }
			else if ("image/jpeg".equals(mimeType)) { compressionAlg = FingerInfo.COMPRESSION_JPEG; }
			else if ("image/jpeg2000".equals(mimeType)) { compressionAlg = FingerInfo.COMPRESSION_JPEG2000; }
			else { fail("This test doesn't support this image data type " + mimeType); }
			byte[] encoded = original.getEncoded();
			assertNotNull(encoded);
			ByteArrayInputStream in = new ByteArrayInputStream(encoded);
			FingerImageInfo copy = new FingerImageInfo(in, compressionAlg);
			assertEquals(original, copy);
			byte[] encodedCopy = copy.getEncoded();
			assertNotNull(encodedCopy);
			assertEquals(Hex.bytesToHexString(encoded), Hex.bytesToHexString(encodedCopy));
		} catch (Exception e) {
			e.printStackTrace();
			fail(e.toString());
		}
	}

	public void testWidthHeight() {
		try {
			FingerImageInfo imageInfo = createRightIndexFingerTestObject();
			LOGGER.info("DEBUG: imageInfo.getWidth() = " + imageInfo.getWidth());
			LOGGER.info("DEBUG: imageInfo.getHeight() = " + imageInfo.getHeight());
			String mimeType = imageInfo.getMimeType();
			assertNotNull(mimeType);
			assertTrue("image/x-wsq".equals(mimeType) || "image/jpeg2000".equals(mimeType) || "image/jpeg".equals(mimeType));
//			BufferedImage image = ImageUtil.read(imageInfo.getImageInputStream(), imageInfo.getImageLength(), mimeType);
//			assertEquals(imageInfo.getWidth(), image.getWidth());
//			assertEquals(imageInfo.getHeight(), image.getHeight());
		} catch (Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		}
	}

	//	public void testExtractImage() {
	//		FingerImageInfo imageInfo = createRightIndexFingerTestObject();
	//		testExtractImage(imageInfo, 545, 622);
	//	}

	//	public void testExtractImage(FingerImageInfo imageInfo, int expectedWidth, int expectedHeight) {
	//		try {
	//			BufferedImage image = ImageUtil.read(imageInfo.getImageInputStream(), imageInfo.getImageLength(), imageInfo.getMimeType());
	//			assertNotNull(image);
	//			assertEquals(image.getType(), BufferedImage.TYPE_BYTE_GRAY);
	//			assertEquals(image.getWidth(), expectedWidth);
	//			assertEquals(image.getHeight(), expectedHeight);
	//		} catch (Exception e) {
	//			e.printStackTrace();
	//			fail(e.getMessage());
	//		}
	//	}

	public void testViewCountAndNumber() {
		FingerImageInfo fingerImageInfo = createRightIndexFingerTestObject();
		testViewCountAndNumber(fingerImageInfo);
	}

	public void testViewCountAndNumber(FingerImageInfo fingerImageInfo) {
		int viewCount = fingerImageInfo.getViewCount();
		int viewNumber = fingerImageInfo.getViewCount();
		LOGGER.info("DEBUG: viewCount = " + viewCount);
		LOGGER.info("DEBUG: viewNumber = " + viewNumber);
		assertTrue(viewCount >= 1);
		assertTrue(viewNumber <= viewCount);
	}

	public void testValidType() {
		FingerImageInfo portraitInfo = createRightIndexFingerTestObject();
		testValidType(portraitInfo);
	}

	public void testValidType(FingerImageInfo imageInfo) {
		int type = imageInfo.getType();
		assertEquals(type, ImageInfo.TYPE_FINGER);
	}

	public void testLength() {
		FingerImageInfo fingerImageInfo = createRightIndexFingerTestObject();
		int imageLength = fingerImageInfo.getImageLength();
		int recordLength = (int)fingerImageInfo.getRecordLength();
		LOGGER.info("DEBUG: imageLength = " + imageLength);
		LOGGER.info("DEBUG: recordLength = " + recordLength);
		assertTrue(imageLength < recordLength);
	}

	public static FingerImageInfo createNonEmptyTestObject() {
		return createNonEmptyTestObject(createTrivialJPGBytes(200, 200), 200, 200, "image/jpeg");
	}

//	public static FingerImageInfo createNonEmptyTestObject(byte[] imageBytes, String mimeType) {
//		try {
//			BufferedImage image = ImageUtil.read(new ByteArrayInputStream(imageBytes), imageBytes.length, mimeType);
//			int width = image.getWidth();
//			int height = image.getHeight();
//			return createNonEmptyTestObject(imageBytes, width, height, mimeType);
//		} catch (IOException ioe) {
//			ioe.printStackTrace();
//			fail(ioe.getMessage());
//			return null;
//		}
//	}

	public static String
	JPEG_MIME_TYPE = "image/jpeg",
	JPEG2000_MIME_TYPE = "image/jp2",
	JPEG2000_ALT_MIME_TYPE = "image/jpeg2000",
	WSQ_MIME_TYPE = "image/x-wsq";
	
	public static FingerImageInfo createNonEmptyTestObject(byte[] imageBytes, int width, int height, String mimeType) {
		try {
			int position = FingerImageInfo.POSITION_RIGHT_INDEX_FINGER;
			int viewCount = 1;
			int viewNumber = 1;
			int quality = 69;
			int impressionType = FingerImageInfo.IMPRESSION_TYPE_LIVE_SCAN_PLAIN;
			int compressionType = -1;

			if (JPEG_MIME_TYPE.equals(mimeType)) { compressionType = FingerInfo.COMPRESSION_JPEG; }
			else if (WSQ_MIME_TYPE.equals(mimeType)) {compressionType = FingerInfo.COMPRESSION_WSQ; }
			else if (JPEG2000_MIME_TYPE.equals(mimeType) || JPEG2000_ALT_MIME_TYPE.equals(mimeType)) {compressionType = FingerInfo.COMPRESSION_JPEG2000; }

			FingerImageInfo imageInfo = new FingerImageInfo(position, viewCount,  viewNumber,  quality,  impressionType,
					width,  height, new ByteArrayInputStream(imageBytes), imageBytes.length, compressionType);

			return imageInfo;
		} catch (IOException ioe) {
			ioe.printStackTrace();
			fail(ioe.getMessage());
			return null;
		}
	}

	/*
	 * Encoding of a 545 x 622 WSQ image.
	 */
	private static byte[] getSampleWSQBytes() {
		try {
			return ResourceUtil.getBytes("/lds/wsq/sample_image.wsq");
		} catch (Exception e) {
			e.printStackTrace();
			fail(e.toString());
			return null;
		}
	}

	//	/**
	//	 * FIXME: this appears to break j2wsq!
	//	 * 
	//	 * @param width
	//	 * @param height
	//	 * @return
	//	 */
	//	private static byte[] createTrivialWSQBytes(int width, int height) {
	//		try {
	//			BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_BYTE_GRAY);
	//			ByteArrayOutputStream out = new ByteArrayOutputStream();			
	//			// Images.writeImage(image, "image/x-wsq", out);
	//			ImageIO.write(image, "wsq", out);
	//			out.flush();
	//			byte[] bytes = out.toByteArray();
	//			return bytes;
	//		} catch (Exception e) {
	//			fail(e.toString());
	//			return null;
	//		}
	//	}

	/**
	 * FIXME: this appears to break j2wsq!
	 * 
	 * @param width
	 * @param height
	 * @return
	 */
	private static byte[] createTrivialJPGBytes(int width, int height) {
		try {
			BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_BYTE_GRAY);
			ByteArrayOutputStream out = new ByteArrayOutputStream();			
			// Images.writeImage(image, "image/x-wsq", out);
			ImageIO.write(image, "jpg", out);
			out.flush();
			byte[] bytes = out.toByteArray();
			return bytes;
		} catch (Exception e) {
			fail(e.toString());
			return null;
		}
	}


	/*
	 * A finger image object containing a JPG image with position is right index finger.
	 */
	public static FingerImageInfo createRightIndexFingerTestObject() {
		int width = 545;
		int height = 622;
		byte[] imageBytes = getSampleWSQBytes();
		return createNonEmptyTestObject(imageBytes, width, height, JPEG_MIME_TYPE);
	}

	public static FingerImageInfo createBSITestObject() {
		try {
			DG3File dg3 = new DG3File(ResourceUtil.getInputStream("/lds/bsi2008/Datagroup3.bin"));
			List<FingerInfo> fingerInfos = dg3.getFingerInfos();
			FingerInfo fingerInfo = fingerInfos.get(1);
			List<FingerImageInfo> fingerImageInfos = fingerInfo.getFingerImageInfos();
			return fingerImageInfos.get(0);
		} catch (Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
			return null;
		}
	}
}
