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

package org.jmrtd.cbeff;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;

public class ISO781611CodecTest {

  @Test
  public void roundTripsMultipleBiometricInformationTemplates() throws Exception {
    StandardBiometricHeader firstHeader = createHeader((byte)0x01);
    StandardBiometricHeader secondHeader = createHeader((byte)0x02);
    TestBiometricDataBlock first =
        new TestBiometricDataBlock(firstHeader, new byte[] { 0x11, 0x12 });
    TestBiometricDataBlock second =
        new TestBiometricDataBlock(secondHeader, new byte[] { 0x21, 0x22, 0x23 });
    ComplexCBEFFInfo<TestBiometricDataBlock> group =
        new ComplexCBEFFInfo<TestBiometricDataBlock>();
    group.add(new SimpleCBEFFInfo<TestBiometricDataBlock>(first));
    group.add(new SimpleCBEFFInfo<TestBiometricDataBlock>(second));

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    new ISO781611Encoder<TestBiometricDataBlock>(
        new TestEncoder(BiometricEncodingType.ISO_19794)).encode(group, outputStream);
    RecordingDecoder decoder = new RecordingDecoder();
    ISO781611Decoder<TestBiometricDataBlock> containerDecoder =
        new ISO781611Decoder<TestBiometricDataBlock>(decoder);

    ComplexCBEFFInfo<TestBiometricDataBlock> decoded =
        containerDecoder.decode(new ByteArrayInputStream(outputStream.toByteArray()));

    List<CBEFFInfo<TestBiometricDataBlock>> records = decoded.getSubRecords();
    assertEquals(2, records.size());
    assertBlock(records.get(0), firstHeader, first.getPayload());
    assertBlock(records.get(1), secondHeader, second.getPayload());
    assertEquals(2, decoder.getDecodeCount());
    assertEquals(BiometricEncodingType.ISO_19794, containerDecoder.getEncodingType());
  }

  @Test
  public void selectsDecoderUsingBiometricDataBlockTag() throws Exception {
    TestBiometricDataBlock block =
        new TestBiometricDataBlock(createHeader((byte)0x03), new byte[] { 0x31 });
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    new ISO781611Encoder<TestBiometricDataBlock>(
        new TestEncoder(BiometricEncodingType.ISO_39794))
        .encode(new SimpleCBEFFInfo<TestBiometricDataBlock>(block), outputStream);

    RecordingDecoder primitiveDecoder = new RecordingDecoder();
    RecordingDecoder constructedDecoder = new RecordingDecoder();
    Map<Integer, BiometricDataBlockDecoder<TestBiometricDataBlock>> decoders =
        new HashMap<Integer, BiometricDataBlockDecoder<TestBiometricDataBlock>>();
    decoders.put(ISO781611.BIOMETRIC_DATA_BLOCK_TAG, primitiveDecoder);
    decoders.put(ISO781611.BIOMETRIC_DATA_BLOCK_CONSTRUCTED_TAG, constructedDecoder);
    ISO781611Decoder<TestBiometricDataBlock> decoder =
        new ISO781611Decoder<TestBiometricDataBlock>(decoders);

    decoder.decode(new ByteArrayInputStream(outputStream.toByteArray()));

    assertEquals(0, primitiveDecoder.getDecodeCount());
    assertEquals(1, constructedDecoder.getDecodeCount());
    assertEquals(BiometricEncodingType.ISO_39794, decoder.getEncodingType());
  }

  @Test
  public void rejectsMalformedGroupAndCountTags() {
    final ISO781611Decoder<TestBiometricDataBlock> decoder =
        new ISO781611Decoder<TestBiometricDataBlock>(new RecordingDecoder());

    assertThrows(IllegalArgumentException.class,
        () -> decoder.decode(new ByteArrayInputStream(new byte[] {
            0x7F, 0x62, 0x00 })));
    assertThrows(IllegalArgumentException.class,
        () -> decoder.decode(new ByteArrayInputStream(new byte[] {
            0x7F, 0x61, 0x04, 0x02, 0x02, 0x01, 0x00 })));
  }

  private static StandardBiometricHeader createHeader(byte subtype) {
    Map<Integer, byte[]> elements = new HashMap<Integer, byte[]>();
    elements.put(ISO781611.BIOMETRIC_TYPE_TAG, new byte[] { 0x02 });
    elements.put(ISO781611.BIOMETRIC_SUBTYPE_TAG, new byte[] { subtype });
    return new StandardBiometricHeader(elements);
  }

  private static void assertBlock(CBEFFInfo<TestBiometricDataBlock> info,
      StandardBiometricHeader expectedHeader, byte[] expectedPayload) {
    TestBiometricDataBlock block =
        ((SimpleCBEFFInfo<TestBiometricDataBlock>)info).getBiometricDataBlock();
    assertEquals(expectedHeader, block.getStandardBiometricHeader());
    assertArrayEquals(expectedPayload, block.getPayload());
  }

  private static final class TestEncoder
      implements BiometricDataBlockEncoder<TestBiometricDataBlock> {

    private final BiometricEncodingType encodingType;

    private TestEncoder(BiometricEncodingType encodingType) {
      this.encodingType = encodingType;
    }

    @Override
    public void encode(TestBiometricDataBlock block, OutputStream outputStream)
        throws IOException {
      outputStream.write(block.getPayload());
    }

    @Override
    public BiometricEncodingType getEncodingType() {
      return encodingType;
    }
  }

  private static final class RecordingDecoder
      implements BiometricDataBlockDecoder<TestBiometricDataBlock> {

    private int decodeCount;

    @Override
    public TestBiometricDataBlock decode(InputStream inputStream,
        StandardBiometricHeader header, int index, int length) throws IOException {
      byte[] payload = new byte[length];
      int offset = 0;
      while (offset < payload.length) {
        int count = inputStream.read(payload, offset, payload.length - offset);
        if (count < 0) {
          throw new IOException("Unexpected end of biometric data block");
        }
        offset += count;
      }
      assertEquals(decodeCount, index);
      decodeCount++;
      return new TestBiometricDataBlock(header, payload);
    }

    private int getDecodeCount() {
      return decodeCount;
    }
  }

  private static final class TestBiometricDataBlock implements BiometricDataBlock {

    private static final long serialVersionUID = 1L;

    private final StandardBiometricHeader header;
    private final byte[] payload;

    private TestBiometricDataBlock(StandardBiometricHeader header, byte[] payload) {
      this.header = header;
      this.payload = payload.clone();
    }

    @Override
    public StandardBiometricHeader getStandardBiometricHeader() {
      return header;
    }

    private byte[] getPayload() {
      return payload.clone();
    }
  }
}
