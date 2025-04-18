/*
 * JMRTD - A Java API for accessing machine readable travel documents.
 *
 * Copyright (C) 2006 - 2025  The JMRTD team
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
 *
 * $Id$
 *
 * Based on ISO-IEC-39794-5-ed-1-v1. Disclaimer:
 * THE SCHEMA ON WHICH THIS SOFTWARE IS BASED IS PROVIDED BY THE COPYRIGHT
 * HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THE CODE COMPONENTS, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.jmrtd.lds.iso39794;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.jmrtd.ASN1Util;

public class FaceImageCaptureDevice2DBlock extends Block {

  private static final long serialVersionUID = -8445632002285427924L;

  public static enum CaptureDeviceTechnologyId2DCode implements EncodableEnum<CaptureDeviceTechnologyId2DCode> {
    UNKNOWN(0),
    STATIC_PHOTOGRAPH_FROM_UNKNOWN_SOURCE(1),
    STATIC_PHOTOGRAPH_FROM_DIGITAL_STILL_IMAGE_CAMERA(2),
    STATIC_PHOTOGRAPH_FROM_SCANNER(3),
    VIDEO_FRAME_FROM_UNKNOWN_SOURCE(4),
    VIDEO_FRAME_FROM_ANALOGUE_VIDEO_CAMERA(5),
    VIDEO_FRAME_FROM_DIGITAL_VIDEO_CAMERA(6);

    private int code;

    private CaptureDeviceTechnologyId2DCode(int code) {
      this.code = code;
    }

    public int getCode() {
      return code;
    }

    public static CaptureDeviceTechnologyId2DCode fromCode(int code) {
      return EncodableEnum.fromCode(code, CaptureDeviceTechnologyId2DCode.class);
    }
  }

  private FaceImageCaptureDeviceSpectral2DBlock captureDeviceSpectral2DBlock;

  private CaptureDeviceTechnologyId2DCode captureDeviceTechnologyId2D;

  public FaceImageCaptureDevice2DBlock(FaceImageCaptureDeviceSpectral2DBlock captureDeviceSpectral2DBlock,
      CaptureDeviceTechnologyId2DCode captureDeviceTechnologyId2D) {
    this.captureDeviceSpectral2DBlock = captureDeviceSpectral2DBlock;
    this.captureDeviceTechnologyId2D = captureDeviceTechnologyId2D;
  }

  //  CaptureDevice2DBlock ::= SEQUENCE {
  //    captureDeviceSpectral2DBlock [0] CaptureDeviceSpectral2DBlock OPTIONAL,
  //    captureDeviceTechnologyId2D [1] CaptureDeviceTechnologyId2D OPTIONAL,
  //    ...
  //  }

  FaceImageCaptureDevice2DBlock(ASN1Encodable asn1Encodable) {
    if (asn1Encodable == null) {
      throw new IllegalArgumentException("Cannot decode null!");
    }

    if (asn1Encodable instanceof ASN1Sequence) {
      Map<Integer, ASN1Encodable> taggedObjects = ASN1Util.decodeTaggedObjects(ASN1Sequence.getInstance(asn1Encodable));
      if (taggedObjects.containsKey(0)) {
        captureDeviceSpectral2DBlock = new FaceImageCaptureDeviceSpectral2DBlock(taggedObjects.get(0));
      }

      if (taggedObjects.containsKey(1)) {
        captureDeviceTechnologyId2D = CaptureDeviceTechnologyId2DCode.fromCode(ISO39794Util.decodeCodeFromChoiceExtensionBlockFallback(taggedObjects.get(1)));
      }
    }
  }

  public FaceImageCaptureDeviceSpectral2DBlock getCaptureDeviceSpectral2DBlock() {
    return captureDeviceSpectral2DBlock;
  }

  public CaptureDeviceTechnologyId2DCode getCaptureDeviceTechnologyId2D() {
    return captureDeviceTechnologyId2D;
  }

  @Override
  public int hashCode() {
    return Objects.hash(captureDeviceSpectral2DBlock, captureDeviceTechnologyId2D);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null) {
      return false;
    }
    if (getClass() != obj.getClass()) {
      return false;
    }

    FaceImageCaptureDevice2DBlock other = (FaceImageCaptureDevice2DBlock) obj;
    return Objects.equals(captureDeviceSpectral2DBlock, other.captureDeviceSpectral2DBlock)
        && captureDeviceTechnologyId2D == other.captureDeviceTechnologyId2D;
  }

  @Override
  public String toString() {
    return "FaceImageCaptureDevice2DBlock ["
        + "captureDeviceSpectral2DBlock: " + captureDeviceSpectral2DBlock
        + ", captureDeviceTechnologyId2D: " + captureDeviceTechnologyId2D
        + "]";
  }

  /* PACKAGE */

  @Override
  ASN1Encodable getASN1Object() {
    Map<Integer, ASN1Encodable> taggedObjects = new HashMap<Integer, ASN1Encodable>();
    if (captureDeviceSpectral2DBlock != null) {
      taggedObjects.put(0, captureDeviceSpectral2DBlock.getASN1Object());
    }
    if (captureDeviceTechnologyId2D != null) {
      taggedObjects.put(1, ISO39794Util.encodeCodeAsChoiceExtensionBlockFallback(captureDeviceTechnologyId2D.getCode()));
    }
    return ASN1Util.encodeTaggedObjects(taggedObjects);
  }
}
