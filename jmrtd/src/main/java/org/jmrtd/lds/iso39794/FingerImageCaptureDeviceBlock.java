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
 * Based on ISO-IEC-39794-4-ed-1-v2. Disclaimer:
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
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.bouncycastle.asn1.ASN1Encodable;
import org.jmrtd.ASN1Util;

public class FingerImageCaptureDeviceBlock extends Block {

  private static final long serialVersionUID = -5356682106972185445L;

  public static enum CaptureDeviceTechnologyIdCode implements EncodableEnum<CaptureDeviceTechnologyIdCode> {
    UNKNOWN_CAPTURE_DEVICE_TECHNOLOGY(0),
    OTHER_CAPTURE_DEVICE_TECHNOLOGY(1),
    SCANNED_INK_ON_PAPER(2),
    OPTICAL_TIR_BRIGHT_FIELD(3),
    OPTICAL_TIR_DARK_FIELD(4),
    OPTICAL_IMAGE(5),
    OPTICAL_LOW_FREQUENCY_3D_MAPPED(6),
    OPTICAL_HIGH_FREQUENCY_3D_MAPPED(7),
    CAPACITIVE(9),
    CAPACITIVE_RF(10),
    ELECTRO_LUMINESCENCE(11),
    REFLECTED_ULTRASONIC(12),
    IMPEDIOGRAPHIC_ULTRASONIC(13),
    THERMAL(14),
    DIRECT_PRESSURE(15),
    INDIRECT_PRESSURE(16),
    LIVE_TAPE(17),
    LATENT_IMPRESSION(18),
    LATENT_PHOTO(19),
    LATENT_MOLDED(20),
    LATENT_TRACING(21),
    LATENT_LIFT(22);

    private int code;

    private CaptureDeviceTechnologyIdCode(int code) {
      this.code = code;
    }

    @Override
    public int getCode() {
      return code;
    }

    public static CaptureDeviceTechnologyIdCode fromCode(int code) {
      return EncodableEnum.fromCode(code, CaptureDeviceTechnologyIdCode.class);
    }
  }

  /** Identification of the model capture device. */
  private RegistryIdBlock model;

  private CaptureDeviceTechnologyIdCode captureDeviceTechnologyIdCode;

  /** Identification of certifications. */
  private List<RegistryIdBlock> certifications;

  public FingerImageCaptureDeviceBlock(RegistryIdBlock model,
      CaptureDeviceTechnologyIdCode captureDeviceTechnologyIdCode, List<RegistryIdBlock> certifications) {
    this.model = model;
    this.captureDeviceTechnologyIdCode = captureDeviceTechnologyIdCode;
    this.certifications = certifications;
  }

  //  CaptureDeviceBlock ::= SEQUENCE {
  //    modelIdBlock [0] RegistryIdBlock,
  //    technologyId [1] CaptureDeviceTechnologyId OPTIONAL,
  //    certificationIdBlocks [2] CertificationIdBlocks OPTIONAL,
  //    ...
  //  }

  FingerImageCaptureDeviceBlock(ASN1Encodable asn1Encodable) {
    if (asn1Encodable == null) {
      throw new IllegalArgumentException("Cannot decode null!");
    }

    Map<Integer, ASN1Encodable> taggedObjects = ASN1Util.decodeTaggedObjects(asn1Encodable);
    if (taggedObjects.containsKey(0)) {
      model = new RegistryIdBlock(taggedObjects.get(0));
    }
    if (taggedObjects.containsKey(1)) {
      captureDeviceTechnologyIdCode = CaptureDeviceTechnologyIdCode.fromCode(ISO39794Util.decodeCodeFromChoiceExtensionBlockFallback(taggedObjects.get(1)));
    }
    if (taggedObjects.containsKey(2)) {
      certifications = RegistryIdBlock.decodeRegistryIdBlocks(taggedObjects.get(2));
    }
  }

  public RegistryIdBlock getModel() {
    return model;
  }

  public CaptureDeviceTechnologyIdCode getCaptureDeviceTechnologyIdCode() {
    return captureDeviceTechnologyIdCode;
  }

  public List<RegistryIdBlock> getCertifications() {
    return certifications;
  }

  @Override
  public int hashCode() {
    return Objects.hash(captureDeviceTechnologyIdCode, certifications, model);
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

    FingerImageCaptureDeviceBlock other = (FingerImageCaptureDeviceBlock)obj;
    return captureDeviceTechnologyIdCode == other.captureDeviceTechnologyIdCode
        && Objects.equals(certifications, other.certifications) && Objects.equals(model, other.model);
  }

  @Override
  public String toString() {
    return "FingerImageCaptureDeviceBlock ["
        + "model: " + model
        + ", captureDeviceTechnologyIdCode: " + captureDeviceTechnologyIdCode
        + ", certifications: " + certifications
        + "]";
  }

  /* PACKAGE */

  @Override
  ASN1Encodable getASN1Object() {
    Map<Integer, ASN1Encodable> taggedObjects = new HashMap<Integer, ASN1Encodable>();
    if (model != null) {
      taggedObjects.put(0, model.getASN1Object());
    }
    if (captureDeviceTechnologyIdCode != null) {
      taggedObjects.put(1, ISO39794Util.encodeCodeAsChoiceExtensionBlockFallback(captureDeviceTechnologyIdCode.getCode()));
    }
    if (certifications != null) {
      taggedObjects.put(2, ISO39794Util.encodeBlocks(certifications));
    }
    return ASN1Util.encodeTaggedObjects(taggedObjects);
  }
}
