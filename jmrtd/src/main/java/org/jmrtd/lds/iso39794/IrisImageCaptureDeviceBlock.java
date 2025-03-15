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
 * Based on ISO-IEC-39794-6-ed-1-v1. Disclaimer:
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

import org.bouncycastle.asn1.ASN1Encodable;
import org.jmrtd.ASN1Util;

public class IrisImageCaptureDeviceBlock extends Block {

  private static final long serialVersionUID = -4279701511600052026L;

  public enum CaptureDeviceTechnologyIdCode {
    UNKNOWN(0),
    CMOS_CCD(1);

    private int code;

    private CaptureDeviceTechnologyIdCode(int code) {
      this.code = code;
    }

    public int getCode() {
      return code;
    }

    public static CaptureDeviceTechnologyIdCode fromCode(int code) {
      if (code < 0) {
        return null;
      }
      for (CaptureDeviceTechnologyIdCode value: values()) {
        if (code == value.code) {
          return value;
        }
      }

      return null;
    }
  }

  /** Identification of the model capture device. */
  private RegistryIdBlock model;

  private CaptureDeviceTechnologyIdCode captureDeviceTechnologyIdCode;

  /** Identification of certifications. */
  private List<RegistryIdBlock> certifications;

  //  CaptureDeviceBlock ::= SEQUENCE {
  //    modelIdBlock [0] RegistryIdBlock,
  //    technologyId [1] CaptureDeviceTechnologyId OPTIONAL,
  //    certificationIdBlocks [2] CertificationIdBlocks OPTIONAL,
  //    ...
  //  }

  public IrisImageCaptureDeviceBlock(ASN1Encodable asn1Encodable) {
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
    // TODO Auto-generated method stub
    return 0;
  }

  @Override
  public boolean equals(Object other) {
    // TODO Auto-generated method stub
    return false;
  }

  /* PACKAGE */

  @Override
  ASN1Encodable getASN1Object() {
    Map<Integer, ASN1Encodable> taggedObjects = new HashMap<Integer, ASN1Encodable>();
    taggedObjects.put(0, model.getASN1Object());
    if (captureDeviceTechnologyIdCode != null) {
      taggedObjects.put(1,
          ISO39794Util.encodeCodeAsChoiceExtensionBlockFallback(captureDeviceTechnologyIdCode.getCode()));
    }
    if (certifications != null) {
      taggedObjects.put(2, ISO39794Util.encodeBlocks(certifications));
    }
    return ASN1Util.encodeTaggedObjects(taggedObjects);
  }
}
