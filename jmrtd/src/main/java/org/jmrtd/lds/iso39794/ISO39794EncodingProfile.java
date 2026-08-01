/*
 * JMRTD - A Java API for accessing machine readable travel documents.
 *
 * Copyright (C) 2006 - 2026  The JMRTD team
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
 */

package org.jmrtd.lds.iso39794;

import java.util.List;

import org.jmrtd.lds.iso39794.FaceImageIdentityMetadataBlock.GenderCode;
import org.jmrtd.lds.iso39794.FaceImageInformation2DBlock.FaceImageKind2DCode;
import org.jmrtd.lds.iso39794.FaceImageInformation2DBlock.ImageDataFormatCode;

/**
 * Encoding profiles for ISO/IEC 39794 data.
 *
 * Decoding deliberately does not use a profile: JMRTD accepts both base-standard
 * and application-profile encodings.
 */
public enum ISO39794EncodingProfile {

  /** The unconstrained ISO/IEC 39794 base-standard encoding. */
  BASE,

  /** ISO/IEC 39794-5 Application Profile for eMRTDs, version 1.0. */
  ICAO_39794_5_EMRTD_V1;

  enum ChoiceType {
    SCORING_ERROR,
    PAD_DECISION,
    PAD_CAPTURE_CONTEXT,
    PAD_SUPERVISION_LEVEL,
    PAD_CRITERIA_CATEGORY,
    GENDER,
    EYE_COLOUR,
    HAIR_COLOUR,
    MPEG4_FEATURE_POINT,
    ANTHROPOMETRIC_LANDMARK_NAME,
    ANTHROPOMETRIC_LANDMARK_POINT_NAME,
    ANTHROPOMETRIC_LANDMARK_POINT_ID,
    CAPTURE_DEVICE_TECHNOLOGY_2D,
    FACE_IMAGE_KIND_2D,
    LOSSY_TRANSFORMATION_ATTEMPTS,
    IMAGE_COLOUR_SPACE
  }

  boolean usesExtensionBlockFallback(ChoiceType choiceType) {
    return this == ICAO_39794_5_EMRTD_V1;
  }

  void validate(FaceImageDataBlock dataBlock) {
    if (this != ICAO_39794_5_EMRTD_V1) {
      return;
    }

    List<FaceImageRepresentationBlock> representations = dataBlock.getRepresentationBlocks();
    if (representations == null || representations.size() != 1) {
      throw new IllegalArgumentException("ICAO ISO/IEC 39794-5 profile requires exactly one representation");
    }

    FaceImageRepresentationBlock representation = representations.get(0);
    if (representation == null || representation.getImageRepresentation2DBlock() == null) {
      throw new IllegalArgumentException("ICAO ISO/IEC 39794-5 profile requires a 2D face representation");
    }
    if (representation.getPadDataBlocks() != null && representation.getPadDataBlocks().size() > 1) {
      throw new IllegalArgumentException("ICAO ISO/IEC 39794-5 profile permits at most one PAD data block");
    }

    FaceImageInformation2DBlock information = representation.getImageRepresentation2DBlock().getImageInformation2DBlock();
    if (information == null) {
      throw new IllegalArgumentException("ICAO ISO/IEC 39794-5 profile requires 2D image information");
    }
    ImageDataFormatCode format = information.getImageDataFormatCode();
    if (format != ImageDataFormatCode.JPEG && format != ImageDataFormatCode.JPEG2000_LOSSY
        && format != ImageDataFormatCode.JPEG2000_LOSSLESS) {
      throw new IllegalArgumentException("Image format is not permitted by the ICAO ISO/IEC 39794-5 profile: " + format);
    }
    FaceImageKind2DCode kind = information.getFaceImageKind2DCode();
    if (kind != null && kind != FaceImageKind2DCode.MRTD) {
      throw new IllegalArgumentException("Face image kind is not permitted by the ICAO ISO/IEC 39794-5 profile: " + kind);
    }

    FaceImageIdentityMetadataBlock identity = representation.getIdentityMetadataBlock();
    if (identity != null && identity.getGenderCode() == GenderCode.UNKNOWN) {
      throw new IllegalArgumentException("UNKNOWN gender is not permitted by the ICAO ISO/IEC 39794-5 profile");
    }
  }
}
