/*
 * JMRTD - A Java API for accessing machine readable travel documents.
 *
 * Copyright (C) 2006 - 2017  The JMRTD team
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

package org.jmrtd.lds.icao;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.jmrtd.lds.DataGroup;

import net.sf.scuba.tlv.TLVInputStream;
import net.sf.scuba.tlv.TLVOutputStream;

/**
 * File structure for the EF_DG1 file.
 * Datagroup 1 contains the Machine
 * Readable Zone information.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision$
 */
public class DG1File extends DataGroup {

  private static final long serialVersionUID = 5091606125728809058L;

  private static final short MRZ_INFO_TAG = 0x5F1F;

  private MRZInfo mrzInfo;

  /**
   * Creates a new file based on MRZ information.
   *
   * @param mrzInfo the MRZ information to store in this file
   */
  public DG1File(MRZInfo mrzInfo) {
    super(EF_DG1_TAG);
    this.mrzInfo = mrzInfo;
  }

  /**
   * Creates a new file based on an input stream.
   *
   * @param in an input stream
   *
   * @throws IOException if something goes wrong
   */
  public DG1File(InputStream in) throws IOException {
    super(EF_DG1_TAG, in);
  }

  protected void readContent(InputStream in) throws IOException {
    TLVInputStream tlvIn = in instanceof TLVInputStream ? (TLVInputStream)in : new TLVInputStream(in);
    tlvIn.skipToTag(MRZ_INFO_TAG);
    int length = tlvIn.readLength();
    this.mrzInfo = new MRZInfo(tlvIn, length);
  }

  /**
   * Gets the MRZ information stored in this file.
   *
   * @return the MRZ information
   */
  public MRZInfo getMRZInfo() {
    return mrzInfo;
  }

  /**
   * Gets a textual representation of this file.
   *
   * @return a textual representation of this file
   */
  @Override
  public String toString() {
    return "DG1File " + mrzInfo.toString().replaceAll("\n", "").trim();
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == null) {
      return false;
    }
    if (!(obj.getClass().equals(this.getClass()))) {
      return false;
    }
    
    DG1File other = (DG1File)obj;
    return mrzInfo.equals(other.mrzInfo);
  }

  @Override
  public int hashCode() {
    return 3 * mrzInfo.hashCode() + 57;
  }

  @Override
  protected void writeContent(OutputStream out) throws IOException {
    TLVOutputStream tlvOut = out instanceof TLVOutputStream ? (TLVOutputStream)out : new TLVOutputStream(out);
    tlvOut.writeTag(MRZ_INFO_TAG);
    byte[] value = mrzInfo.getEncoded();
    tlvOut.writeValue(value);
  }
}
