/*
 * JMRTD - A Java API for accessing machine readable travel documents.
 *
 * Copyright (C) 2006 - 2015  The JMRTD team
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

package org.jmrtd.lds;

import java.io.IOException;
import java.io.InputStream;
import java.util.logging.Logger;

/**
 * Base class for data group files.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision$
 */
public abstract class DataGroup extends AbstractTaggedLDSFile {
  
  private static final long serialVersionUID = -4761360877353069639L;
  
  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");
  
  /**
   * Constructs a data group. This constructor
   * is only visible to the other classes in this package.
   *
   * @param dataGroupTag data group tag
   */
  protected DataGroup(int dataGroupTag) {
    super(dataGroupTag);
  }
  
  /**
   * Constructs a data group from the DER encoded data in the
   * given input stream. Tag and length are read, so the input stream
   * is positioned just before the value.
   *
   * @param dataGroupTag data group tag
   * @param inputStream an input stream
   *
   * @throws IOException on error reading input stream
   */
  protected DataGroup(int dataGroupTag, InputStream inputStream) throws IOException {
    super(dataGroupTag, inputStream);
  }
  
  /**
   * Gets a textual representation of this file.
   *
   * @return a textual representation of this file
   */
  public String toString() {
    return "DataGroup [" + Integer.toHexString(getTag()) + " (" + getLength() + ")]";
  }
}
