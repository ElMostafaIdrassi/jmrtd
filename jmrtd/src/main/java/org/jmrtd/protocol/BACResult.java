/*
 * JMRTD - A Java API for accessing machine readable travel documents.
 *
 * Copyright (C) 2006 - 2016  The JMRTD team
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
 * $Id: $
 */

package org.jmrtd.protocol;

import java.io.Serializable;

import org.jmrtd.BACKeySpec;
import org.jmrtd.SecureMessagingWrapper;

public class BACResult implements Serializable {
  
  private static final long serialVersionUID = -7114911372181772099L;
  
  private BACKeySpec bacKey;
  private SecureMessagingWrapper wrapper;
  
  public BACResult(SecureMessagingWrapper wrapper) {
    this(null, wrapper);
  }
  
  public BACResult(BACKeySpec bacKey, SecureMessagingWrapper wrapper) {
    this.bacKey = bacKey;
    this.wrapper = wrapper;
  }
  
  public BACKeySpec getBACKey() {
    return bacKey;
  }
  
  public SecureMessagingWrapper getWrapper() {
    return wrapper;
  }
  
  @Override
  public String toString() {
    return (new StringBuilder())
        .append("BACResult [bacKey: " + bacKey)
        .append(", wrapper: " + wrapper)
        .append("]")
        .toString();
  }
  
  @Override
  public int hashCode() {
    final int prime = 1234567891;
    int result = 1991;
    result = prime * result + ((bacKey == null) ? 0 : bacKey.hashCode());
    result = prime * result + ((wrapper == null) ? 0 : wrapper.hashCode());
    return result;
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
    
    BACResult other = (BACResult) obj;
    if (bacKey == null) {
      if (other.bacKey != null) {
        return false;
      }
    } else if (!bacKey.equals(other.bacKey)) {
      return false;
    }
    if (wrapper == null) {
      if (other.wrapper != null) {
        return false;
      }
    } else if (!wrapper.equals(other.wrapper)) {
      return false;
    }
    
    return true;
  }
}
