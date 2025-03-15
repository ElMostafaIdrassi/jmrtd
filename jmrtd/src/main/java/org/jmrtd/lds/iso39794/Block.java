package org.jmrtd.lds.iso39794;

import java.io.IOException;
import java.io.Serializable;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1Encodable;

abstract class Block implements Serializable {

  private static final long serialVersionUID = -8585852930916738115L;

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd.lds.iso39794");

  abstract ASN1Encodable getASN1Object();

  public byte[] getEncoded() {
    try {
      return getASN1Object().toASN1Primitive().getEncoded("DER");
    } catch (IOException ioe) {
      LOGGER.log(Level.WARNING, "Error decoding", ioe);
      return null;
    }
  }

  @Override
  public abstract int hashCode();

  @Override
  public abstract boolean equals(Object other);
}
