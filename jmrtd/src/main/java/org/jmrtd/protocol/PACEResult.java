package org.jmrtd.protocol;

import org.jmrtd.SecureMessagingWrapper;

public class PACEResult {

  private SecureMessagingWrapper wrapper;
  
  public PACEResult(SecureMessagingWrapper wrapper) {
    this.wrapper = wrapper;
  }

  public SecureMessagingWrapper getWrapper() {
    return wrapper;
  }
}
