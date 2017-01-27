package org.jmrtd.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.logging.Logger;

public class ResourceUtil {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  public static byte[] getBytes(String resource) throws IOException {
    InputStream is = getInputStream(resource);
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    int nRead;
    byte[] data = new byte[16384];
    while ((nRead = is.read(data, 0, data.length)) != -1) {
      buffer.write(data, 0, nRead);
    }
    buffer.flush();
    return buffer.toByteArray();
  }

  public static InputStream getInputStream(String resource) {
    InputStream inputStream = null;
    URL url = ResourceUtil.class.getResource(resource);
    /* NOTE: getResourceAsStream() is preferred over openConnection on URL. */
    inputStream = ResourceUtil.class.getResourceAsStream(resource);
    return inputStream;
  }
}
