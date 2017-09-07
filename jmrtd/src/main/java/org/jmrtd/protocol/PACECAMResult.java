package org.jmrtd.protocol;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.util.Arrays;

import org.jmrtd.lds.PACEInfo.MappingType;

import net.sf.scuba.util.Hex;

public class PACECAMResult extends PACEResult {

  private static final long serialVersionUID = -4288710920347109329L;

  private byte[] encryptedChipAuthenticationData;
  private byte[] chipAuthenticationData;

  public PACECAMResult(KeySpec paceKey,
      String agreementAlg, String cipherAlg, String digestAlg, int keyLength,
      PACEMappingResult mappingResult,
      KeyPair pcdKeyPair, PublicKey piccPublicKey,
      byte[] encryptedChipAuthenticationData, byte[] chipAuthenticationData, SecureMessagingWrapper wrapper) {
    super(paceKey, MappingType.CAM, agreementAlg, cipherAlg, digestAlg, keyLength, mappingResult, pcdKeyPair, piccPublicKey, wrapper);

    this.encryptedChipAuthenticationData = null;
    if (encryptedChipAuthenticationData != null) {
      this.encryptedChipAuthenticationData = new byte[encryptedChipAuthenticationData.length];
      System.arraycopy(encryptedChipAuthenticationData, 0, this.encryptedChipAuthenticationData, 0, encryptedChipAuthenticationData.length);
    }

    this.chipAuthenticationData = null;
    if (chipAuthenticationData != null) {
      this.chipAuthenticationData = new byte[chipAuthenticationData.length];
      System.arraycopy(chipAuthenticationData, 0, this.chipAuthenticationData, 0, chipAuthenticationData.length);
    }
  }

  public byte[] getEncryptedChipAuthenticationData() {
    if (encryptedChipAuthenticationData == null) {
      return null;
    }

    byte[] result = new byte[encryptedChipAuthenticationData.length];
    System.arraycopy(encryptedChipAuthenticationData, 0, result, 0, encryptedChipAuthenticationData.length);
    return result;
  }

  public byte[] getChipAuthenticationData() {
    if (chipAuthenticationData == null) {
      return null;
    }

    byte[] result = new byte[chipAuthenticationData.length];
    System.arraycopy(chipAuthenticationData, 0, result, 0, chipAuthenticationData.length);
    return result;
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = super.hashCode();
    result = prime * result + Arrays.hashCode(chipAuthenticationData);
    result = prime * result + Arrays.hashCode(encryptedChipAuthenticationData);
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (!super.equals(obj)) {
      return false;
    }
    if (getClass() != obj.getClass()) {
      return false;
    }

    PACECAMResult other = (PACECAMResult) obj;
    if (!Arrays.equals(chipAuthenticationData, other.chipAuthenticationData)) {
      return false;
    }
    if (!Arrays.equals(encryptedChipAuthenticationData, other.encryptedChipAuthenticationData)) {
      return false;
    }

    return true;
  }

  @Override
  public String toString() {
    return new StringBuilder()
        .append("PACECAMResult [")
        .append("paceKey: ").append(getPACEKey()).append(", ")
        .append("mappingType: ").append(getMappingType()).append(", ")
        .append("agreementAlg: ").append(getAgreementAlg()).append(", ")
        .append("cipherAlg: ").append(getCipherAlg()).append(", ")
        .append("digestAlg: ").append(getDigestAlg()).append(", ")
        .append("keyLength: ").append(getKeyLength()).append(", ")
        .append("mappingResult: ").append(getMappingResult()).append(", ")
        .append("pcdKeyPair: ").append(getPCDKeyPair()).append(", ")
        .append("piccPublicKey: ").append(getPICCPublicKey()).append(", ")
        .append("encryptedChipAuthenticationData: ").append(Hex.bytesToHexString(encryptedChipAuthenticationData)).append(", ")
        .append("wrapper: ").append(getWrapper()).append(", ")
        .append("chipAuthenticationData: ").append(Hex.bytesToHexString(chipAuthenticationData))
        .append("]").toString();
  }
}
