package org.jmrtd.protocol;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;

import org.jmrtd.SecureMessagingWrapper;
import org.jmrtd.lds.PACEInfo.MappingType;

public class PACEResult {
  
  private MappingType mappingType;
  private String agreementAlg;
  private String cipherAlg;
  private int keyLength;
  
  private byte[] piccNonce;
  private AlgorithmParameterSpec ephemeralParams;
  private KeyPair pcdKeyPair;
  private PublicKey piccPublicKey;
  private byte[] sharedSecretBytes;
  
  private SecureMessagingWrapper wrapper;
  
  public PACEResult(MappingType mappingType, String agreementAlg, String cipherAlg, int keyLength,
      byte[] piccNonce, AlgorithmParameterSpec ephemeralParams, KeyPair pcdKeyPair, PublicKey piccPublicKey,
      byte[] sharedSecretBytes, SecureMessagingWrapper wrapper) {
    this.mappingType = mappingType;
    this.agreementAlg = agreementAlg;
    this.cipherAlg = cipherAlg;
    this.keyLength = keyLength;
    this.piccNonce = piccNonce;
    this.ephemeralParams = ephemeralParams;
    this.pcdKeyPair = pcdKeyPair;
    this.piccPublicKey = piccPublicKey;
    this.sharedSecretBytes = sharedSecretBytes;
    this.wrapper = wrapper;
  }
  
  public SecureMessagingWrapper getWrapper() {
    return wrapper;
  }
  
  public MappingType getMappingType() {
    return mappingType;
  }

  public String getAgreementAlg() {
    return agreementAlg;
  }

  public String getCipherAlg() {
    return cipherAlg;
  }

  public int getKeyLength() {
    return keyLength;
  }

  public byte[] getPICCNonce() {
    return piccNonce;
  }

  public AlgorithmParameterSpec getEphemeralParams() {
    return ephemeralParams;
  }

  public KeyPair getPCDKeyPair() {
    return pcdKeyPair;
  }

  public PublicKey getPICCPublicKey() {
    return piccPublicKey;
  }

  public byte[] getSharedSecretBytes() {
    return sharedSecretBytes;
  }
}
