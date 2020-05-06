package com.arnobpaul.common.crypto;

public class AsymmetricKeyPair {
    public final String publicKey;
    public final String privateKey;

    /**
     * @param publicKey  base64-encoded public key
     * @param privateKey base64-encoded private key
     */
    public AsymmetricKeyPair(String publicKey, String privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }
}
