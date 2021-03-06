package com.arnobpaul.common.crypto;

import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.interfaces.DHPublicKey;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class DiffieHellmanKeyExchange {
    private final static String ALGORITHM = "DH";

    private final KeyPairGenerator keyPairGenerator;
    private final KeyFactory keyFactory;
    private final KeyAgreement keyAgreement;

    public DiffieHellmanKeyExchange() throws NoSuchAlgorithmException, NoSuchPaddingException {
        keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        keyFactory = KeyFactory.getInstance(ALGORITHM);
        keyAgreement = KeyAgreement.getInstance(ALGORITHM);
    }

    public AsymmetricKeyPair generateKey(int keySize) {
        keyPairGenerator.initialize(keySize);
        java.security.KeyPair keyPair = keyPairGenerator.generateKeyPair();

        return new AsymmetricKeyPair(
                Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()),
                Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
    }

    /**
     * @param otherPublicKey base64-encoded public key from the other party
     * @return asymmetric key pair
     */
    public AsymmetricKeyPair generateKey(String otherPublicKey) throws InvalidKeySpecException, InvalidAlgorithmParameterException {
        keyPairGenerator.initialize(((DHPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(otherPublicKey)))).getParams());
        java.security.KeyPair keyPair = keyPairGenerator.generateKeyPair();

        return new AsymmetricKeyPair(
                Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()),
                Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
    }

    /**
     * @param ownKeyPair     asymmetric key pair generated by oneself
     * @param otherPublicKey base64-encoded public key from the other party
     * @return base64-encoded shared secret key
     */
    public String getSharedSecretKey(AsymmetricKeyPair ownKeyPair, String otherPublicKey) throws InvalidKeySpecException, InvalidKeyException {
        keyAgreement.init(keyFactory.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(ownKeyPair.privateKey))));
        keyAgreement.doPhase(keyFactory.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(otherPublicKey))), true);
        return Base64.getEncoder().encodeToString(keyAgreement.generateSecret());
    }
}
