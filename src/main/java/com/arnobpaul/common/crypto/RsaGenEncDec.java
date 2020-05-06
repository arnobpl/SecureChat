package com.arnobpaul.common.crypto;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static com.arnobpaul.common.AppConfig.DEFAULT_CHARSET;

/**
 * This class is for RSA generation, encryption, and decryption.
 */
public class RsaGenEncDec {
    private final static String ALGORITHM = "RSA";

    private final KeyPairGenerator keyPairGenerator;
    private final Cipher cipher;
    private final KeyFactory keyFactory;

    public RsaGenEncDec() throws NoSuchAlgorithmException, NoSuchPaddingException {
        keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        cipher = Cipher.getInstance(ALGORITHM);
        keyFactory = KeyFactory.getInstance(ALGORITHM);
    }

    public AsymmetricKeyPair generateKey(int keySize) {
        keyPairGenerator.initialize(keySize);
        java.security.KeyPair keyPair = keyPairGenerator.generateKeyPair();

        return new AsymmetricKeyPair(
                Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()),
                Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
    }

    /**
     * @param plaintext plaintext to encrypt
     * @param publicKey base64-encoded public key
     * @return encrypted ciphertext
     */
    public String encrypt(String plaintext, String publicKey) throws InvalidKeySpecException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        cipher.init(Cipher.ENCRYPT_MODE,
                keyFactory.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(publicKey))));
        return Base64.getEncoder().encodeToString(cipher.doFinal(plaintext.getBytes(DEFAULT_CHARSET)));
    }

    /**
     * @param ciphertext ciphertext to decrypt
     * @param privateKey base64-encoded private key
     * @return decrypted plaintext
     */
    public String decrypt(String ciphertext, String privateKey) throws InvalidKeySpecException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        cipher.init(Cipher.DECRYPT_MODE,
                keyFactory.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKey))));
        return new String(cipher.doFinal(Base64.getDecoder().decode(ciphertext)), DEFAULT_CHARSET);
    }
}
