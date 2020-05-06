package com.arnobpaul.common.crypto;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static com.arnobpaul.common.AppConfig.DEFAULT_CHARSET;

/**
 * This class is for AES generation, encryption, and decryption.
 */
public class AesGenEncDec {
    private final static String ALGORITHM = "AES";
    private final static String ALGORITHM_FULL = "AES/CBC/PKCS5Padding";

    private final static String IV_SEPARATOR = ":";

    private final KeyGenerator keyGenerator;
    private final Cipher cipher;

    public AesGenEncDec() throws NoSuchAlgorithmException, NoSuchPaddingException {
        keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        cipher = Cipher.getInstance(ALGORITHM_FULL);
    }

    /**
     * @param keySize key size in bits
     * @return base64-encoded key
     */
    public String generateKey(int keySize) {
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();
        System.out.println("Key size: " + secretKey.getEncoded().length);
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    /**
     * @param plaintext plaintext to encrypt
     * @param key       base64-encoded key
     * @return encrypted ciphertext
     */
    public String encrypt(String plaintext, String key) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        cipher.init(Cipher.ENCRYPT_MODE,
                new SecretKeySpec(Base64.getDecoder().decode(key), ALGORITHM));
        String iv = Base64.getEncoder().encodeToString(cipher.getIV());
        return iv + IV_SEPARATOR + Base64.getEncoder().encodeToString(cipher.doFinal(plaintext.getBytes(DEFAULT_CHARSET)));
    }

    /**
     * @param ciphertext ciphertext to decrypt
     * @param key        base64-encoded key
     * @return decrypted plaintext
     */
    public String decrypt(String ciphertext, String key) throws InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        String[] ciphertextItems = ciphertext.split(":", 2);
        if (ciphertextItems.length != 2) {
            throw new InvalidKeyException("IV is not found.");
        }
        String iv = ciphertextItems[0];
        String ciphertextPart = ciphertextItems[1];
        cipher.init(Cipher.DECRYPT_MODE,
                new SecretKeySpec(Base64.getDecoder().decode(key), ALGORITHM),
                new IvParameterSpec(Base64.getDecoder().decode(iv)));
        return new String(cipher.doFinal(Base64.getDecoder().decode(ciphertextPart)), DEFAULT_CHARSET);
    }
}
