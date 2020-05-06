package com.arnobpaul.common.crypto;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static com.arnobpaul.common.AppConfig.DEFAULT_CHARSET;

/**
 * This class is for RSA signing, and verification.
 */
public class RsaSignVerify {
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final String KEY_ALGORITHM = "RSA";

    private final Signature signature;
    private final KeyFactory keyFactory;

    public RsaSignVerify() throws NoSuchAlgorithmException {
        signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
    }

    /**
     * @param text       text to sign
     * @param privateKey base64-encoded private key
     * @return base64-encoded signature of the text
     */
    public String sign(String text, String privateKey) throws InvalidKeySpecException, InvalidKeyException, SignatureException {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKey));
        signature.initSign(keyFactory.generatePrivate(keySpec));
        signature.update(text.getBytes(DEFAULT_CHARSET));
        return Base64.getEncoder().encodeToString(signature.sign());
    }

    /**
     * @param text          text to verify
     * @param signatureText base64-encoded signature of the text
     * @param publicKey     base64-encoded public key
     * @return true if verification result of the signature of the text succeeds
     */
    public boolean verify(String text, String signatureText, String publicKey) throws InvalidKeySpecException, InvalidKeyException, SignatureException {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKey));
        signature.initVerify(keyFactory.generatePublic(keySpec));
        signature.update(text.getBytes(DEFAULT_CHARSET));
        return signature.verify(Base64.getDecoder().decode(signatureText));
    }
}
