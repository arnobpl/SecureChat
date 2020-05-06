package com.arnobpaul.common.crypto;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static com.arnobpaul.common.AppConfig.DEFAULT_CHARSET;

public class HmacGenerateVerify {
    private static final String ALGORITHM = "HMACSHA256";

    private final Mac mac;

    public HmacGenerateVerify() throws NoSuchAlgorithmException {
        mac = Mac.getInstance(ALGORITHM);
    }

    /**
     * @param text text to sign
     * @param key  base64-encoded key
     * @return base64-encoded signature of the text
     */
    public String generateTag(String text, String key) throws InvalidKeyException {
        mac.init(new SecretKeySpec(Base64.getDecoder().decode(key), ALGORITHM));
        return Base64.getEncoder().encodeToString(mac.doFinal(text.getBytes(DEFAULT_CHARSET)));
    }

    /**
     * @param text text to verify
     * @param tag  base64-encoded tag of the text
     * @param key  base64-encoded key
     * @return true if verification result of the tag of the text succeeds
     */
    public boolean verifyTag(String text, String tag, String key) throws InvalidKeyException {
        return (tag != null && tag.equals(generateTag(text, key)));
    }
}
