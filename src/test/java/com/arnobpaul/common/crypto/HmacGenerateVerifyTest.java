package com.arnobpaul.common.crypto;

import com.arnobpaul.common.AppConfig;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class HmacGenerateVerifyTest {
    @Test
    void generateTag() throws Exception {
        HmacGenerateVerify hmacGenerateVerify = new HmacGenerateVerify();
        AesGenEncDec aesGenEncDec = new AesGenEncDec();
        String key = aesGenEncDec.generateKey(AppConfig.AES_KEY_SIZE);
        String text = "$ABCD 1234.........";
        Assertions.assertEquals(
                hmacGenerateVerify.generateTag(text, key),
                hmacGenerateVerify.generateTag(text, key));
    }

    @Test
    void verifyTag() throws Exception {
        HmacGenerateVerify hmacGenerateVerify1 = new HmacGenerateVerify();
        AesGenEncDec aesGenEncDec = new AesGenEncDec();
        String key = aesGenEncDec.generateKey(AppConfig.AES_KEY_SIZE);
        String text = "$ABCD 1234.........";
        String tag = hmacGenerateVerify1.generateTag(text, key);
        HmacGenerateVerify hmacGenerateVerify2 = new HmacGenerateVerify();
        Assertions.assertTrue(hmacGenerateVerify2.verifyTag(text, tag, key));
    }
}