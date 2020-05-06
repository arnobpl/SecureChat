package com.arnobpaul.common.crypto;

import com.arnobpaul.common.AppConfig;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class RsaSignVerifyTest {
    @Test
    void sign() throws Exception {
        RsaSignVerify rsaSignVerify = new RsaSignVerify();
        RsaGenEncDec rsaGenEncDec = new RsaGenEncDec();
        AsymmetricKeyPair asymmetricKeyPair = rsaGenEncDec.generateKey(AppConfig.RSA_KEY_SIZE);
        String text = "$ABCD 1234.........";
        Assertions.assertEquals(
                rsaSignVerify.sign(text, asymmetricKeyPair.privateKey),
                rsaSignVerify.sign(text, asymmetricKeyPair.privateKey));
    }

    @Test
    void verify() throws Exception {
        RsaSignVerify rsaSignVerify1 = new RsaSignVerify();
        RsaGenEncDec rsaGenEncDec = new RsaGenEncDec();
        AsymmetricKeyPair asymmetricKeyPair = rsaGenEncDec.generateKey(AppConfig.RSA_KEY_SIZE);
        String text = "$ABCD 1234.........";
        String signature = rsaSignVerify1.sign(text, asymmetricKeyPair.privateKey);
        RsaSignVerify rsaSignVerify2 = new RsaSignVerify();
        Assertions.assertTrue(rsaSignVerify2.verify(text, signature, asymmetricKeyPair.publicKey));
    }
}