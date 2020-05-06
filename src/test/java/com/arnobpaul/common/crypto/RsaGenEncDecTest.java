package com.arnobpaul.common.crypto;

import com.arnobpaul.common.AppConfig;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Random;

class RsaGenEncDecTest {
    @Test
    void generateKey() throws Exception {
        RsaGenEncDec rsaGenEncDec = new RsaGenEncDec();
        rsaGenEncDec.generateKey(AppConfig.RSA_KEY_SIZE);
    }

    @Test
    void encrypt() throws Exception {
        RsaGenEncDec rsaGenEncDec = new RsaGenEncDec();
        AsymmetricKeyPair keyPair = rsaGenEncDec.generateKey(AppConfig.RSA_KEY_SIZE);
        String plaintext = "$ABCD 1234.........";
        // testing non-deterministic encryption
        Assertions.assertNotEquals(
                rsaGenEncDec.encrypt(plaintext, keyPair.publicKey),
                rsaGenEncDec.encrypt(plaintext, keyPair.publicKey));
    }

    @Test
    void decrypt() throws Exception {
        RsaGenEncDec rsaGenEncDec1 = new RsaGenEncDec();
        AsymmetricKeyPair keyPair = rsaGenEncDec1.generateKey(AppConfig.RSA_KEY_SIZE);
        RsaGenEncDec rsaGenEncDec2 = new RsaGenEncDec();
        Random random = new Random();
        for (int i = 0; i < 100; i++) {
            String plaintext = RandomStringUtils.randomAscii(random.nextInt(100) + 1);
            String ciphertext = rsaGenEncDec1.encrypt(plaintext, keyPair.publicKey);
            Assertions.assertEquals(plaintext, rsaGenEncDec2.decrypt(ciphertext, keyPair.privateKey));
        }
    }
}