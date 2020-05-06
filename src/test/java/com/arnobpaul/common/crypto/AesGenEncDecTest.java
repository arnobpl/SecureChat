package com.arnobpaul.common.crypto;

import com.arnobpaul.common.AppConfig;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.Random;

class AesGenEncDecTest {
    @Test
    void generateKey() throws Exception {
        AesGenEncDec aesGenEncDec = new AesGenEncDec();
        String key = aesGenEncDec.generateKey(AppConfig.AES_KEY_SIZE);
        Assertions.assertEquals(AppConfig.AES_KEY_SIZE, Base64.getDecoder().decode(key).length * 8);
    }

    @Test
    void encrypt() throws Exception {
        AesGenEncDec aesGenEncDec = new AesGenEncDec();
        String key = aesGenEncDec.generateKey(AppConfig.AES_KEY_SIZE);
        String plaintext = "$ABCD 1234.........";
        // testing non-deterministic encryption
        Assertions.assertNotEquals(
                aesGenEncDec.encrypt(plaintext, key),
                aesGenEncDec.encrypt(plaintext, key));
    }

    @Test
    void decrypt() throws Exception {
        AesGenEncDec aesGenEncDec1 = new AesGenEncDec();
        String key = aesGenEncDec1.generateKey(AppConfig.AES_KEY_SIZE);
        AesGenEncDec aesGenEncDec2 = new AesGenEncDec();
        Random random = new Random();
        for (int i = 0; i < 100; i++) {
            String plaintext = RandomStringUtils.randomAscii(random.nextInt(1000) + 1);
            String ciphertext = aesGenEncDec1.encrypt(plaintext, key);
            Assertions.assertEquals(plaintext, aesGenEncDec2.decrypt(ciphertext, key));
        }
    }
}