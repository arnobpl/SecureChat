package com.arnobpaul.common.crypto;

import com.arnobpaul.common.AppConfig;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class DiffieHellmanKeyExchangeTest {
    @Test
    void generateKey() throws Exception {
        DiffieHellmanKeyExchange diffieHellmanKeyExchange = new DiffieHellmanKeyExchange();
        AsymmetricKeyPair asymmetricKeyPair = diffieHellmanKeyExchange.generateKey(AppConfig.RSA_KEY_SIZE);
        diffieHellmanKeyExchange.generateKey(asymmetricKeyPair.publicKey);
    }

    @Test
    void getSharedSecretKey() throws Exception {
        DiffieHellmanKeyExchange diffieHellmanKeyExchange1 = new DiffieHellmanKeyExchange();
        AsymmetricKeyPair asymmetricKeyPair1 = diffieHellmanKeyExchange1.generateKey(AppConfig.RSA_KEY_SIZE);
        DiffieHellmanKeyExchange diffieHellmanKeyExchange2 = new DiffieHellmanKeyExchange();
        AsymmetricKeyPair asymmetricKeyPair2 = diffieHellmanKeyExchange2.generateKey(asymmetricKeyPair1.publicKey);
        Assertions.assertEquals(
                diffieHellmanKeyExchange1.getSharedSecretKey(asymmetricKeyPair1, asymmetricKeyPair2.publicKey),
                diffieHellmanKeyExchange2.getSharedSecretKey(asymmetricKeyPair2, asymmetricKeyPair1.publicKey));
    }
}