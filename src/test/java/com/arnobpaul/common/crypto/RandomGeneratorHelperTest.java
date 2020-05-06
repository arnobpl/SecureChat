package com.arnobpaul.common.crypto;

import com.arnobpaul.common.RandomGeneratorHelper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class RandomGeneratorHelperTest {

    @Test
    void nextBase64String() {
        String seed = "SEED";
        RandomGeneratorHelper randomGeneratorHelper1 = new RandomGeneratorHelper(seed);
        RandomGeneratorHelper randomGeneratorHelper2 = new RandomGeneratorHelper(seed);
        for (int i = 0; i < 100; i++) {
            Assertions.assertEquals(
                    randomGeneratorHelper1.nextBase64String(1024),
                    randomGeneratorHelper2.nextBase64String(1024));
        }
    }
}