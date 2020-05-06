package com.arnobpaul.common;

import java.util.Base64;
import java.util.Random;

public class RandomGeneratorHelper {
    // Here SecureRandom is not used because SecureRandom does not produce deterministic values even if a same seed is set.
    private final Random random;

    public RandomGeneratorHelper(String seed) {
        this.random = new Random();

        byte[] seedBytes = seed.getBytes(AppConfig.DEFAULT_CHARSET);
        long seedLong = 1;
        for (int i = 0; i < seedBytes.length; i++) {
            long byteLong = seedBytes[i];
            seedLong += (byteLong * (i + 1));
        }

        random.setSeed(seedLong);
    }

    public String nextBase64String(int byteSize) {
        byte[] randomBytes = new byte[byteSize];
        random.nextBytes(randomBytes);
        return Base64.getEncoder().encodeToString(randomBytes);
    }
}
