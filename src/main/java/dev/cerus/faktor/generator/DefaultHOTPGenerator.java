package dev.cerus.faktor.generator;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.jetbrains.annotations.NotNull;

/**
 * Default HOTPGenerator implementation
 */
public class DefaultHOTPGenerator implements HOTPGenerator {

    private static final int[] POWERS = new int[10];
    private static final String ALGO_SHA1 = "HmacSHA1";

    static {
        for (int i = 0; i < POWERS.length; i++) {
            POWERS[i] = (int) Math.floor(Math.pow(10, i + 1));
        }
    }

    @Override
    public int generateHOTP(final byte @NotNull [] secret, final long counter, final int digits) throws NoSuchAlgorithmException, InvalidKeyException {
        final byte[] hmacResult = this.hmac(secret, counter);
        return this.truncate(hmacResult, digits);
    }

    protected int truncate(final byte[] hmacResult, final int digits) {
        if (digits < 6 || digits > 10) {
            throw new IllegalArgumentException("Digits out of bounds, only 6 - 10 is supported");
        }
        final int dt = this.dynamicTruncation(hmacResult);
        return dt % POWERS[digits - 1];
    }

    protected byte[] hmac(final byte[] key, final long counter, final String algo) throws NoSuchAlgorithmException, InvalidKeyException {
        final byte[] data = ByteBuffer.allocate(8).putLong(counter).array();
        return this.hmac(key, data, algo);
    }

    protected byte[] hmac(final byte[] key, final long counter) throws NoSuchAlgorithmException, InvalidKeyException {
        final byte[] data = ByteBuffer.allocate(8).putLong(counter).array();
        return this.hmac(key, data, ALGO_SHA1);
    }

    protected byte[] hmac(final byte[] key, final byte[] data, final String algo) throws NoSuchAlgorithmException, InvalidKeyException {
        final SecretKeySpec secretKeySpec = new SecretKeySpec(key, algo);
        final Mac mac = Mac.getInstance(algo);
        mac.init(secretKeySpec);
        return mac.doFinal(data);
    }

    protected int dynamicTruncation(final byte[] hmacResult) {
        final int offset = hmacResult[hmacResult.length - 1] & 0xF;
        return (hmacResult[offset] & 0x7F) << 24
                | (hmacResult[offset + 1] & 0xFF) << 16
                | (hmacResult[offset + 2] & 0xFF) << 8
                | (hmacResult[offset + 3] & 0xFF);
    }

}
