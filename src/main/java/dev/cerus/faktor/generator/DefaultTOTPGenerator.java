package dev.cerus.faktor.generator;

import dev.cerus.faktor.HMACAlgorithm;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import org.jetbrains.annotations.NotNull;

/**
 * Default TOTPGenerator implementation
 */
public class DefaultTOTPGenerator extends DefaultHOTPGenerator implements TOTPGenerator {

    @Override
    public int generateTOTP(final byte @NotNull [] secret, final long timeReferenceMillis, final long timeStepMillis, final int digits, final @NotNull HMACAlgorithm algo) throws NoSuchAlgorithmException, InvalidKeyException {
        final String algoString = "Hmac" + algo.name();
        final long counter = timeReferenceMillis / timeStepMillis;
        final byte[] hmacResult = this.hmac(secret, counter, algoString);
        return this.truncate(hmacResult, digits);
    }

}
