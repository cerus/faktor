package dev.cerus.faktor.generator;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;

/**
 * RFC 4226 compliant HOTP (HMAC-based one-time password) generator
 * <p>
 * See <a href="https://www.rfc-editor.org/rfc/rfc4226">RFC 4226</a>
 */
public interface HOTPGenerator {

    /**
     * Create a new {@link DefaultHOTPGenerator}
     *
     * @return a new {@link DefaultHOTPGenerator}
     */
    @Contract(value = "-> new", pure = true)
    static HOTPGenerator newDefaultGenerator() {
        return new DefaultHOTPGenerator();
    }

    /**
     * Generates a HOTP based on the provided parameters
     * <p>
     * Implementations shall not cause visible side effects.
     *
     * @param secret  The secret (see {@link dev.cerus.faktor.service.secret.OTPSecret})
     * @param counter The counter value
     * @param digits  The amount of digits the password should have
     *
     * @return the generated HOTP
     *
     * @throws NoSuchAlgorithmException if the HMAC SHA1 algorithm can not be initialized
     * @throws InvalidKeyException      if the secret is invalid
     */
    @Contract(pure = true)
    int generateHOTP(byte @NotNull [] secret, long counter, int digits) throws NoSuchAlgorithmException, InvalidKeyException;

}
