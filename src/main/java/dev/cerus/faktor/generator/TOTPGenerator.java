package dev.cerus.faktor.generator;

import dev.cerus.faktor.HMACAlgorithm;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;

/**
 * RFC 6238 compliant TOTP (Time-based one-time password) generator based on {@link HOTPGenerator}
 * <p>
 * See <a href="https://www.rfc-editor.org/rfc/rfc6238">RFC 6238</a>
 */
public interface TOTPGenerator extends HOTPGenerator {

    /**
     * Create a new {@link DefaultTOTPGenerator}
     *
     * @return a new {@link DefaultTOTPGenerator}
     */
    @Contract(value = "-> new", pure = true)
    static @NotNull TOTPGenerator newDefaultGenerator() {
        return new DefaultTOTPGenerator();
    }

    /**
     * Generates a TOTP for N time steps backwards
     * <p>
     * N = <code>backwardsSteps</code>
     * <p>
     * <code>timeReferenceMillis = timeReferenceMillis - (timeStepMillis * backwardsSteps)</code>
     * <p>
     * Implementations shall not cause visible side effects.
     *
     * @param secret              The secret (see {@link dev.cerus.faktor.service.secret.OTPSecret})
     * @param timeReferenceMillis The timestamp to generate the password for in millis
     * @param timeStepMillis      The lifetime of the password in millis
     * @param digits              The amount of digits the password should have
     * @param backwardsSteps      The amount of time steps to subtract from <code>timeReferenceMillis</code>
     * @param algo                The HMAC algorithm that should be used (SHA1 is most common)
     *
     * @return the generated TOTP
     *
     * @throws NoSuchAlgorithmException if the HMAC SHA1 algorithm can not be initialized
     * @throws InvalidKeyException      if the secret is invalid
     */
    @Contract(pure = true)
    default int generateTOTP(final byte @NotNull [] secret,
                             final long timeReferenceMillis,
                             final long timeStepMillis,
                             final int digits,
                             final int backwardsSteps,
                             @NotNull final HMACAlgorithm algo) throws NoSuchAlgorithmException, InvalidKeyException {
        final long millis = timeReferenceMillis - (timeStepMillis * backwardsSteps);
        return this.generateTOTP(secret, millis, timeStepMillis, digits, algo);
    }

    /**
     * Generates a TOTP based on the current timestamp
     * <p>
     * Implementations shall not cause visible side effects.
     *
     * @param secret         The secret (see {@link dev.cerus.faktor.service.secret.OTPSecret})
     * @param timeStepMillis The lifetime of the password in millis
     * @param digits         The amount of digits the password should have
     * @param algo           The HMAC algorithm that should be used (SHA1 is most common)
     *
     * @return the generated TOTP
     *
     * @throws NoSuchAlgorithmException if the HMAC SHA1 algorithm can not be initialized
     * @throws InvalidKeyException      if the secret is invalid
     */
    @Contract(pure = true)
    default int generateTOTP(final byte @NotNull [] secret,
                             final long timeStepMillis,
                             final int digits,
                             final HMACAlgorithm algo) throws NoSuchAlgorithmException, InvalidKeyException {
        return this.generateTOTP(secret, System.currentTimeMillis(), timeStepMillis, digits, algo);
    }

    /**
     * Generates a TOTP
     * <p>
     * Implementations shall not cause visible side effects.
     *
     * @param secret              The secret (see {@link dev.cerus.faktor.service.secret.OTPSecret})
     * @param timeReferenceMillis The timestamp to generate the password for in millis
     * @param timeStepMillis      The lifetime of the password in millis
     * @param digits              The amount of digits the password should have
     * @param algo                The HMAC algorithm that should be used (SHA1 is most common)
     *
     * @return the generated TOTP
     *
     * @throws NoSuchAlgorithmException if the HMAC SHA1 algorithm can not be initialized
     * @throws InvalidKeyException      if the secret is invalid
     */
    @Contract(pure = true)
    int generateTOTP(byte @NotNull [] secret,
                     long timeReferenceMillis,
                     long timeStepMillis,
                     int digits,
                     @NotNull HMACAlgorithm algo) throws NoSuchAlgorithmException, InvalidKeyException;

}
