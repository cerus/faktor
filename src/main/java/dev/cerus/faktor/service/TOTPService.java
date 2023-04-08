package dev.cerus.faktor.service;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import org.jetbrains.annotations.Contract;

/**
 * Service for generating and validating TOTPs
 */
public interface TOTPService {

    @Contract(value = "-> new", pure = true)
    static DefaultTOTPService.Builder defaultServiceBuilder() {
        return DefaultTOTPService.builder();
    }

    /**
     * Validates a TOTP and wraps potential exceptions in a {@link RuntimeException}
     *
     * @param totp The TOTP to validate
     *
     * @return whether the provided TOTP is valid
     */
    default boolean validateTOTPUnchecked(final int totp) {
        try {
            return this.validateTOTP(totp);
        } catch (final NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Unable to validate TOTP", e);
        }
    }

    /**
     * Validates a TOTP
     *
     * @param totp The TOTP to validate
     *
     * @return whether the provided TOTP is valid
     *
     * @throws NoSuchAlgorithmException if the set HMAC SHA1 algorithm can not be initialized
     * @throws InvalidKeyException      if the set secret is invalid
     */
    boolean validateTOTP(int totp) throws NoSuchAlgorithmException, InvalidKeyException;

    /**
     * Generates a TOTP and wraps potential exceptions in a {@link RuntimeException}
     *
     * @return the generated TOTP
     */
    default int generateTOTPUnchecked() {
        try {
            return this.generateTOTP();
        } catch (final NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Unable to generate TOTP", e);
        }
    }

    /**
     * Generates a TOTP
     *
     * @return the generated TOTP
     *
     * @throws NoSuchAlgorithmException if the set HMAC SHA1 algorithm can not be initialized
     * @throws InvalidKeyException      if the set secret is invalid
     */
    int generateTOTP() throws NoSuchAlgorithmException, InvalidKeyException;

}
