package dev.cerus.faktor.service.secret;

import dev.cerus.faktor.HMACAlgorithm;
import java.util.Random;
import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;

/**
 * Represents a master secret for one-time-password generation and validation
 */
public interface OTPSecret {

    /**
     * Generate a new secret in Hex format
     *
     * @param algo   The algorithm to generate the key with
     * @param random The Random-instance to use when generating the key (Instance of {@link java.security.SecureRandom} recommended)
     *
     * @return a new otp secret in Hex format
     */
    @Contract("_, _ -> new")
    static OTPSecret generateHexSecret(final @NotNull HMACAlgorithm algo, final @NotNull Random random) {
        return OTPHexSecret.generate(algo, random);
    }

    /**
     * Generate a new secret in Base32 format
     *
     * @param algo   The algorithm to generate the key with
     * @param random The Random-instance to use when generating the key (Instance of {@link java.security.SecureRandom} recommended)
     *
     * @return a new otp secret in Base32 format
     */
    @Contract("_, _ -> new")
    static OTPSecret generateBase32Secret(final @NotNull HMACAlgorithm algo, final @NotNull Random random) {
        return OTPBase32Secret.generate(algo, random);
    }

    /**
     * Convert a raw byte array to an otp secret
     *
     * @param cls   The class of the OTPSecret implementation
     * @param bytes The raw secret
     * @param <T>   The OTPSecret type
     *
     * @return a new OTPSecret instance of the provided implementation class
     */
    @Contract(value = "_, _ -> new", pure = true)
    static <T extends OTPSecret> T fromBytes(final @NotNull Class<T> cls, final byte @NotNull [] bytes) {
        if (cls == OTPHexSecret.class) {
            return (T) OTPHexSecret.fromBytes(bytes);
        }
        if (cls == OTPBase32Secret.class) {
            return (T) OTPBase32Secret.fromBytes(bytes);
        }
        throw new UnsupportedOperationException("Unknown OTPSecret implementation");
    }

    /**
     * Convert an encoded secret to an otp secret
     *
     * @param cls    The class of the OTPSecret implementation
     * @param string The encoded secret
     * @param <T>    The OTPSecret type
     *
     * @return a new OTPSecret instance of the provided implementation class
     */
    @Contract(value = "_, _ -> new", pure = true)
    static <T extends OTPSecret> T fromString(final @NotNull Class<T> cls, final @NotNull String string) {
        if (cls == OTPHexSecret.class) {
            return (T) OTPHexSecret.fromString(string);
        }
        if (cls == OTPBase32Secret.class) {
            return (T) OTPBase32Secret.fromString(string);
        }
        throw new UnsupportedOperationException("Unknown OTPSecret implementation");
    }

    /**
     * Encode the secret into a string
     *
     * @return the encoded secret
     */
    @NotNull String asString();

    /**
     * Get the raw bytes of the secret
     * <p>
     * Implementations should always return a copy of the secret.
     *
     * @return the bytes of the secret
     */
    byte @NotNull [] asBytes();

}
