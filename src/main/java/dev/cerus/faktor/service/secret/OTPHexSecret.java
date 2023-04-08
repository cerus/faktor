package dev.cerus.faktor.service.secret;

import dev.cerus.faktor.HMACAlgorithm;
import java.util.Arrays;
import java.util.Random;
import java.util.regex.Pattern;
import org.jetbrains.annotations.NotNull;

/**
 * Hex OTPSecret implementation
 */
public class OTPHexSecret implements OTPSecret {

    private static final String KEY_PATTERN_STRING = "([0-9a-fA-F]{40})|([0-9a-fA-F]{64})|([0-9a-fA-F]{128})";
    private static final Pattern KEY_PATTERN = Pattern.compile(KEY_PATTERN_STRING);

    private final byte[] bytes;

    private OTPHexSecret(final byte[] bytes) {
        this.bytes = bytes;
    }

    /**
     * Create a new Hex otp secret from a byte array
     *
     * @param bytes The bytes of the secret
     *
     * @return the new OTPSecret instance
     */
    public static OTPSecret fromBytes(final byte[] bytes) {
        if (bytes.length != 20 && bytes.length != 32 && bytes.length != 64) {
            throw new IllegalArgumentException("Secrets can have one of the following lengths: 20, 32, 64");
        }
        return new OTPHexSecret(bytes);
    }

    /**
     * Create a new Hex otp secret from an encoded string
     *
     * @param secret The encoded secret
     *
     * @return the new OTPSecret instance
     */
    public static OTPSecret fromString(final @org.intellij.lang.annotations.Pattern(value = KEY_PATTERN_STRING) String secret) {
        if (!KEY_PATTERN.matcher(secret).matches()) {
            throw new IllegalArgumentException("Not an encoded Hex OTPSecret");
        }

        final byte[] bytes = new byte[secret.length() / 2];
        final char[] chars = secret.toCharArray();
        for (int i = 0; i < chars.length; i++) {
            final int num = charToHex(chars[i++]) * 16 + charToHex(chars[i]);
            bytes[i / 2] = (byte) num;
        }
        return fromBytes(bytes);
    }

    /**
     * Generate a new Hex otp secret
     *
     * @param algo   The HMAC algorithm to use
     * @param random The random instance to use
     *
     * @return the new OTPSecret instance
     */
    public static OTPSecret generate(final HMACAlgorithm algo, final Random random) {
        final byte[] key = new byte[algo.byteAmount()];
        random.nextBytes(key);
        return fromBytes(key);
    }

    private static int charToHex(final char c) {
        if (c <= '9') {
            return c - '0';
        } else if (c <= 'F') {
            return 10 + (c - 'A');
        } else if (c <= 'f') {
            return 10 + (c - 'a');
        }
        throw new IllegalArgumentException("Not a hex char: " + c);
    }

    @Override
    public @NotNull String asString() {
        final StringBuilder builder = new StringBuilder();
        for (final byte b : this.bytes) {
            builder.append(String.format("%2X", b).replace(' ', '0'));
        }
        return builder.toString();
    }

    @Override
    public byte @NotNull [] asBytes() {
        return Arrays.copyOf(this.bytes, this.bytes.length);
    }

}
