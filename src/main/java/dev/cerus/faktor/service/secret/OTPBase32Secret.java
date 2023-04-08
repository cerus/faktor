package dev.cerus.faktor.service.secret;

import dev.cerus.faktor.HMACAlgorithm;
import java.util.Arrays;
import java.util.Random;
import org.jetbrains.annotations.NotNull;

/**
 * Base32 OTPSecret implementation
 */
public class OTPBase32Secret implements OTPSecret {

    private final byte[] bytes;

    private OTPBase32Secret(final byte[] bytes) {
        this.bytes = bytes;
    }

    /**
     * Create a new Base32 otp secret from a byte array
     *
     * @param bytes The bytes of the secret
     *
     * @return the new OTPSecret instance
     *
     * @throws IllegalArgumentException if the secret is invalid
     */
    public static OTPSecret fromBytes(final byte[] bytes) {
        if (bytes.length != 20 && bytes.length != 32 && bytes.length != 64) {
            throw new IllegalArgumentException("Secrets can have one of the following lengths: 20, 32, 64");
        }
        return new OTPBase32Secret(bytes);
    }

    /**
     * Create a new Base32 otp secret from an encoded string
     *
     * @param secret The encoded secret
     *
     * @return the new OTPSecret instance
     *
     * @throws IllegalArgumentException if the encoded secret is invalid
     */
    public static OTPSecret fromString(final String secret) {
        if (secret.length() % 8 != 0 || secret.length() == 0) {
            throw new IllegalArgumentException("Not an encoded Base32 OTPSecret");
        }
        return fromBytes(base32Decode(secret));
    }

    /**
     * Generate a new Base32 otp secret
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

    private static byte[] base32Decode(final String encoded) {
        final byte[] data = new byte[determineOriginalSize(encoded)];
        final char[] chars = encoded.toCharArray();

        int bitIndex = 0;
        for (final char c : chars) {
            if (c == '=') {
                // Skip padding
                continue;
            }

            // Each character represents five bits of information. The character is mapped to its index in
            // the Base32 alphabet and the first five bits of that index are appended into the data array.

            // Convert the character to its index in the Base32 alphabet
            final int num = char2num(c);
            // Copy the first five bits of the index into the data array at the correct position
            for (int bit = 0; bit < 5; bit++) {
                if ((num & (1 << (4 - bit))) > 0) { // Check if the bit is set
                    final int byteIdx = bitIndex / 8;
                    final int byteBitIdx = bitIndex % 8;
                    data[byteIdx] |= (1 << (7 - byteBitIdx)); // Set the bit in the data array
                }
                bitIndex++;
            }
        }
        return data;
    }

    private static String base32Encode(final byte[] data) {
        final StringBuilder builder = new StringBuilder();
        int from = 0;
        int to = Math.min(5, data.length);
        // Split the array into 5 byte groups and encode each one separately
        while (from < data.length) {
            final byte[] group = Arrays.copyOfRange(data, from, to);
            builder.append(base32EncodeGroup(group));
            from += 5;
            to = Math.min(from + 5, data.length);
        }
        return builder.toString();
    }

    private static String base32EncodeGroup(final byte[] group) {
        final StringBuilder builder = new StringBuilder();

        // Encode the group
        // The 5 byte group is split into 5 bit groups. Each 5 bit group represents an index in the Base32
        // alphabet. The index is mapped into its corresponding character and appended to the output.
        int num = 0;
        for (int i = 0; i < 8 * 5; i++) {
            final int byteIdx = i / 8;
            final int bitIdx = i % 8;
            if (i != 0 && i % 5 == 0) {
                // We reached a new 5 bit group, append the previous one to the string
                builder.append(int2char(num));
                num = 0;
            }
            // If byte is present and current bit is set...
            if (byteIdx < group.length && (group[byteIdx] & (1 << (7 - bitIdx))) > 0) {
                // ...then set the bit in the current index number
                num |= (1 << (4 - (i % 5)));
            }
        }
        builder.append(int2char(num));

        // Set padding
        base32SetPadding(builder, group.length);

        return builder.toString();
    }

    // TODO: Move a more compact padding algorithm into base32EncodeGroup() and get rid of this
    private static void base32SetPadding(final StringBuilder builder, final int length) {
        switch (length) {
            case 1 -> builder.delete(2, builder.length()).append("=".repeat(6));
            case 2 -> builder.delete(4, builder.length()).append("=".repeat(4));
            case 3 -> builder.delete(5, builder.length()).append("=".repeat(3));
            case 4 -> builder.deleteCharAt(builder.length() - 1).append("=");
        }
    }

    private static char int2char(final int i) {
        if (i >= 0 && i <= 25) {
            return (char) ('A' + i);
        } else if (i >= 26 && i <= 31) {
            return (char) ('2' + (i - 26));
        }
        throw new IllegalArgumentException("Unrecognized Base32 number: " + i);
    }

    private static int char2num(final char c) {
        if (c >= 'A' && c <= 'Z') {
            return c - 'A';
        } else if (c >= '2' && c <= '7') {
            return ('Z' - 'A') + (c - '2') + 1;
        }
        throw new IllegalArgumentException("Unrecognized Base32 character: " + c);
    }

    private static int determineOriginalSize(final String s) {
        final int padding = countPadding(s);
        final int size = s.length() / 8 * 5;
        return size - switch (padding) {
            case 6 -> 4;
            case 4 -> 3;
            case 3 -> 2;
            case 1 -> 1;
            default -> 0;
        };
    }

    private static int countPadding(final String s) {
        final int idx = s.indexOf('=');
        return idx == -1 ? 0 : (s.length() - s.indexOf('='));
    }

    @Override
    public @NotNull String asString() {
        return base32Encode(this.bytes);
    }

    @Override
    public byte @NotNull [] asBytes() {
        return Arrays.copyOf(this.bytes, this.bytes.length);
    }

}
