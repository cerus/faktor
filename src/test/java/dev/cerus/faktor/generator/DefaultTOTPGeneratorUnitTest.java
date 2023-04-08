package dev.cerus.faktor.generator;

import dev.cerus.faktor.HMACAlgorithm;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.Test;

public class DefaultTOTPGeneratorUnitTest {

    private final TOTPGenerator generator = new DefaultTOTPGenerator();
    private final byte[] secret = new byte[20];

    public DefaultTOTPGeneratorUnitTest() {
        this.setup();
    }

    public void setup() {
        final Random random = new Random(1703 * 0xAFFE);
        random.nextBytes(this.secret);
    }

    @Test
    public void testGenerateTOTP_Backwards() {
        final long timeStep = TimeUnit.SECONDS.toMillis(30);
        assertDoesNotThrow(() -> {
            final int totp1 = this.generator.generateTOTP(this.secret, 1703 * 100_000_000L, timeStep, 6, 0, HMACAlgorithm.SHA1);
            final int totp2 = this.generator.generateTOTP(this.secret, 1703 * 100_000_000L, timeStep, 6, 1, HMACAlgorithm.SHA1);
            final int totp3 = this.generator.generateTOTP(this.secret, 1703 * 100_000_000L, timeStep, 6, 2, HMACAlgorithm.SHA1);
            assertEquals(87492, totp1);
            assertEquals(372589, totp2);
            assertEquals(218863, totp3);
        });
    }

    @Test
    public void testGenerateTOTP_SHA1() {
        final long timeStep = TimeUnit.SECONDS.toMillis(30);
        assertDoesNotThrow(() -> {
            final int totp1 = this.generator.generateTOTP(this.secret, 1703 * 100_000_000L, timeStep, 6, HMACAlgorithm.SHA1);
            final int totp2 = this.generator.generateTOTP(this.secret, 1703 * 100_000_000L, timeStep, 8, HMACAlgorithm.SHA1);
            final int totp3 = this.generator.generateTOTP(this.secret, 1703 * 100_000_000L, timeStep, 10, HMACAlgorithm.SHA1);
            assertEquals(87492, totp1);
            assertEquals(50087492, totp2);
            assertEquals(1950087492, totp3);
        });
    }

    @Test
    public void testGenerateTOTP_SHA256() {
        final long timeStep = TimeUnit.SECONDS.toMillis(30);
        assertDoesNotThrow(() -> {
            final int totp1 = this.generator.generateTOTP(this.secret, 1703 * 100_000_000L, timeStep, 6, HMACAlgorithm.SHA256);
            final int totp2 = this.generator.generateTOTP(this.secret, 1703 * 100_000_000L, timeStep, 8, HMACAlgorithm.SHA256);
            final int totp3 = this.generator.generateTOTP(this.secret, 1703 * 100_000_000L, timeStep, 10, HMACAlgorithm.SHA256);
            assertEquals(962634, totp1);
            assertEquals(42962634, totp2);
            assertEquals(1142962634, totp3);
        });
    }

    @Test
    public void testGenerateTOTP_SHA512() {
        final long timeStep = TimeUnit.SECONDS.toMillis(30);
        assertDoesNotThrow(() -> {
            final int totp1 = this.generator.generateTOTP(this.secret, 1703 * 100_000_000L, timeStep, 6, HMACAlgorithm.SHA512);
            final int totp2 = this.generator.generateTOTP(this.secret, 1703 * 100_000_000L, timeStep, 8, HMACAlgorithm.SHA512);
            final int totp3 = this.generator.generateTOTP(this.secret, 1703 * 100_000_000L, timeStep, 10, HMACAlgorithm.SHA512);
            assertEquals(165612, totp1);
            assertEquals(23165612, totp2);
            assertEquals(1623165612, totp3);
        });
    }

}
