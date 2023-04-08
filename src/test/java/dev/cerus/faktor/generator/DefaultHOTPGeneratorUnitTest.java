package dev.cerus.faktor.generator;

import java.util.Random;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.Test;

public class DefaultHOTPGeneratorUnitTest {

    private final HOTPGenerator generator = new DefaultHOTPGenerator();
    private final byte[] secret = new byte[20];

    public DefaultHOTPGeneratorUnitTest() {
        this.setup();
    }

    public void setup() {
        final Random random = new Random(1703 * 0xAFFE);
        random.nextBytes(this.secret);
    }

    @Test
    public void testGenerateHOTP() {
        assertDoesNotThrow(() -> {
            final int totp1 = this.generator.generateHOTP(this.secret, 1703, 6);
            final int totp2 = this.generator.generateHOTP(this.secret, 1703, 8);
            final int totp3 = this.generator.generateHOTP(this.secret, 1703, 10);
            assertEquals(199682, totp1);
            assertEquals(20199682, totp2);
            assertEquals(620199682, totp3);
        });
    }

}
