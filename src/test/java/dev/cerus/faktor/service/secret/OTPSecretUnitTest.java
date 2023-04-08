package dev.cerus.faktor.service.secret;

import dev.cerus.faktor.HMACAlgorithm;
import dev.cerus.faktor.service.secret.mock.MockOTPSecret;
import java.util.Random;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class OTPSecretUnitTest {

    private Random random;

    @BeforeEach
    public void beforeEach() {
        this.random = new Random(1703 * 0xAFFE);
    }

    @Test
    public void testGenerateHexSecretSHA1() {
        final OTPSecret secret = OTPSecret.generateHexSecret(HMACAlgorithm.SHA1, this.random);
        assertArrayEquals(new byte[] {106, -68, 105, -51, -5, -66, 74, 95, 111, 119, -94, -60, 40, -59, 55, -15, 73, -97, -105, 69}, secret.asBytes());
        assertEquals("6ABC69CDFBBE4A5F6F77A2C428C537F1499F9745", secret.asString());
    }

    @Test
    public void testGenerateHexSecretSHA256() {
        final OTPSecret secret = OTPSecret.generateHexSecret(HMACAlgorithm.SHA256, this.random);
        assertArrayEquals(new byte[] {106, -68, 105, -51, -5, -66, 74, 95, 111, 119, -94, -60, 40, -59, 55, -15, 73, -97, -105, 69, -66, -84, -56, 104, 118, 41, 125, -65, -1, -100, 9, 87}, secret.asBytes());
        assertEquals("6ABC69CDFBBE4A5F6F77A2C428C537F1499F9745BEACC86876297DBFFF9C0957", secret.asString());
    }

    @Test
    public void testGenerateHexSecretSHA512() {
        final OTPSecret secret = OTPSecret.generateHexSecret(HMACAlgorithm.SHA512, this.random);
        assertArrayEquals(new byte[] {106, -68, 105, -51, -5, -66, 74, 95, 111, 119, -94, -60, 40, -59, 55, -15, 73, -97, -105, 69, -66, -84, -56, 104, 118, 41, 125, -65, -1, -100, 9, 87, 14, 15, 55, 122, 5, -33, 7, 121, -95, 106, 84, 3, -59, -78, 1, 58, 77, 44, -11, 49, -79, -125, 98, 28, -123, -8, 37, 71, 94, 29, 47, 77}, secret.asBytes());
        assertEquals("6ABC69CDFBBE4A5F6F77A2C428C537F1499F9745BEACC86876297DBFFF9C09570E0F377A05DF0779A16A5403C5B2013A4D2CF531B183621C85F825475E1D2F4D", secret.asString());
    }

    @Test
    public void testGenerateBase32SecretSHA1() {
        final OTPSecret secret = OTPSecret.generateBase32Secret(HMACAlgorithm.SHA1, this.random);
        assertArrayEquals(new byte[] {106, -68, 105, -51, -5, -66, 74, 95, 111, 119, -94, -60, 40, -59, 55, -15, 73, -97, -105, 69}, secret.asBytes());
        assertEquals("NK6GTTP3XZFF633XULCCRRJX6FEZ7F2F", secret.asString());
    }

    @Test
    public void testGenerateBase32SecretSHA256() {
        final OTPSecret secret = OTPSecret.generateBase32Secret(HMACAlgorithm.SHA256, this.random);
        assertArrayEquals(new byte[] {106, -68, 105, -51, -5, -66, 74, 95, 111, 119, -94, -60, 40, -59, 55, -15, 73, -97, -105, 69, -66, -84, -56, 104, 118, 41, 125, -65, -1, -100, 9, 87}, secret.asBytes());
        assertEquals("NK6GTTP3XZFF633XULCCRRJX6FEZ7F2FX2WMQ2DWFF637744BFLQ====", secret.asString());
    }

    @Test
    public void testGenerateBase32SecretSHA512() {
        final OTPSecret secret = OTPSecret.generateBase32Secret(HMACAlgorithm.SHA512, this.random);
        assertArrayEquals(new byte[] {106, -68, 105, -51, -5, -66, 74, 95, 111, 119, -94, -60, 40, -59, 55, -15, 73, -97, -105, 69, -66, -84, -56, 104, 118, 41, 125, -65, -1, -100, 9, 87, 14, 15, 55, 122, 5, -33, 7, 121, -95, 106, 84, 3, -59, -78, 1, 58, 77, 44, -11, 49, -79, -125, 98, 28, -123, -8, 37, 71, 94, 29, 47, 77}, secret.asBytes());
        assertEquals("NK6GTTP3XZFF633XULCCRRJX6FEZ7F2FX2WMQ2DWFF637744BFLQ4DZXPIC56B3ZUFVFIA6FWIATUTJM6UY3DA3CDSC7QJKHLYOS6TI=", secret.asString());
    }

    @Test
    public void testFromBytesHex() {
        final byte[] secretData = new byte[20];
        this.random.nextBytes(secretData);
        final OTPHexSecret secret = OTPSecret.fromBytes(OTPHexSecret.class, secretData);
        assertSame(secret.getClass(), OTPHexSecret.class);
        assertArrayEquals(secret.asBytes(), secretData);
    }

    @Test
    public void testFromBytesBase32() {
        final byte[] secretData = new byte[20];
        this.random.nextBytes(secretData);
        final OTPBase32Secret secret = OTPSecret.fromBytes(OTPBase32Secret.class, secretData);
        assertSame(secret.getClass(), OTPBase32Secret.class);
        assertArrayEquals(secret.asBytes(), secretData);
    }

    @Test
    public void testFromBytesInvalid() {
        final byte[] secretData = new byte[20];
        this.random.nextBytes(secretData);
        assertThrows(UnsupportedOperationException.class, () -> OTPSecret.fromBytes(MockOTPSecret.class, secretData));
    }

    @Test
    public void testFromStringHex() {
        final String encoded = "0102030405060708091011121314151617181920";
        final OTPHexSecret secret = OTPSecret.fromString(OTPHexSecret.class, encoded);
        assertSame(secret.getClass(), OTPHexSecret.class);
        assertEquals(secret.asString(), encoded);
    }

    @Test
    public void testFromStringBase32() {
        final String encoded = "AEBAGBAFAYDQQCIQCEJBGFAVCYLRQGJA";
        final OTPBase32Secret secret = OTPSecret.fromString(OTPBase32Secret.class, encoded);
        assertSame(secret.getClass(), OTPBase32Secret.class);
        assertEquals(secret.asString(), encoded);
    }

    @Test
    public void testFromStringInvalid() {
        final String encoded = "invalid data";
        assertThrows(UnsupportedOperationException.class, () -> OTPSecret.fromString(MockOTPSecret.class, encoded));
    }

}
