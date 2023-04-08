package dev.cerus.faktor.service.secret;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.Test;

public class OTPHexSecretUnitTest {

    @Test
    public void testFromBytes20() {
        final byte[] secretInBytes = new byte[] {-107, -50, -97, -57, 8, 85, -68, 5, -27, -67, -3, -90, 8, -97, -45, -128, -3, -7, 62, -71};
        final String secretAsString = "95CE9FC70855BC05E5BDFDA6089FD380FDF93EB9";

        final OTPSecret secret = OTPHexSecret.fromBytes(secretInBytes);
        assertArrayEquals(secretInBytes, secret.asBytes(), "OTPHexSecret#asBytes() should be equal to the raw secret");
        assertEquals(secretAsString, secret.asString(), "OTPHexSecret#asString() should be equal to the encoded secret");
    }

    @Test
    public void testFromBytes32() {
        final byte[] secretInBytes = new byte[] {115, 104, 32, 86, 118, 66, -62, 72, 51, 39, -122, 116, 106, 51, -60, -99, -47, -6, 80, 14, 10, 75, -7, -95, -67, 94, -92, -9, 22, -91, 46, 63};
        final String secretAsString = "736820567642C248332786746A33C49DD1FA500E0A4BF9A1BD5EA4F716A52E3F";

        final OTPSecret secret = OTPHexSecret.fromBytes(secretInBytes);
        assertArrayEquals(secretInBytes, secret.asBytes(), "OTPHexSecret#asBytes() should be equal to the raw secret");
        assertEquals(secretAsString, secret.asString(), "OTPHexSecret#asString() should be equal to the encoded secret");
    }

    @Test
    public void testFromBytes64() {
        final byte[] secretInBytes = new byte[] {-127, -39, -45, 110, -25, 97, -56, 47, 36, -6, 64, 76, -4, 1, 31, -113, -102, -37, 36, -111, 117, -89, -19, 53, 121, -91, 115, 17, 114, 73, 89, 53, -93, 99, 62, -96, 102, -75, 24, -38, -81, 45, 28, 85, -126, 86, 118, 61, 37, -101, 113, -3, -71, 68, 65, 84, 37, -112, 69, 90, -33, -127, -114, -103};
        final String secretAsString = "81D9D36EE761C82F24FA404CFC011F8F9ADB249175A7ED3579A5731172495935A3633EA066B518DAAF2D1C558256763D259B71FDB94441542590455ADF818E99";

        final OTPSecret secret = OTPHexSecret.fromBytes(secretInBytes);
        assertArrayEquals(secretInBytes, secret.asBytes(), "OTPHexSecret#asBytes() should be equal to the raw secret");
        assertEquals(secretAsString, secret.asString(), "OTPHexSecret#asString() should be equal to the encoded secret");
    }

    @Test
    public void testFromString20() {
        final byte[] secretInBytes = new byte[] {69, -45, 87, 27, 3, 116, -59, -13, 69, -110, 61, 45, -85, -39, -69, 2, 39, -7, -41, 62};
        final String secretAsString = "45D3571B0374C5F345923D2DABD9BB0227F9D73E";

        final OTPSecret secret = OTPHexSecret.fromString(secretAsString);
        assertArrayEquals(secretInBytes, secret.asBytes(), "OTPHexSecret#asBytes() should be equal to the raw secret");
        assertEquals(secretAsString, secret.asString(), "OTPHexSecret#asString() should be equal to the encoded secret");
    }

    @Test
    public void testFromString32() {
        final byte[] secretInBytes = new byte[] {17, -4, 117, -52, 103, -104, -108, -110, -71, -76, -64, -42, -101, 39, 22, -115, -109, 94, -18, 48, 117, 83, -79, -125, 92, -126, 84, -109, 14, 33, -37, -43};
        final String secretAsString = "11FC75CC67989492B9B4C0D69B27168D935EEE307553B1835C8254930E21DBD5";

        final OTPSecret secret = OTPHexSecret.fromString(secretAsString);
        assertArrayEquals(secretInBytes, secret.asBytes(), "OTPHexSecret#asBytes() should be equal to the raw secret");
        assertEquals(secretAsString, secret.asString(), "OTPHexSecret#asString() should be equal to the encoded secret");
    }

    @Test
    public void testFromStrings64() {
        final byte[] secretInBytes = new byte[] {-94, 98, 99, 61, 56, -59, 111, 76, 1, 37, -102, -39, 110, -98, -85, -22, -116, 74, 54, -66, 21, -109, -114, -104, 93, -6, 111, -81, -22, 89, 74, 101, -45, -69, -95, 67, -108, 8, -91, 15, 55, -92, 7, -122, -37, 29, 76, 2, -46, -48, 45, -80, 63, 55, -42, -2, -66, -2, -96, -30, 19, 11, -6, -95};
        final String secretAsString = "A262633D38C56F4C01259AD96E9EABEA8C4A36BE15938E985DFA6FAFEA594A65D3BBA1439408A50F37A40786DB1D4C02D2D02DB03F37D6FEBEFEA0E2130BFAA1";

        final OTPSecret secret = OTPHexSecret.fromString(secretAsString);
        assertArrayEquals(secretInBytes, secret.asBytes(), "OTPHexSecret#asBytes() should be equal to the raw secret");
        assertEquals(secretAsString, secret.asString(), "OTPHexSecret#asString() should be equal to the encoded secret");
    }

}
