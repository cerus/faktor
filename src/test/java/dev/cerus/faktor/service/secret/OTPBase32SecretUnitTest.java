package dev.cerus.faktor.service.secret;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

public class OTPBase32SecretUnitTest {

    @Test
    public void testFromBytesInvalid() {
        final String expectedExceptionMessage = "Secrets can have one of the following lengths: 20, 32, 64";
        final Throwable ex1 = assertThrows(IllegalArgumentException.class, () -> OTPBase32Secret.fromBytes(new byte[] {1, 2, 3}));
        final Throwable ex2 = assertThrows(IllegalArgumentException.class, () -> OTPBase32Secret.fromBytes(new byte[] {9, 8, 7, 6, 5, 4, 3, 2, 1, 0}));
        final Throwable ex3 = assertThrows(IllegalArgumentException.class, () -> OTPBase32Secret.fromBytes(new byte[0]));
        assertEquals(expectedExceptionMessage, ex1.getMessage(), "Expected '" + expectedExceptionMessage + "'");
        assertEquals(expectedExceptionMessage, ex2.getMessage(), "Expected '" + expectedExceptionMessage + "'");
        assertEquals(expectedExceptionMessage, ex3.getMessage(), "Expected '" + expectedExceptionMessage + "'");
    }

    @Test
    public void testFromBytes20() {
        final byte[] secretInBytes = new byte[] {32, 118, 14, 55, 16, 81, -117, -52, 63, -39, -84, -58, 28, 12, -34, 120, 107, -101, -16, -9};
        final String secretAsString = "EB3A4NYQKGF4YP6ZVTDBYDG6PBVZX4HX";

        final OTPSecret secret = OTPBase32Secret.fromBytes(secretInBytes);
        assertArrayEquals(secretInBytes, secret.asBytes(), "OTPHexSecret#asBytes() should be equal to the raw secret");
        assertEquals(secretAsString, secret.asString(), "OTPHexSecret#asString() should be equal to the encoded secret");
    }

    @Test
    public void testFromBytes32() {
        final byte[] secretInBytes = new byte[] {-119, 37, 27, -47, 95, -21, -78, 124, -87, -83, -57, -12, -118, 77, -34, 89, -124, -124, 117, 114, 93, -88, -126, 17, -18, -108, 106, 85, -113, -34, 20, -62};
        final String secretAsString = "RESRXUK75OZHZKNNY72IUTO6LGCII5LSLWUIEEPOSRVFLD66CTBA====";

        final OTPSecret secret = OTPBase32Secret.fromBytes(secretInBytes);
        assertArrayEquals(secretInBytes, secret.asBytes(), "OTPHexSecret#asBytes() should be equal to the raw secret");
        assertEquals(secretAsString, secret.asString(), "OTPHexSecret#asString() should be equal to the encoded secret");
    }

    @Test
    public void testFromBytes64() {
        final byte[] secretInBytes = new byte[] {-113, 76, -46, 99, -23, 123, -10, 41, 30, -46, 63, -100, 98, 112, -77, -109, 10, 123, -108, 45, -75, 94, -1, -18, -32, -71, -1, -19, 94, 122, 67, 2, 35, 0, 21, -70, -103, 3, 22, 34, -53, 107, 90, -33, 118, 80, 66, 126, -32, -20, -16, 47, -111, 110, -101, -75, 80, -89, -65, 13, -126, -46, -67, -98};
        final String secretAsString = "R5GNEY7JPP3CSHWSH6OGE4FTSMFHXFBNWVPP73XAXH762XT2IMBCGAAVXKMQGFRCZNVVVX3WKBBH5YHM6AXZC3U3WVIKPPYNQLJL3HQ=";

        final OTPSecret secret = OTPBase32Secret.fromBytes(secretInBytes);
        assertArrayEquals(secretInBytes, secret.asBytes(), "OTPHexSecret#asBytes() should be equal to the raw secret");
        assertEquals(secretAsString, secret.asString(), "OTPHexSecret#asString() should be equal to the encoded secret");
    }

    @Test
    public void testFromStringInvalid() {
        String expectedExceptionMessage = "Not an encoded Base32 OTPSecret";
        final Throwable ex1 = assertThrows(IllegalArgumentException.class, () -> OTPBase32Secret.fromString(""));
        final Throwable ex2 = assertThrows(IllegalArgumentException.class, () -> OTPBase32Secret.fromString("123"));
        final Throwable ex3 = assertThrows(IllegalArgumentException.class, () -> OTPBase32Secret.fromString("123abc456"));
        assertEquals(expectedExceptionMessage, ex1.getMessage(), "Expected '" + expectedExceptionMessage + "'");
        assertEquals(expectedExceptionMessage, ex2.getMessage(), "Expected '" + expectedExceptionMessage + "'");
        assertEquals(expectedExceptionMessage, ex3.getMessage(), "Expected '" + expectedExceptionMessage + "'");

        expectedExceptionMessage = "Secrets can have one of the following lengths: 20, 32, 64";
        final Throwable ex4 = assertThrows(IllegalArgumentException.class, () -> OTPBase32Secret.fromString("234567AB"));
        assertEquals(expectedExceptionMessage, ex4.getMessage(), "Expected '" + expectedExceptionMessage + "'");

        expectedExceptionMessage = "Unrecognized Base32 character: 1";
        final Throwable ex5 = assertThrows(IllegalArgumentException.class, () -> OTPBase32Secret.fromString("11234567"));
        assertEquals(expectedExceptionMessage, ex5.getMessage(), "Expected '" + expectedExceptionMessage + "'");

        expectedExceptionMessage = "Unrecognized Base32 character: 8";
        final Throwable ex6 = assertThrows(IllegalArgumentException.class, () -> OTPBase32Secret.fromString("88234567"));
        assertEquals(expectedExceptionMessage, ex6.getMessage(), "Expected '" + expectedExceptionMessage + "'");
    }

    @Test
    public void testFromString20() {
        final byte[] secretInBytes = new byte[] {108, -73, 51, -33, 86, 91, -4, 118, 8, 89, 32, 121, -54, -9, 44, -12, -20, -48, -17, 6};
        final String secretAsString = "NS3THX2WLP6HMCCZEB44V5ZM6TWNB3YG";

        final OTPSecret secret = OTPBase32Secret.fromString(secretAsString);
        assertArrayEquals(secretInBytes, secret.asBytes(), "OTPHexSecret#asBytes() should be equal to the raw secret");
        assertEquals(secretAsString, secret.asString(), "OTPHexSecret#asString() should be equal to the encoded secret");
    }

    @Test
    public void testFromString32() {
        final byte[] secretInBytes = new byte[] {71, -42, -76, -36, 76, -89, -123, -25, 75, 98, 104, 108, 107, -90, -100, -83, 29, 106, 28, 40, -70, -46, -29, -94, -72, 68, 36, -99, -17, 44, -96, -99};
        final String secretAsString = "I7LLJXCMU6C6OS3CNBWGXJU4VUOWUHBIXLJOHIVYIQSJ33ZMUCOQ====";

        final OTPSecret secret = OTPBase32Secret.fromString(secretAsString);
        assertArrayEquals(secretInBytes, secret.asBytes(), "OTPHexSecret#asBytes() should be equal to the raw secret");
        assertEquals(secretAsString, secret.asString(), "OTPHexSecret#asString() should be equal to the encoded secret");
    }

    @Test
    public void testFromString64() {
        final byte[] secretInBytes = new byte[] {-102, -70, 25, -118, -73, 3, -97, -25, 71, 48, 125, 113, 57, 9, -124, 15, -108, -34, -10, 47, -15, -66, 127, -46, -77, 20, 40, 78, -101, -63, -39, 32, -4, -14, -125, 28, 82, -76, 88, 82, 93, 87, -57, 63, -27, -11, -75, 68, 107, 77, -79, -26, 9, 110, -124, -5, -40, -101, 53, -81, -122, -100, -102, 92};
        final String secretAsString = "TK5BTCVXAOP6ORZQPVYTSCMEB6KN55RP6G7H7UVTCQUE5G6B3EQPZ4UDDRJLIWCSLVL4OP7F6W2UI22NWHTAS3UE7PMJWNNPQ2OJUXA=";

        final OTPSecret secret = OTPBase32Secret.fromString(secretAsString);
        assertArrayEquals(secretInBytes, secret.asBytes(), "OTPHexSecret#asBytes() should be equal to the raw secret");
        assertEquals(secretAsString, secret.asString(), "OTPHexSecret#asString() should be equal to the encoded secret");
    }

}
