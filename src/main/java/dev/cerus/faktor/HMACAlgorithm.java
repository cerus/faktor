package dev.cerus.faktor;

/**
 * Available HMAC algorithms for OTP generation
 */
public enum HMACAlgorithm {

    SHA1(20),
    SHA256(32),
    SHA512(64);

    private final int byteAmount;

    HMACAlgorithm(final int byteAmount) {
        this.byteAmount = byteAmount;
    }

    public int byteAmount() {
        return this.byteAmount;
    }

}
