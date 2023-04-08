package dev.cerus.faktor.service;

import dev.cerus.faktor.HMACAlgorithm;
import dev.cerus.faktor.generator.DefaultTOTPGenerator;
import dev.cerus.faktor.generator.TOTPGenerator;
import dev.cerus.faktor.service.secret.OTPSecret;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.TimeUnit;
import org.jetbrains.annotations.Contract;

/**
 * Default TOTPService implementation
 */
public class DefaultTOTPService implements TOTPService {

    private final TOTPGenerator generator;
    private final byte[] secret;
    private final HMACAlgorithm algorithm;
    private final long timeStepMillis;
    private final int digits;
    private final int backwardsSteps;

    private DefaultTOTPService(final TOTPGenerator generator,
                               final OTPSecret secret,
                               final HMACAlgorithm algorithm,
                               final long timeStepMillis,
                               final int digits,
                               final int backwardsSteps) {
        this.generator = generator;
        this.secret = secret.asBytes();
        this.algorithm = algorithm;
        this.timeStepMillis = timeStepMillis;
        this.digits = digits;
        this.backwardsSteps = backwardsSteps;
    }

    /**
     * Create a new builder for {@link DefaultTOTPService}
     *
     * @return a new builder
     */
    @Contract(value = "-> new", pure = true)
    public static Builder builder() {
        return new Builder();
    }

    @Override
    public boolean validateTOTP(final int totp) throws NoSuchAlgorithmException, InvalidKeyException {
        for (int step = this.backwardsSteps; step >= 0; step--) {
            final int generatedTOTP = this.generator.generateTOTP(this.secret,
                    System.currentTimeMillis(), this.timeStepMillis, this.digits, step, this.algorithm);
            if (generatedTOTP == totp) {
                return true;
            }
        }
        return false;
    }

    @Override
    public int generateTOTP() throws NoSuchAlgorithmException, InvalidKeyException {
        return this.generator.generateTOTP(this.secret, System.currentTimeMillis(), this.timeStepMillis, this.digits, this.algorithm);
    }

    /**
     * Builder for {@link DefaultTOTPService}
     */
    public static class Builder {

        private TOTPGenerator generator;
        private OTPSecret secret;
        private HMACAlgorithm algorithm;
        private Long timeStepMillis;
        private Integer digits;
        private int backwardsSteps;

        private Builder() {
        }

        /**
         * Fill generator, digits and backwards steps with default values
         */
        @Contract("-> this")
        public Builder withDefaults() {
            return this.withDefaultBackwardsSteps()
                    .withDefaultGenerator()
                    .withDefaultDigits();
        }

        /**
         * Use the default TOTP generator
         * <p>
         * See also {@link Builder#withGenerator(TOTPGenerator)}
         */
        @Contract("-> this")
        public Builder withDefaultGenerator() {
            return this.withGenerator(new DefaultTOTPGenerator());
        }

        /**
         * Use the specified generator
         */
        @Contract("_ -> this")
        public Builder withGenerator(final TOTPGenerator generator) {
            this.generator = generator;
            return this;
        }

        /**
         * Use the specified OTP secret
         */
        @Contract("_ -> this")
        public Builder withSecret(final OTPSecret secret) {
            this.secret = secret;
            return this;
        }

        /**
         * Use the specified HMAC algorithm
         */
        @Contract("_ -> this")
        public Builder withAlgorithm(final HMACAlgorithm algorithm) {
            this.algorithm = algorithm;
            return this;
        }

        /**
         * Use the specified time step
         */
        @Contract("_, _ -> this")
        public Builder withTimeStep(final long timeStepValue, final TimeUnit timeStepUnit) {
            return this.withTimeStep(timeStepUnit.toMillis(timeStepValue));
        }

        /**
         * Use the specified time step
         */
        @Contract("_ -> this")
        public Builder withTimeStep(final long timeStepMillis) {
            this.timeStepMillis = timeStepMillis;
            return this;
        }

        /**
         * Use the default digits
         * <p>
         * See also {@link Builder#withDigits(int)}
         */
        @Contract("-> this")
        public Builder withDefaultDigits() {
            return this.withDigits(6);
        }

        /**
         * Use the specified digits
         */
        @Contract("_ -> this")
        public Builder withDigits(final int digits) {
            this.digits = digits;
            return this;
        }

        /**
         * Use the default backwards steps
         * <p>
         * See also {@link Builder#withBackwardsSteps(int)}
         */
        @Contract("-> this")
        public Builder withDefaultBackwardsSteps() {
            return this.withBackwardsSteps(0);
        }

        /**
         * Use the specified backwards steps
         * <p>
         * This specifies how many time steps a secret can be old to still count as valid.
         */
        @Contract("_ -> this")
        public Builder withBackwardsSteps(final int backwardsSteps) {
            this.backwardsSteps = backwardsSteps;
            return this;
        }

        /**
         * Build a new {@link DefaultTOTPService} with the configured parameters
         */
        @Contract(value = "-> new", pure = true)
        public TOTPService build() {
            this.verifyState();
            return new DefaultTOTPService(
                    this.generator,
                    this.secret,
                    this.algorithm,
                    this.timeStepMillis,
                    this.digits,
                    this.backwardsSteps
            );
        }

        /**
         * Performs sanity checks
         */
        private void verifyState() {
            if (this.generator == null) {
                this.panicFieldNotSet("generator", "withDefaultGenerator()", "withGenerator(TOTPGenerator)");
            }
            if (this.secret == null) {
                this.panicFieldNotSet("secret", "withSecret(OTPSecret)");
            }
            if (this.algorithm == null) {
                this.panicFieldNotSet("algorithm", "withAlgorithm(TOTPGenerator.HMACAlgorithm)");
            }
            if (this.timeStepMillis == null) {
                this.panicFieldNotSet("timeStepMillis", "withTimeStep(long, TimeUnit)", "withTimeStep(long)");
            }
            if (this.digits == null) {
                this.panicFieldNotSet("digits", "withDefaultDigits()", "withDigits(int)");
            }
            if (this.backwardsSteps < 0) {
                this.panicFieldInvalid("backwardsSteps", "Must be >= 0");
            }
            if (this.digits < 6 || this.digits > 10) {
                this.panicFieldInvalid("digits", "Must be in interval [6,10]");
            }
            if (this.timeStepMillis < 1) {
                this.panicFieldInvalid("timeStepMillis", "Must be >= 1");
            }
        }

        private void panicFieldInvalid(final String field, final String problem) {
            throw new IllegalStateException("Unable to build TOTP-Service: Field %s is invalid: %s".formatted(field, problem));
        }

        private void panicFieldNotSet(final String field, final String... methods) {
            throw new IllegalStateException("Unable to build TOTP-Service: Field %s is not set. Call one of [%s] before calling build()."
                    .formatted(field, String.join(", ", methods)));
        }

    }

}
