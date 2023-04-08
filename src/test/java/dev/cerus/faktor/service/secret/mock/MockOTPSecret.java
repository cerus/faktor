package dev.cerus.faktor.service.secret.mock;

import dev.cerus.faktor.service.secret.OTPSecret;
import org.jetbrains.annotations.NotNull;

public class MockOTPSecret implements OTPSecret {

    @Override
    public @NotNull String asString() {
        throw new UnsupportedOperationException();
    }

    @Override
    public byte @NotNull [] asBytes() {
        throw new UnsupportedOperationException();
    }

}
