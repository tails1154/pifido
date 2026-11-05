package com.github.mphi_rc.fido2.authenticator.user;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/** Fail-closed user presence using a momentary switch from BCM26 to ground. */
public final class GpioButtonUserVerifier implements UserVerifier {

	private static final Path VALUE = Paths.get("/sys/class/gpio/gpio26/value");
	private static final Path ACT_LED = Paths.get("/sys/class/leds/led0/brightness");
	private static final long TIMEOUT_MILLIS = 8_000L;
	private static final long DEBOUNCE_MILLIS = 40L;

	public GpioButtonUserVerifier() {
		if (!Files.isReadable(VALUE)) {
			throw new IllegalStateException("GPIO26 input is unavailable");
		}
	}

	@Override
	public boolean isRegistrationApproved(String relyingPartyId) {
		return waitForPress();
	}

	@Override
	public boolean isAuthenticationApproved(String relyingPartyId) {
		return waitForPress();
	}

	@Override
	public boolean isManagementApproved(String operation) {
		return waitForPress();
	}

	private boolean waitForPress() {
		long deadline = System.nanoTime() + TIMEOUT_MILLIS * 1_000_000L;
		setLed(true);
		try {
			// A button held during boot or from a previous request never approves
			// the next operation. Require release before accepting a fresh press.
			while (isPressed() && before(deadline)) {
				Thread.sleep(10L);
			}
			while (before(deadline)) {
				if (isPressed() && stablePress(deadline)) {
					return true;
				}
				Thread.sleep(10L);
			}
			return false;
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			return false;
		} catch (IOException e) {
			return false;
		} finally {
			setLed(false);
		}
	}

	private boolean stablePress(long deadline) throws IOException, InterruptedException {
		long stableUntil = System.nanoTime() + DEBOUNCE_MILLIS * 1_000_000L;
		while (System.nanoTime() < stableUntil && before(deadline)) {
			Thread.sleep(5L);
			if (!isPressed()) {
				return false;
			}
		}
		return before(deadline) && isPressed();
	}

	private static boolean before(long deadline) {
		return System.nanoTime() < deadline;
	}

	private static boolean isPressed() throws IOException {
		byte[] value = Files.readAllBytes(VALUE);
		return value.length > 0 && value[0] == '0';
	}

	private static void setLed(boolean on) {
		if (!Files.isWritable(ACT_LED)) {
			return;
		}
		try {
			Files.write(ACT_LED, (on ? "1\n" : "0\n").getBytes(StandardCharsets.US_ASCII));
		} catch (IOException ignored) {
			// The onboard LED is optional; button approval remains authoritative.
		}
	}
}
