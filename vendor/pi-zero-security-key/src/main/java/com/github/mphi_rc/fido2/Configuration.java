package com.github.mphi_rc.fido2;


import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.immutables.gson.Gson;
import org.immutables.value.Value;

import com.github.mphi_rc.fido2.authenticator.Credential;
import com.github.mphi_rc.fido2.authenticator.crypto.Algorithm;
import com.github.mphi_rc.usb.gadget.UsbDeviceController;
import com.google.common.collect.ImmutableList;
import com.google.common.hash.Hashing;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

@Gson.TypeAdapters
@Value.Immutable
public interface Configuration {

	List<Credential> credentials();

	@Value.Default
	default List<Algorithm> enabledAlgorithms() {
		return ImmutableList.of(Algorithm.P256_ECDSA, Algorithm.Ed25519);
	}

	@Value.Default
	default UUID id() {
		return UUID.randomUUID();
	}

	@Value.Default
	default Optional<byte[]> pinHash() {
		byte[] full = Hashing.sha256().hashString("1234", StandardCharsets.UTF_8).asBytes();
		return Optional.of(Arrays.copyOf(full, 16));
	}

	@Value.Default
	default boolean pinChangeRequired() {
		return true;
	}

	@Value.Default
	default int pinRetries() {
		return 8;
	}

	@Value.Default
	default boolean enableBonnet() {
		return false;
	}

	@Value.Default
	default String usbGadgetDevicePath() {
		return "/dev/hidg0";
	}

	@Value.Default
	default UsbDeviceController usbDeviceController() {
		return UsbDeviceController.raspberryPiZero();
	}

	@Value.Default
	default String usbGadgetName() {
		return "fido2";
	}
}
