package com.github.mphi_rc.usb.gadget;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.io.IOException;

import org.immutables.gson.Gson;
import org.immutables.value.Value;

import com.google.common.base.Preconditions;

@Gson.TypeAdapters
@Value.Immutable
public interface UsbDeviceController {

	static UsbDeviceController raspberryPiZero() {
		try (java.util.stream.Stream<Path> udcs = Files.list(Paths.get("/sys/class/udc"))) {
			Path first = udcs.findFirst().orElse(null);
			if (first != null) {
				return ImmutableUsbDeviceController.of(first.getFileName().toString());
			}
		} catch (IOException ignored) {
			// The value check below provides the actionable error if UDC is absent.
		}
		return ImmutableUsbDeviceController.of("20980000.usb");
	}

	static UsbDeviceController dummy() {
		return ImmutableUsbDeviceController.of("dummy_udc.0");
	}

	@Value.Parameter
	String name();

	@Value.Check
	default void check() {
		Path udcPath = Paths.get("/sys/class/udc/", name());
		Preconditions.checkState(Files.isDirectory(udcPath), "Chosen USB device controller is unavailable");
	}

}
