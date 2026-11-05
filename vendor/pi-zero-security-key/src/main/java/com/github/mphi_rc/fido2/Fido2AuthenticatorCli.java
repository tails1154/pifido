package com.github.mphi_rc.fido2;

import com.github.mphi_rc.usb.gadget.ConfigFs;
import com.github.mphi_rc.usb.gadget.ImmutableUsbHidGadget;
import com.github.mphi_rc.usb.gadget.UsbHidDescriptors;
import com.github.mphi_rc.usb.gadget.UsbHidGadget;

public class Fido2AuthenticatorCli {

	private Fido2AuthenticatorCli() {}

	public static void main(String[] args) throws Exception {

		ConfigurationFile config = ConfigurationFile.defaultPath();
		System.err.println("PiFIDO Java: credential configuration loaded");
		config.persistToDiskSync();
		System.err.println("PiFIDO Java: credential configuration persisted");

		UsbHidGadget fido2Gadget = ImmutableUsbHidGadget.builder()
				.name(config.usbGadgetName())
				.manufacturerName("Tails1154")
				.productName("FIDO2")
				.vendorId("0x1209")
				.productId("0xf1d0")
				.deviceBcd("0x0001")
				.hidDescriptor(UsbHidDescriptors.FIDO2)
				.hidReportLength(64)
				.maxPowerMilliamps(250)
				.build();

		if (!Boolean.getBoolean("pifido.externalGadget")) {
			ConfigFs configFs = ConfigFs.ofDefault();
			configFs.initialize(fido2Gadget);
			configFs.attach(fido2Gadget, config.usbDeviceController());
		}

		System.err.println("PiFIDO Java: opening HID transport");
		Fido2Authenticator authenticator = new Fido2Authenticator(config);
		System.err.println("PiFIDO Java: HID transport open; waiting for CTAPHID");
		authenticator.start();
	}
}
