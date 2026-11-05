package com.github.mphi_rc.fido2;

import com.github.mphi_rc.usb.gadget.ConfigFs;
import com.github.mphi_rc.usb.gadget.ImmutableUsbHidGadget;
import com.github.mphi_rc.usb.gadget.UsbHidDescriptors;
import com.github.mphi_rc.usb.gadget.UsbHidGadget;

public class Fido2AuthenticatorCli {

	private Fido2AuthenticatorCli() {}

	public static void main(String[] args) throws Exception {

		ConfigurationFile config = ConfigurationFile.defaultPath();
		config.persistToDiskSync();

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

		ConfigFs configFs = ConfigFs.ofDefault();
		configFs.initialize(fido2Gadget);
		// FunctionFS must publish its descriptors before the composite gadget is
		// bound to the UDC, otherwise Linux rejects the ffs function with ENODEV.
		ManagementHidServer management = new ManagementHidServer(config);
		management.prepare();
		management.start();
		configFs.attach(fido2Gadget, config.usbDeviceController());

		Fido2Authenticator authenticator = new Fido2Authenticator(config);
		authenticator.start();
	}
}
