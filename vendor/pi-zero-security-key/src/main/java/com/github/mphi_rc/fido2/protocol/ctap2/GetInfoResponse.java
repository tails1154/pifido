package com.github.mphi_rc.fido2.protocol.ctap2;

import java.util.List;

import org.immutables.value.Value;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.model.DataItem;

@Value.Immutable
public abstract class GetInfoResponse {
	
	private static final byte VERSIONS_KEY = 0x01;
	private static final byte AAGUID_KEY = 0x03;
	private static final byte OPTIONS_KEY = 0x04;
	private static final byte MAX_MSG_SIZE_KEY = 0x05;
	private static final byte PIN_UV_AUTH_PROTOCOLS_KEY = 0x06;
	private static final byte TRANSPORTS_KEY = 0x09;
	private static final String PLATFORM_OPTION = "plat";
	private static final String RESIDENT_KEY_OPTION = "rk";
	private static final String USER_PRESENCE_OPTION = "up";
	private static final String CLIENT_PIN_OPTION = "clientPin";
	
	public static enum Version {
		FIDO_2_0, U2F_V2;
	}
	
	@Value.Parameter
	public abstract Version version();
	
	@Value.Parameter
	public abstract byte[] aaguid();
	
	@Value.Parameter
	public abstract boolean isPinConfigured();
	
	public List<DataItem> asCborMap() {
		return new CborBuilder()
				.addMap()
					.putArray(VERSIONS_KEY)
						.add(version().name())
					.end()
					.put(AAGUID_KEY, aaguid())
					.putMap(OPTIONS_KEY)
						.put(PLATFORM_OPTION, false)
						.put(RESIDENT_KEY_OPTION, true)
						.put(USER_PRESENCE_OPTION, true)
						.put(CLIENT_PIN_OPTION, isPinConfigured())
					.end()
					// Chromium treats clientPin=true as invalid unless the
					// authenticator also advertises a supported PIN/UV protocol.
					.put(MAX_MSG_SIZE_KEY, 1200)
					.putArray(PIN_UV_AUTH_PROTOCOLS_KEY)
						.add(1)
					.end()
					.putArray(TRANSPORTS_KEY)
						.add("usb")
					.end()
				.end()
				.build();
	}
}
