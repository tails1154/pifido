package com.github.mphi_rc.fido2.protocol.usbhid;

import java.util.HashSet;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.mphi_rc.fido2.protocol.ctap2.AuthenticatorRequestHandler;
import com.github.mphi_rc.fido2.protocol.usbhid.command.ImmutableInitResponsePayload;
import com.github.mphi_rc.fido2.protocol.usbhid.command.InitRequestPayload;
import com.github.mphi_rc.fido2.protocol.usbhid.command.InitResponsePayload;
import com.github.mphi_rc.fido2.ConfigurationFile;

public class UsbHidRequestHandler {

	private static final Logger log = LoggerFactory.getLogger(UsbHidRequestHandler.class);

	private final AuthenticatorRequestHandler authenticator;
	private final Set<ChannelId> activeChannels;
	private final U2fHandler u2f;

	public UsbHidRequestHandler(AuthenticatorRequestHandler authenticator, ConfigurationFile config) {
		this.authenticator = authenticator;
		this.activeChannels = new HashSet<>();
		this.u2f = new U2fHandler(config);
	}
	/** Compatibility constructor used by protocol unit tests. */
	public UsbHidRequestHandler(AuthenticatorRequestHandler authenticator) {
		this.authenticator = authenticator;
		this.activeChannels = new HashSet<>();
		this.u2f = null;
	}

	public RawMessage handle(RawMessage message) {
		log.trace("Received message {}", message);

		if (message.channelId().equals(ChannelId.broadcast())) {
			return handleBroadcast(message);
		}

		if (!activeChannels.contains(message.channelId())) {
			return RawMessage.error(message.channelId(), HidError.INVALID_CHANNEL);
		}

		switch(message.command()) {
		case CBOR:
			return authenticator.handleCborRequest(message.channelId(), message.payload());

		case INIT:
			InitRequestPayload initRequest = InitRequestPayload.from(message);
			InitResponsePayload initResponse = ImmutableInitResponsePayload.builder()
					.nonce(initRequest.nonce())
					.channel(message.channelId())
					.build();
			return ImmutableRawMessage.of(message.channelId(), HidCommand.INIT, initResponse.asBytes());

		case PING:
			return ImmutableRawMessage.of(message.channelId(), HidCommand.PING, message.payload());
		case MSG:
			return u2f == null ? RawMessage.error(message.channelId(), HidError.INVALID_CMD)
					: ImmutableRawMessage.of(message.channelId(), HidCommand.MSG, u2f.handle(message.payload()));
		default:
			return RawMessage.error(message.channelId(), HidError.INVALID_CMD);
		}
	}

	private ChannelId allocateChannel() {
		ChannelId id;
		do {
			id = ChannelId.random();
		} while (activeChannels.contains(id));
		activeChannels.add(id);
		return id;
	}

	private RawMessage handleBroadcast(RawMessage message) {
		switch (message.command()) {
		case INIT:
			InitRequestPayload initRequest = InitRequestPayload.from(message);
			InitResponsePayload initResponse = ImmutableInitResponsePayload.builder()
					.nonce(initRequest.nonce())
					.channel(allocateChannel())
					.build();
			return ImmutableRawMessage.of(message.channelId(), HidCommand.INIT, initResponse.asBytes());
		default:
			return RawMessage.error(message.channelId(), HidError.INVALID_CMD);
		}
	}
}
