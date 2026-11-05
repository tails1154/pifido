package com.github.mphi_rc.fido2.authenticator;

import java.time.Instant;

import org.immutables.gson.Gson;
import org.immutables.value.Value;

import com.github.mphi_rc.fido2.authenticator.crypto.AttestationKeyPair;

@Gson.TypeAdapters
@Value.Immutable
public interface Credential {

	@Value.Parameter
	String relayingPartyId();

	@Value.Parameter
	Instant creation();

	@Value.Parameter
	byte[] userId();

	@Value.Parameter
	AttestationKeyPair keyPair();

	@Value.Parameter
	int signatureCount();

	/** Random per-credential identifier, persisted with the private key. */
	@Value.Parameter
	byte[] id();
}
