package com.github.mphi_rc.fido2.authenticator;

import java.time.Instant;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import com.github.mphi_rc.fido2.ConfigurationFile;
import com.github.mphi_rc.fido2.authenticator.crypto.AttestationKeyPair;


public class ConfigurationCredentialStore implements CredentialStore {

	private static final SecureRandom RANDOM = new SecureRandom();

	private final ConfigurationFile config;

	public ConfigurationCredentialStore(ConfigurationFile config) {
		this.config = config;
	}

	@Override
	public Collection<Credential> getCredentials(String relayingPartyId) {
		return config.credentials().stream()
				.filter(c -> c.relayingPartyId().equals(relayingPartyId))
				.collect(Collectors.toList());
	}

	@Override
	public Credential saveCredential(String relayingPartyId, byte[] userId, AttestationKeyPair keyPair) {
		byte[] credentialId = new byte[32];
		RANDOM.nextBytes(credentialId);
		Credential credential = ImmutableCredential.builder()
				.relayingPartyId(relayingPartyId)
				.creation(Instant.now())
				.userId(userId)
				.keyPair(keyPair)
				.signatureCount(0)
				.id(credentialId)
				.build();
		config.addCredential(credential);
		return credential;
	}

	@Override
	public void incrementCredentialCounter(String relayingPartyId, AttestationKeyPair keyPair) {
		Optional<Credential> matchingCredential = getCredentials(relayingPartyId).stream()
				.filter(cred -> cred.keyPair().equals(keyPair))
				.findFirst();

		if (matchingCredential.isPresent()) {
			Credential existing = matchingCredential.get();
			Credential updated = ImmutableCredential.builder()
					.from(existing)
					.signatureCount(existing.signatureCount() + 1)
					.build();

			List<Credential> updatedCredentials = new ArrayList<>(config.credentials());
			updatedCredentials.remove(existing);
			updatedCredentials.add(updated);

			config.updateAllStoredCredentials(updatedCredentials);
		}
	}


}
