package com.github.mphi_rc.fido2.authenticator.user;

/** Used when GPIO setup fails. Authentication is unavailable rather than auto-approved. */
public final class DenyUserVerifier implements UserVerifier {
	@Override
	public boolean isRegistrationApproved(String relayingPartyId) {
		return false;
	}

	@Override
	public boolean isAuthenticationApproved(String relayingPartyId) {
		return false;
	}

	@Override
	public boolean isManagementApproved(String operation) {
		return false;
	}
}
