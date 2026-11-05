package com.github.mphi_rc.fido2.authenticator;

import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Optional;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.mphi_rc.fido2.ConfigurationFile;
import com.github.mphi_rc.fido2.protocol.ctap2.Ctap2ResponseCode;
import com.google.common.hash.Hashing;


public class PinState {

	private static final Logger log = LoggerFactory.getLogger(PinState.class);
	private static final Provider securityProvider = new BouncyCastleProvider();

	private final byte[] pinToken;
	private KeyPair pinKeyPair;
	private int retriesLeft;
	private ConfigurationFile config;

	private static KeyPair generateP256KeyPair() {
		try {
			AlgorithmParameters algParam = AlgorithmParameters.getInstance("EC", securityProvider);
			algParam.init(new ECGenParameterSpec("P-256"));
			ECGenParameterSpec parameterSpec = algParam.getParameterSpec(ECGenParameterSpec.class);

			KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", securityProvider);
			generator.initialize(parameterSpec);
			return generator.generateKeyPair();
		} catch(Exception e) {
			throw new RuntimeException(e);
		}
	}

	public PinState(ConfigurationFile config) {
		this.pinToken = new byte[32];
		new SecureRandom().nextBytes(pinToken);
		this.pinKeyPair = generateP256KeyPair();
		this.retriesLeft = Math.max(0, Math.min(8, config.pinRetries()));
		this.config = config;
	}
	
	public int getCountRemainingPinAttempts() {
		return retriesLeft;
	}
	
	public boolean isPinSet() {
		return config.pinHash().isPresent();
	}

	public PublicKey getKeyAgreementKey() {
		return pinKeyPair.getPublic();
	}

	public Ctap2ResponseCode setNewPin(PublicKey hostKey, byte[] encryptedPin, byte[] auth) {
		if (isPinSet()) {
			return Ctap2ResponseCode.PIN_AUTH_INVALID;
		}
		
		try {
			byte[] sharedSecret = deriveSharedSecret(hostKey);
			SecretKey hmacKey = new SecretKeySpec(sharedSecret, "HMACSHA256");

			Mac hmac = Mac.getInstance("HMACSHA256", securityProvider);
			hmac.init(hmacKey);
			byte[] mac = hmac.doFinal(encryptedPin);
			byte[] expectedAuth = new byte[16];
			ByteBuffer.wrap(mac).get(expectedAuth);

			if (!MessageDigest.isEqual(expectedAuth, auth)) {
				log.info("PIN setup authentication failed");
				return Ctap2ResponseCode.PIN_AUTH_INVALID;
			}

			SecretKey aesKey = new SecretKeySpec(sharedSecret, "AES");
			IvParameterSpec iv = new IvParameterSpec(new byte[16]); // yes, the spec really uses an all-zero IV
			Cipher aes = Cipher.getInstance("AES/CBC/NoPadding");
			aes.init(Cipher.DECRYPT_MODE, aesKey, iv);
			byte[] newPinPadded = aes.doFinal(encryptedPin);
			
			int lastPinIndex = newPinPadded.length -1;
			while (lastPinIndex >= 0) {
				if (newPinPadded[lastPinIndex] != 0) {
					break;
				}
				lastPinIndex--;
			}
			if (lastPinIndex < 3 || lastPinIndex >= 63) {
				log.info("New PIN is too short (last index = {})", lastPinIndex);
				return Ctap2ResponseCode.PIN_POLICY_VIOLATION;
			}

			byte[] newPin = new byte[lastPinIndex + 1];
			ByteBuffer.wrap(newPinPadded).get(newPin);
			byte[] hashedNewPin = Hashing.sha256().hashBytes(newPin).asBytes();
			byte[] storedPin = new byte[16];
			ByteBuffer.wrap(hashedNewPin).get(storedPin);
			config.updatePinHash(storedPin);
			Arrays.fill(newPin, (byte) 0);
			retriesLeft = 8;
			persistRetries();
			
			return Ctap2ResponseCode.OK;
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	public Ctap2ResponseCode setPin(PublicKey hostKey, byte[] encryptedNewPin, byte[] encryptedPinHash, byte[] auth) {
		if (!isPinSet()) return Ctap2ResponseCode.PIN_NOT_SET;
		if (retriesLeft <= 0) return Ctap2ResponseCode.PIN_BLOCKED;
		try {
			byte[] sharedSecret = deriveSharedSecret(hostKey);
			SecretKey hmacKey = new SecretKeySpec(sharedSecret, "HMACSHA256");

			Mac hmac = Mac.getInstance("HMACSHA256", securityProvider);
			hmac.init(hmacKey);
			hmac.update(encryptedNewPin);
			hmac.update(encryptedPinHash);
			byte[] mac = hmac.doFinal();
			byte[] expectedAuth = new byte[16];
			ByteBuffer.wrap(mac).get(expectedAuth);

			if (!MessageDigest.isEqual(expectedAuth, auth)) {
				log.info("PIN change authentication failed");
				return Ctap2ResponseCode.PIN_AUTH_INVALID;
			}

			retriesLeft = Math.max(0, retriesLeft - 1);
			persistRetries();

			SecretKey aesKey = new SecretKeySpec(sharedSecret, "AES");
			IvParameterSpec iv = new IvParameterSpec(new byte[16]); // yes, the spec really uses an all-zero IV
			Cipher aes = Cipher.getInstance("AES/CBC/NoPadding");
			aes.init(Cipher.DECRYPT_MODE, aesKey, iv);
			byte[] pinHash = aes.doFinal(encryptedPinHash);
			
			if (!MessageDigest.isEqual(pinHash, config.pinHash().get())) {
				log.info("PIN verification failed");
				pinKeyPair = generateP256KeyPair();
				if (retriesLeft == 0) {
					return Ctap2ResponseCode.PIN_BLOCKED;
				}
				return Ctap2ResponseCode.PIN_INVALID;
			}
			
			retriesLeft = 8;
			persistRetries();

			Cipher aes2 = Cipher.getInstance("AES/CBC/NoPadding");
			aes2.init(Cipher.DECRYPT_MODE, aesKey, iv);
			byte[] newPinPadded = aes.doFinal(encryptedNewPin);
			
			int lastPinIndex = newPinPadded.length -1;
			while (lastPinIndex >= 0) {
				if (newPinPadded[lastPinIndex] != 0) {
					break;
				}
				lastPinIndex--;
			}
			if (lastPinIndex < 3 || lastPinIndex >= 63) {
				log.info("New PIN violates the PIN length policy");
				return Ctap2ResponseCode.PIN_POLICY_VIOLATION;
			}

			byte[] newPin = new byte[lastPinIndex + 1];
			ByteBuffer.wrap(newPinPadded).get(newPin);
			byte[] hashedNewPin = Hashing.sha256().hashBytes(newPin).asBytes();
			byte[] storedPin = new byte[16];
			ByteBuffer.wrap(hashedNewPin).get(storedPin);
			config.updatePinHash(storedPin);
			Arrays.fill(newPin, (byte) 0);
			
			return Ctap2ResponseCode.OK;
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	public Result<byte[], Ctap2ResponseCode> getPinTokenEncrypted(PublicKey hostKey, byte[] encryptedPinHash) { // No auth
		if (!isPinSet()) return Result.err(Ctap2ResponseCode.PIN_NOT_SET);
		if (retriesLeft <= 0) return Result.err(Ctap2ResponseCode.PIN_BLOCKED);
		try {
			byte[] sharedSecret = deriveSharedSecret(hostKey);

			SecretKey aesKey = new SecretKeySpec(sharedSecret, "AES");
			IvParameterSpec iv = new IvParameterSpec(new byte[16]); // yes, the spec really uses an all-zero IV
			Cipher aes = Cipher.getInstance("AES/CBC/NoPadding");
			aes.init(Cipher.DECRYPT_MODE, aesKey, iv);
			byte[] pinHash = aes.doFinal(encryptedPinHash);
			retriesLeft = Math.max(0, retriesLeft - 1);
			persistRetries();
			if (!MessageDigest.isEqual(pinHash, config.pinHash().get())) {
				log.info("PIN verification failed");
				pinKeyPair = generateP256KeyPair();
				
				if (retriesLeft == 0) {
					return Result.err(Ctap2ResponseCode.PIN_BLOCKED);
				}
				return Result.err(Ctap2ResponseCode.PIN_INVALID);
			}
			
			retriesLeft = 8;
			persistRetries();
			
			Cipher aes2 = Cipher.getInstance("AES/CBC/NoPadding");
			aes2.init(Cipher.ENCRYPT_MODE, aesKey, iv);
			byte[] encryptedPinToken = aes2.doFinal(pinToken);
			return Result.ok(encryptedPinToken);

		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	public Optional<Ctap2ResponseCode> isPinAuthValid(byte[] clientDataHash, byte[] pinAuth) {
		try {
			SecretKey hmacKey = new SecretKeySpec(pinToken, "HMACSHA256");
			Mac hmac = Mac.getInstance("HMACSHA256", securityProvider);
			hmac.init(hmacKey);
			hmac.update(clientDataHash);
			byte[] mac = hmac.doFinal();
			byte[] expectedAuth = new byte[16];
			ByteBuffer.wrap(mac).get(expectedAuth);
			
			if (!MessageDigest.isEqual(expectedAuth, pinAuth)) {
				log.info("PIN authorization token is invalid");
				return Optional.of(Ctap2ResponseCode.PIN_AUTH_INVALID);
			}
			return Optional.empty();
			
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			throw new RuntimeException(e);
		}
	}

	private void persistRetries() {
		config.updatePinRetries(retriesLeft);
	}

	private byte[] deriveSharedSecret(PublicKey hostKey) {
		try {
			KeyAgreement ka = KeyAgreement.getInstance("ECDH", securityProvider);
			ka.init(pinKeyPair.getPrivate());
			ka.doPhase(hostKey, true);
			byte[] secret = ka.generateSecret();
			return Hashing.sha256().hashBytes(secret).asBytes();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

}
