package com.github.mphi_rc.fido2;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.mphi_rc.fido2.authenticator.Credential;
import com.github.mphi_rc.fido2.authenticator.GsonAdaptersCredential;
import com.github.mphi_rc.fido2.authenticator.crypto.Algorithm;
import com.github.mphi_rc.fido2.authenticator.crypto.AttestationKeyPair;
import com.github.mphi_rc.fido2.authenticator.crypto.GsonAdaptersEd25519AttestationKeyPair;
import com.github.mphi_rc.fido2.authenticator.crypto.GsonAdaptersP256AttestationKeyPair;
import com.github.mphi_rc.fido2.authenticator.user.AlwaysAllowUserVerifier;
import com.github.mphi_rc.fido2.authenticator.user.DenyUserVerifier;
import com.github.mphi_rc.fido2.authenticator.user.GpioButtonUserVerifier;
import com.github.mphi_rc.fido2.authenticator.user.UserVerifier;
import com.github.mphi_rc.gson.AttestationKeyPairTypeAdapter;
import com.github.mphi_rc.gson.Base64TypeAdapter;
import com.github.mphi_rc.gson.MillisTypeAdapter;
import com.github.mphi_rc.usb.gadget.GsonAdaptersUsbDeviceController;
import com.github.mphi_rc.usb.gadget.UsbDeviceController;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class ConfigurationFile implements Configuration {

	private static final Logger log = LoggerFactory.getLogger(ConfigurationFile.class);
	private static final java.nio.file.attribute.FileAttribute<java.util.Set<java.nio.file.attribute.PosixFilePermission>> OWNER_RW =
			PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"));

	private final Gson gson;
	private final Path configFile;
	private final Path configDirectory;
	private Configuration config;

	public static ConfigurationFile defaultPath() {
		return new ConfigurationFile(Paths.get("/data/pifido/credentials.json"));
	}

	public ConfigurationFile(Path path) {
		this.gson = new GsonBuilder()
				.setPrettyPrinting()
				.registerTypeAdapterFactory(new GsonAdaptersConfiguration())
				.registerTypeAdapterFactory(new GsonAdaptersUsbDeviceController())
				.registerTypeAdapterFactory(new GsonAdaptersCredential())
				.registerTypeAdapterFactory(new GsonAdaptersEd25519AttestationKeyPair())
				.registerTypeAdapterFactory(new GsonAdaptersP256AttestationKeyPair())
				.registerTypeAdapter(AttestationKeyPair.class, new AttestationKeyPairTypeAdapter())
				.registerTypeAdapter(byte[].class, new Base64TypeAdapter())
				.registerTypeAdapter(Instant.class, new MillisTypeAdapter())
				.create();
		this.configFile = path.toAbsolutePath().normalize();
		this.configDirectory = this.configFile.getParent();
		try {
			Files.createDirectories(configDirectory);
			Files.setPosixFilePermissions(configDirectory, PosixFilePermissions.fromString("rwx------"));
			if (Files.isSymbolicLink(configFile)) {
				throw new IOException("Credential file must not be a symbolic link");
			}
			if (Files.exists(configFile, LinkOption.NOFOLLOW_LINKS)) {
				Files.setPosixFilePermissions(configFile, PosixFilePermissions.fromString("rw-------"));
			}
			this.config = readFromDisk();
			// The headless Pi image has no first-boot PIN-change UI yet.  Keep the
			// documented development PIN (1234) usable instead of making Chrome
			// wait forever for an interaction that cannot be completed.
			if (Boolean.getBoolean("pifido.allowDefaultPin") && this.config.pinChangeRequired()) {
				this.config = ImmutableConfiguration.builder().from(this.config).pinChangeRequired(false).build();
				persistToDiskSync();
			}
		} catch (IOException e) {
			throw new IllegalStateException("Credential store is unavailable", e);
		}
	}

	public UserVerifier userVerifier() {
		if (!Boolean.getBoolean("pifido.requireButton")) {
			log.warn("AUTOMATIC USER PRESENCE ENABLED: this device has no physical approval button");
			return new AlwaysAllowUserVerifier();
		}
		try {
			return new GpioButtonUserVerifier();
		} catch (RuntimeException e) {
			log.error("GPIO user-presence input is unavailable; denying all credential operations", e);
			return new DenyUserVerifier();
		}
	}

	public synchronized void updatePinHash(byte[] pinHash) {
		config = ImmutableConfiguration.builder().from(config).pinHash(Optional.of(pinHash)).pinChangeRequired(false).build();
		persistToDiskSync();
	}

	public synchronized void addCredential(Credential credential) {
		config = ImmutableConfiguration.builder().from(config).addCredentials(credential).build();
		persistToDiskSync();
	}

	public synchronized void updateAllStoredCredentials(List<Credential> credentials) {
		config = ImmutableConfiguration.builder().from(config).credentials(credentials).build();
		persistToDiskSync();
	}

	public synchronized void updatePinRetries(int retries) {
		config = ImmutableConfiguration.builder().from(config).pinRetries(retries).build();
		persistToDiskSync();
	}

	public byte[] getAaguid() {
		ByteBuffer bb = ByteBuffer.wrap(new byte[16]);
		bb.putLong(id().getMostSignificantBits());
		bb.putLong(id().getLeastSignificantBits());
		return bb.array();
	}

	@Override
	public UsbDeviceController usbDeviceController() {
		// The UDC name is hardware/runtime state; never trust a stale persisted
		// value after kernel, overlay, or USB-controller changes.
		return UsbDeviceController.raspberryPiZero();
	}
	@Override
	public List<Credential> credentials() { return config.credentials(); }
	@Override
	public List<Algorithm> enabledAlgorithms() { return config.enabledAlgorithms(); }
	@Override
	public UUID id() { return config.id(); }
	public Optional<byte[]> pinHash() { return config.pinHash(); }
	public int pinRetries() { return config.pinRetries(); }
	public boolean pinChangeRequired() { return config.pinChangeRequired(); }
	@Override
	public boolean enableBonnet() { return false; }
	@Override
	public String usbGadgetDevicePath() { return config.usbGadgetDevicePath(); }
	@Override
	public String usbGadgetName() { return config.usbGadgetName(); }

	/** Serialize, fsync, atomically replace, and fsync the containing directory before CTAP success is sent. */
	public synchronized void persistToDiskSync() {
		java.io.File temporary = null;
		try {
			byte[] bytes = gson.toJson(config).getBytes(StandardCharsets.UTF_8);
			// Avoid java.nio FileChannel on ARMv6 kernels where the Java 8
			// dispatcher probes an unavailable syscall and fails with ENOSYS.
			temporary = java.io.File.createTempFile("credentials.", ".tmp", configDirectory.toFile());
			try (java.io.FileOutputStream output = new java.io.FileOutputStream(temporary)) {
				output.write(bytes);
				output.flush();
				output.getFD().sync();
			}
			java.io.File destination = configFile.toFile();
			if (destination.exists() && !destination.delete()) {
				throw new IOException("unable to replace existing credential file");
			}
			if (!temporary.renameTo(destination)) {
				throw new IOException("unable to atomically rename credential file");
			}
		} catch (IOException e) {
			if (temporary != null) {
				try { temporary.delete(); } catch (RuntimeException ignored) { }
			}
			throw new IllegalStateException("Credential update was not durably committed", e);
		}
	}

	private Configuration readFromDisk() throws IOException {
		if (!Files.exists(configFile, LinkOption.NOFOLLOW_LINKS)) {
			return ImmutableConfiguration.builder().build();
		}
		if (Files.isSymbolicLink(configFile)) {
			throw new IOException("Credential file must not be a symbolic link");
		}
		// Avoid java.nio FileChannel here as well; the ARMv6 Java runtime may
		// report ENOSYS while initializing its native FileDispatcher.
		java.io.ByteArrayOutputStream bytes = new java.io.ByteArrayOutputStream();
		try (java.io.FileInputStream input = new java.io.FileInputStream(configFile.toFile())) {
			byte[] buffer = new byte[4096];
			int count;
			while ((count = input.read(buffer)) != -1) bytes.write(buffer, 0, count);
		}
		String json = new String(bytes.toByteArray(), StandardCharsets.UTF_8);
		Configuration loaded = gson.fromJson(json, Configuration.class);
		if (loaded == null) throw new IOException("Credential file is empty");
		return loaded;
	}
}
