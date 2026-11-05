package com.github.mphi_rc.fido2;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
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
		Path temporary = null;
		try {
			byte[] bytes = gson.toJson(config).getBytes(StandardCharsets.UTF_8);
			temporary = Files.createTempFile(configDirectory, "credentials.", ".tmp", OWNER_RW);
			try (FileChannel channel = FileChannel.open(temporary, StandardOpenOption.WRITE)) {
				ByteBuffer data = ByteBuffer.wrap(bytes);
				while (data.hasRemaining()) channel.write(data);
				channel.force(true);
			}
			try {
				Files.move(temporary, configFile, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
			} catch (AtomicMoveNotSupportedException e) {
				throw new IOException("Credential filesystem does not support atomic replacement", e);
			}
			try (FileChannel directory = FileChannel.open(configDirectory, StandardOpenOption.READ)) {
				directory.force(true);
			}
		} catch (IOException e) {
			if (temporary != null) {
				try { Files.deleteIfExists(temporary); } catch (IOException ignored) { }
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
		String json = new String(Files.readAllBytes(configFile), StandardCharsets.UTF_8);
		Configuration loaded = gson.fromJson(json, Configuration.class);
		if (loaded == null) throw new IOException("Credential file is empty");
		return loaded;
	}
}
