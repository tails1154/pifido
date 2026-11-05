package com.github.mphi_rc.fido2.protocol.usbhid;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.jce.X509Principal;
import java.security.Security;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.mphi_rc.fido2.ConfigurationFile;
import com.github.mphi_rc.fido2.authenticator.Credential;
import com.github.mphi_rc.fido2.authenticator.ImmutableCredential;
import com.github.mphi_rc.fido2.authenticator.crypto.P256AttestationKeyPair;

/** Minimal CTAP1/U2F APDU implementation used by browsers that issue CTAPHID_MSG. */
final class U2fHandler {
    private static final Logger log = LoggerFactory.getLogger(U2fHandler.class);
    private static final byte[] OK = {(byte)0x90, 0x00};
    private static final byte[] VERSION = {'U','2','F','_','V','2', (byte)0x90, 0x00};
    private static final SecureRandom RANDOM = new SecureRandom();
    static { Security.addProvider(new BouncyCastleProvider()); }
    private final ConfigurationFile config;
    private static final P256AttestationKeyPair ATTESTATION = P256AttestationKeyPair.generate();
    private static final byte[] ATTESTATION_CERT = makeCertificate();
    U2fHandler(ConfigurationFile config) { this.config = config; }

    byte[] handle(byte[] apdu) {
        if (apdu.length < 2) return status(0x6d00);
        int ins = apdu[1] & 0xff;
        log.info("U2F APDU INS=0x{} length={}", Integer.toHexString(ins), apdu.length);
        if (ins == 0x03) return VERSION;
        if (apdu.length < 7) return status(0x6700);
        int lc = ((apdu[5] & 0xff) << 8) | (apdu[6] & 0xff);
        if (lc > apdu.length - 7) lc = apdu.length - 7;
        byte[] data = Arrays.copyOfRange(apdu, 7, 7 + lc);
        try {
            if (ins == 0x01 && data.length >= 64) return register(data);
            if (ins == 0x02 && data.length >= 65) return authenticate(data);
        } catch (Exception e) { log.error("U2F APDU failed", e); return status(0x6f00); }
        return status(0x6d00);
    }

    private byte[] register(byte[] d) throws Exception {
        byte[] challenge = Arrays.copyOfRange(d, 0, 32), app = Arrays.copyOfRange(d, 32, 64);
        String rp = hex(app);
        if (!config.userVerifier().isRegistrationApproved(rp)) return status(0x6985);
        P256AttestationKeyPair key = P256AttestationKeyPair.generate();
        byte[] id = new byte[32]; RANDOM.nextBytes(id);
        Credential c = ImmutableCredential.builder().relayingPartyId(rp).creation(java.time.Instant.now())
                .userId(new byte[0]).keyPair(key).signatureCount(0).id(id).build();
        config.addCredential(c);
        byte[] pub = ((BCECPublicKey)KeyFactory.getInstance("EC", "BC")
                .generatePublic(new java.security.spec.X509EncodedKeySpec(key.publicKey()))).getQ().getEncoded(false);
        byte[] signed = concat(new byte[]{0}, app, challenge, new byte[]{(byte)id.length}, id, pub);
        PrivateKey attestPrivate = KeyFactory.getInstance("EC", "BC").generatePrivate(new PKCS8EncodedKeySpec(ATTESTATION.privateKey()));
        Signature sig = Signature.getInstance("SHA256withECDSA", "BC"); sig.initSign(attestPrivate); sig.update(signed);
        return concat(new byte[]{5}, pub, new byte[]{(byte)id.length}, id, ATTESTATION_CERT, sig.sign(), OK);
    }

    private byte[] authenticate(byte[] d) throws Exception {
        byte[] challenge = Arrays.copyOfRange(d, 0, 32), app = Arrays.copyOfRange(d, 32, 64);
        int len = d[64] & 0xff;
        if (len == 0 || d.length < 65 + len) return status(0x6700);
        byte[] id = Arrays.copyOfRange(d, 65, 65 + len);
        String rp = hex(app); Credential found = null;
        for (Credential c : config.credentials()) if (c.relayingPartyId().equals(rp) && Arrays.equals(c.id(), id)) { found = c; break; }
        if (found == null) return status(0x6a80);
        if (!config.userVerifier().isAuthenticationApproved(rp)) return status(0x6985);
        int counter = found.signatureCount() + 1;
        byte[] msg = concat(app, new byte[]{1}, ByteBuffer.allocate(4).putInt(counter).array(), challenge);
        PrivateKey privateKey = KeyFactory.getInstance("EC", "BC").generatePrivate(new PKCS8EncodedKeySpec(found.keyPair().privateKey()));
        Signature sig = Signature.getInstance("SHA256withECDSA", "BC"); sig.initSign(privateKey); sig.update(msg);
        List<Credential> all = new java.util.ArrayList<>(config.credentials());
        all.remove(found); all.add(ImmutableCredential.builder().from(found).signatureCount(counter).build()); config.updateAllStoredCredentials(all);
        return concat(new byte[]{1}, ByteBuffer.allocate(4).putInt(counter).array(), sig.sign(), OK);
    }
    private static byte[] status(int v) { return new byte[]{(byte)(v >>> 8), (byte)v}; }
    private static byte[] concat(byte[]... xs) { ByteArrayOutputStream o = new ByteArrayOutputStream(); for (byte[] x: xs) o.write(x,0,x.length); return o.toByteArray(); }
    private static String hex(byte[] b) { StringBuilder s=new StringBuilder(); for(byte x:b)s.append(String.format("%02x",x)); return s.toString(); }
    private static byte[] makeCertificate() {
        try {
            PrivateKey k = KeyFactory.getInstance("EC", "BC").generatePrivate(new PKCS8EncodedKeySpec(ATTESTATION.privateKey()));
            java.security.PublicKey p = KeyFactory.getInstance("EC", "BC").generatePublic(new java.security.spec.X509EncodedKeySpec(ATTESTATION.publicKey()));
            X509V3CertificateGenerator g = new X509V3CertificateGenerator();
            X509Principal n = new X509Principal("CN=PiFIDO U2F Attestation");
            g.setSerialNumber(java.math.BigInteger.ONE); g.setIssuerDN(n); g.setSubjectDN(n); g.setPublicKey(p);
            g.setNotBefore(new java.util.Date(System.currentTimeMillis()-60000));
            g.setNotAfter(new java.util.Date(System.currentTimeMillis()+31536000000L));
            g.setSignatureAlgorithm("SHA256withECDSA");
            return g.generateX509Certificate(k, "BC").getEncoded();
        } catch (Exception e) { throw new ExceptionInInitializerError(e); }
    }
}
