package com.github.mphi_rc.fido2;

import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import com.google.gson.Gson;

/** Minimal local management channel on the separate hidg1 interface. */
final class ManagementHidServer implements Runnable {
    private final ConfigurationFile config;
    private final Gson gson = new Gson();
    ManagementHidServer(ConfigurationFile config) { this.config = config; }
    void start() { Thread t = new Thread(this, "pifido-management"); t.setDaemon(true); t.start(); }
    @Override public void run() {
        while (true) try (RandomAccessFile ep0 = new RandomAccessFile("/dev/ffs-authui/ep0", "rw")) {
            ep0.write(descriptors());
            try (RandomAccessFile hid = new RandomAccessFile("/dev/ffs-authui/ep1", "rw");
                 RandomAccessFile in = new RandomAccessFile("/dev/ffs-authui/ep2", "rw")) {
            byte[] report = new byte[64];
            while (true) {
                hid.readFully(report);
                int n = ((report[0] & 255) << 24) | ((report[1] & 255) << 16) | ((report[2] & 255) << 8) | (report[3] & 255);
                if (n < 0 || n > 60) { write(hid, error("invalid frame")); continue; }
                Map<?, ?> request = gson.fromJson(new String(report, 4, n, StandardCharsets.UTF_8), Map.class);
                write(in, handle(request));
            }
            }
        } catch (Exception e) { try { Thread.sleep(500); } catch (InterruptedException ignored) { return; } }
    }
    private byte[] descriptors() {
        byte[] d = new byte[28 + 23 * 2]; int p=0;
        p=u32(d,p,3); p=u32(d,p,d.length); p=u32(d,p,3); p=u32(d,p,2); p=u32(d,p,2); p=u32(d,p,0); p=u32(d,p,0);
        p=desc(d,p); p=desc(d,p); return d;
    }
    private int u32(byte[] b,int p,int v){ b[p]=(byte)v;b[p+1]=(byte)(v>>>8);b[p+2]=(byte)(v>>>16);b[p+3]=(byte)(v>>>24);return p+4; }
    private int desc(byte[] b,int p){ byte[] x={9,4,1,0,2,(byte)0xff,0,0,0,7,5,1,2,64,0,0,7,5,(byte)0x81,2,64,0,0}; System.arraycopy(x,0,b,p,x.length); return p+x.length; }
    private byte[] handle(Map<?, ?> r) {
        String op = String.valueOf(r.get("op"));
        Map<String,Object> out = new LinkedHashMap<>(); out.put("ok", true);
        if ("status".equals(op)) {
            out.put("device", "PiFIDO"); out.put("requirePhysicalPresence", true); out.put("pinChangeRequired", config.pinChangeRequired());
        } else if ("listCredentials".equals(op)) {
            java.util.List<Map<String,Object>> list = new java.util.ArrayList<>();
            for (com.github.mphi_rc.fido2.authenticator.Credential c : config.credentials()) {
                Map<String,Object> item = new LinkedHashMap<>(); item.put("rpId", c.relayingPartyId()); item.put("credentialId", Base64.getUrlEncoder().withoutPadding().encodeToString(c.id())); item.put("userName", ""); list.add(item);
            }
            out.put("credentials", list);
        } else { return error("management operation unavailable"); }
        return frame(gson.toJson(out));
    }
    private byte[] error(String s) { Map<String,Object> m = new LinkedHashMap<>(); m.put("ok", false); m.put("error", s); return frame(gson.toJson(m)); }
    private byte[] frame(String s) { byte[] b = s.getBytes(StandardCharsets.UTF_8), out = new byte[64]; int n = Math.min(60, b.length); out[0]=(byte)(n>>>24); out[1]=(byte)(n>>>16); out[2]=(byte)(n>>>8); out[3]=(byte)n; System.arraycopy(b,0,out,4,n); return out; }
    private void write(RandomAccessFile f, byte[] b) throws java.io.IOException { f.write(b); }
}
