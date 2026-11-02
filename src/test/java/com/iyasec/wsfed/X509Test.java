// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.wsfed;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import javax.security.auth.x500.X500Principal;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class X509Test {
    private static final byte[] SKI = new byte[] {0x06, 0x03, 0x55, 0x1d, 0x0e};
    private static final byte[] AKI = new byte[] {0x06, 0x03, 0x55, 0x1d, 0x23};

    @Test
    void signsItselfAndNamesItsKey() throws Exception {
        X509Material pair = X509Material.createSelfSignedKeyPair("rp", 30, 2048);
        pair.certificate.verify(pair.certificate.getPublicKey());
        byte[] want = MessageDigest.getInstance("SHA-1").digest(X509Material.subjectPublicKeyBits(pair.certificate.getPublicKey().getEncoded()));
        byte[] der = pair.certificate.getEncoded();
        assertTrueEquals(want, keyIdAfter(der, SKI));
        assertTrueEquals(want, keyIdAfter(der, AKI));
    }

    @Test
    void twoCertificatesOfOneNameHaveDifferentKeyIdentifiers() throws Exception {
        X509Material one = X509Material.createSelfSignedKeyPair("localhost:3000", 30, 2048);
        X509Material two = X509Material.createSelfSignedKeyPair("localhost:3000", 30, 2048);
        assertEquals(one.certificate.getSubjectX500Principal(), two.certificate.getSubjectX500Principal());
        assertNotEquals(Arrays.toString(keyIdAfter(one.certificate.getEncoded(), SKI)), Arrays.toString(keyIdAfter(two.certificate.getEncoded(), SKI)));
    }

    @Test
    void generateKeysNamesTheCertificateAfterTheRealm(@TempDir Path tmp) throws Exception {
        Path config = tmp.resolve("wsfed.json");
        Files.writeString(config, Json.stringify(map(
                "realm", "http://localhost:3000/",
                "replyUrl", "http://localhost:3000/wsfed",
                "idpMetadata", "x",
                "privateKey", "k.pem",
                "certificate", "c.pem")));
        Cli.run(new String[] {"generate-keys", "--config", config.toString(), "--bits", "2048"}, text -> { });
        var cert = Config.certificate(Files.readString(tmp.resolve("c.pem")));
        assertEquals("CN=wsfed-caep-nodejs relying party http://localhost:3000/", cert.getSubjectX500Principal().getName(X500Principal.RFC2253));
    }

    private static void assertTrueEquals(byte[] left, byte[] right) {
        if (!Arrays.equals(left, right)) throw new AssertionError(Arrays.toString(left) + " != " + Arrays.toString(right));
    }

    private static byte[] keyIdAfter(byte[] cert, byte[] oid) {
        int at = indexOf(cert, oid);
        byte[] rest = Arrays.copyOfRange(cert, at + oid.length, cert.length);
        int marker = indexOf(rest, new byte[] {0x14});
        int start = at + oid.length + marker + 1;
        return Arrays.copyOfRange(cert, start, start + 20);
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            boolean ok = true;
            for (int j = 0; j < needle.length; j++) if (haystack[i + j] != needle[j]) ok = false;
            if (ok) return i;
        }
        throw new AssertionError("marker missing");
    }

    private static java.util.Map<String, Object> map(String k1, String v1, String k2, String v2, String k3, String v3, String k4, String v4, String k5, String v5) {
        java.util.Map<String, Object> out = new java.util.LinkedHashMap<>();
        out.put(k1, v1);
        out.put(k2, v2);
        out.put(k3, v3);
        out.put(k4, v4);
        out.put(k5, v5);
        return out;
    }
}
