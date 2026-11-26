// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.wsfed;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;

/**
 * PEM private keys and certificate chains for the Shared Signals receiver's
 * TLS client identity. The relying party's own key stays RSA PKCS#8
 * ({@link Config#privateKey}).
 */
public final class Keys {
    private Keys() {}

    /** PKCS#8 (RSA or EC), PKCS#1 RSA, or SEC1 EC P-256 ({@code BEGIN EC PRIVATE KEY}). */
    public static PrivateKey loadPrivateKey(String pem) throws Exception {
        String kind = kind(pem);
        byte[] der = der(pem);
        if ("pkcs8".equals(kind)) {
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
            try {
                return KeyFactory.getInstance("RSA").generatePrivate(spec);
            } catch (Exception rsa) {
                return KeyFactory.getInstance("EC").generatePrivate(spec);
            }
        }
        if ("pkcs1".equals(kind)) {
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(wrapPkcs1(der)));
        }
        if ("sec1".equals(kind)) {
            return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(wrapSec1(der)));
        }
        throw new IllegalArgumentException("the client key cannot be read");
    }

    /** Every certificate in the PEM, leaf first. */
    public static List<X509Certificate> certificates(String pem) throws Exception {
        Collection<? extends java.security.cert.Certificate> parsed = CertificateFactory.getInstance("X.509")
                .generateCertificates(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
        List<X509Certificate> out = new ArrayList<>();
        for (java.security.cert.Certificate certificate : parsed) {
            if (certificate instanceof X509Certificate x509) out.add(x509);
        }
        return out;
    }

    /** Whether the private key signs as the certificate's public key. */
    public static boolean matches(PrivateKey key, X509Certificate certificate) {
        try {
            String algorithm = key instanceof RSAKey ? "SHA256withRSA" : "SHA256withECDSA";
            byte[] challenge = "wsfed-tls-client".getBytes(StandardCharsets.UTF_8);
            Signature signature = Signature.getInstance(algorithm);
            signature.initSign(key);
            signature.update(challenge);
            byte[] signed = signature.sign();
            signature.initVerify(certificate.getPublicKey());
            signature.update(challenge);
            return signature.verify(signed);
        } catch (Exception err) {
            Caught.warn(err);
            return false;
        }
    }

    /**
     * Why {@code cert} (a PEM chain, leaf first) and {@code key} cannot be a
     * TLS client identity, or null when they can. The same check the first
     * connection would make, at configuration time.
     */
    public static String clientIdentityProblem(String cert, String key) {
        try {
            List<X509Certificate> chain = certificates(cert);
            if (chain.isEmpty()) return "the certificate holds no CERTIFICATE block";
            PrivateKey privateKey = loadPrivateKey(key);
            if (!matches(privateKey, chain.get(0))) return "the private key does not match the certificate";
            return null;
        } catch (Exception err) {
            Caught.warn(err);
            String message = err.getMessage();
            return message == null || message.isBlank() ? "the client key cannot be read" : message;
        }
    }

    public static String pem(String label, byte[] der) {
        String body = Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(der);
        return "-----BEGIN " + label + "-----\n" + body + "\n-----END " + label + "-----\n";
    }

    private static String kind(String pem) {
        if (pem != null && pem.contains("-----BEGIN PRIVATE KEY-----")) return "pkcs8";
        if (pem != null && pem.contains("-----BEGIN RSA PRIVATE KEY-----")) return "pkcs1";
        if (pem != null && pem.contains("-----BEGIN EC PRIVATE KEY-----")) return "sec1";
        return "";
    }

    private static byte[] der(String pem) {
        int begin = pem.indexOf("-----BEGIN ");
        int end = pem.indexOf("-----END ");
        String body = begin < 0 || end < 0 ? pem : pem.substring(pem.indexOf('\n', begin) + 1, end);
        return Base64.getMimeDecoder().decode(body.replaceAll("\\s+", ""));
    }

    /** PKCS#1 RSAPrivateKey wrapped as PKCS#8 PrivateKeyInfo. */
    private static byte[] wrapPkcs1(byte[] pkcs1) {
        byte[] oid = {0x06, 0x09, 0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x01, 0x01};
        return seq(integer(0), seq(oid, new byte[] {0x05, 0x00}), octet(pkcs1));
    }

    /** SEC1 ECPrivateKey wrapped as PKCS#8 for named curve prime256v1. */
    private static byte[] wrapSec1(byte[] sec1) {
        byte[] ec = {0x06, 0x07, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x02, 0x01};
        byte[] p256 = {0x06, 0x08, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x03, 0x01, 0x07};
        return seq(integer(0), seq(ec, p256), octet(sec1));
    }

    private static byte[] seq(byte[]... parts) {
        int size = 0;
        for (byte[] part : parts) size += part.length;
        byte[] body = new byte[size];
        int offset = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, body, offset, part.length);
            offset += part.length;
        }
        return tlv(0x30, body);
    }

    private static byte[] integer(int value) {
        return tlv(0x02, new byte[] {(byte) value});
    }

    private static byte[] octet(byte[] body) {
        return tlv(0x04, body);
    }

    private static byte[] tlv(int tag, byte[] body) {
        byte[] length = length(body.length);
        byte[] out = new byte[1 + length.length + body.length];
        out[0] = (byte) tag;
        System.arraycopy(length, 0, out, 1, length.length);
        System.arraycopy(body, 0, out, 1 + length.length, body.length);
        return out;
    }

    private static byte[] length(int size) {
        if (size < 128) return new byte[] {(byte) size};
        if (size < 256) return new byte[] {(byte) 0x81, (byte) size};
        return new byte[] {(byte) 0x82, (byte) (size >> 8), (byte) size};
    }
}
