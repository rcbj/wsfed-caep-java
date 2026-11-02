// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.wsfed;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

/** A self-signed certificate. The DER is written by hand, the same shape as the Node library. */
public final class X509Material {
    public final String privateKeyPem;
    public final String certificatePem;
    public final X509Certificate certificate;

    public X509Material(String privateKeyPem, String certificatePem, X509Certificate certificate) {
        this.privateKeyPem = privateKeyPem;
        this.certificatePem = certificatePem;
        this.certificate = certificate;
    }

    public static X509Material createSelfSignedKeyPair(String commonName) {
        return createSelfSignedKeyPair(commonName, 1095, 3072);
    }

    public static X509Material createSelfSignedKeyPair(String commonName, int days, int bits) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(bits);
            var pair = generator.generateKeyPair();
            byte[] serial = new byte[16];
            new SecureRandom().nextBytes(serial);
            serial[0] = (byte) (serial[0] & 0x7f);
            if (serial[0] == 0) serial[0] = 1;
            Instant notBefore = Instant.now().minusSeconds(60);
            Instant notAfter = notBefore.plusSeconds(days * 86_400L);
            byte[] spki = pair.getPublic().getEncoded();
            byte[] keyId = MessageDigest.getInstance("SHA-1").digest(subjectPublicKeyBits(spki));
            byte[] extensions = tlv(0xa3, seq(
                    seq(oid("2.5.29.14"), tlv(0x04, tlv(0x04, keyId))),
                    seq(oid("2.5.29.35"), tlv(0x04, seq(tlv(0x80, keyId)))),
                    seq(oid("2.5.29.19"), tlv(0x01, new byte[] {(byte) 0xff}), tlv(0x04, seq())),
                    seq(oid("2.5.29.15"), tlv(0x01, new byte[] {(byte) 0xff}), tlv(0x04, tlv(0x03, new byte[] {0x05, (byte) 0xa0})))
            ));
            byte[] sha256Rsa = seq(oid("1.2.840.113549.1.1.11"), new byte[] {0x05, 0x00});
            byte[] tbs = seq(
                    tlv(0xa0, tlv(0x02, new byte[] {0x02})),
                    tlv(0x02, serial),
                    sha256Rsa,
                    name(commonName),
                    seq(time(notBefore), time(notAfter)),
                    name(commonName),
                    spki,
                    extensions
            );
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(pair.getPrivate());
            signer.update(tbs);
            byte[] signature = signer.sign();
            byte[] der = seq(tbs, sha256Rsa, tlv(0x03, concat(new byte[] {0}, signature)));
            String certificatePem = "-----BEGIN CERTIFICATE-----\n" + wrap(Base64.getEncoder().encodeToString(der)) + "\n-----END CERTIFICATE-----\n";
            X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(certificatePem.getBytes(StandardCharsets.US_ASCII)));
            String privatePem = "-----BEGIN PRIVATE KEY-----\n" + wrap(Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded())) + "\n-----END PRIVATE KEY-----\n";
            return new X509Material(privatePem, certificatePem, certificate);
        } catch (WsFedError err) {
            throw err;
        } catch (Exception err) {
            Caught.error(err);
            throw new WsFedError("config", "the self-signed certificate could not be built: " + err.getMessage(), err);
        }
    }

    static byte[] subjectPublicKeyBits(byte[] spki) {
        int[] outer = header(spki, 0);
        int[] algorithm = header(spki, outer[0]);
        int[] bits = header(spki, algorithm[1]);
        byte[] out = new byte[bits[1] - (bits[0] + 1)];
        System.arraycopy(spki, bits[0] + 1, out, 0, out.length);
        return out;
    }

    private static int[] header(byte[] spki, int at) {
        int first = spki[at + 1] & 0xff;
        if (first < 0x80) return new int[] {at + 2, at + 2 + first};
        int n = first & 0x7f;
        int len = 0;
        for (int i = 0; i < n; i++) len = len * 256 + (spki[at + 2 + i] & 0xff);
        return new int[] {at + 2 + n, at + 2 + n + len};
    }

    private static byte[] name(String cn) {
        return seq(set(seq(oid("2.5.4.3"), tlv(0x0c, cn.getBytes(StandardCharsets.UTF_8)))));
    }

    private static byte[] time(Instant moment) {
        var utc = moment.atOffset(ZoneOffset.UTC);
        String iso = DateTimeFormatter.ofPattern("yyyyMMddHHmmss").format(utc) + "Z";
        if (utc.getYear() < 2050) return tlv(0x17, iso.substring(2).getBytes(StandardCharsets.US_ASCII));
        return tlv(0x18, iso.getBytes(StandardCharsets.US_ASCII));
    }

    private static byte[] oid(String dotted) {
        String[] parts = dotted.split("\\.");
        int[] numbers = new int[parts.length];
        for (int i = 0; i < parts.length; i++) numbers[i] = Integer.parseInt(parts[i]);
        byte[] body = new byte[32];
        int n = 0;
        body[n++] = (byte) (numbers[0] * 40 + numbers[1]);
        for (int i = 2; i < numbers.length; i++) {
            int value = numbers[i];
            int size = 1;
            for (int v = value >> 7; v > 0; v >>= 7) size++;
            for (int shift = (size - 1) * 7; shift >= 0; shift -= 7) {
                int chunk = (value >> shift) & 0x7f;
                if (shift > 0) chunk |= 0x80;
                body[n++] = (byte) chunk;
            }
        }
        byte[] trimmed = new byte[n];
        System.arraycopy(body, 0, trimmed, 0, n);
        return tlv(0x06, trimmed);
    }

    private static byte[] length(int n) {
        if (n < 0x80) return new byte[] {(byte) n};
        byte[] raw = BigInteger.valueOf(n).toByteArray();
        if (raw[0] == 0) {
            byte[] trimmed = new byte[raw.length - 1];
            System.arraycopy(raw, 1, trimmed, 0, trimmed.length);
            raw = trimmed;
        }
        byte[] out = new byte[1 + raw.length];
        out[0] = (byte) (0x80 | raw.length);
        System.arraycopy(raw, 0, out, 1, raw.length);
        return out;
    }

    private static byte[] tlv(int tag, byte[]... content) {
        byte[] body = concat(content);
        return concat(new byte[] {(byte) tag}, length(body.length), body);
    }

    private static byte[] seq(byte[]... content) { return tlv(0x30, content); }
    private static byte[] set(byte[]... content) { return tlv(0x31, content); }

    private static byte[] concat(byte[]... parts) {
        int n = 0;
        for (byte[] part : parts) n += part.length;
        byte[] out = new byte[n];
        int at = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, at, part.length);
            at += part.length;
        }
        return out;
    }

    private static String wrap(String b64) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < b64.length(); i += 64) {
            if (out.length() > 0) out.append('\n');
            out.append(b64, i, Math.min(i + 64, b64.length()));
        }
        return out.toString();
    }

    @SuppressWarnings("unused")
    private static RSAPrivateCrtKey unused() { return null; }
}
