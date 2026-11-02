// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.wsfed;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.spec.MGF1ParameterSpec;
import java.util.Base64;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import org.w3c.dom.Element;

/** RSA-OAEP plus AES-GCM or AES-CBC. RSA PKCS#1 v1.5 is refused. */
public final class XmlEncryption {
    private static final String OAEP_MGF1P = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
    private static final String OAEP = "http://www.w3.org/2009/xmlenc11#rsa-oaep";
    private static final Map<String, String> DIGESTS = Map.of(
            "http://www.w3.org/2000/09/xmldsig#sha1", "SHA-1",
            "http://www.w3.org/2001/04/xmlenc#sha256", "SHA-256",
            "http://www.w3.org/2001/04/xmldsig-more#sha384", "SHA-384",
            "http://www.w3.org/2001/04/xmlenc#sha512", "SHA-512");
    private static final Map<String, String> MGFS = Map.of(
            "http://www.w3.org/2009/xmlenc11#mgf1sha1", "SHA-1",
            "http://www.w3.org/2009/xmlenc11#mgf1sha256", "SHA-256",
            "http://www.w3.org/2009/xmlenc11#mgf1sha384", "SHA-384",
            "http://www.w3.org/2009/xmlenc11#mgf1sha512", "SHA-512");

    private record CipherSpec(String name, boolean gcm, int keyLength) {}

    private static final Map<String, CipherSpec> CIPHERS = Map.of(
            "http://www.w3.org/2009/xmlenc11#aes128-gcm", new CipherSpec("aes-128-gcm", true, 16),
            "http://www.w3.org/2009/xmlenc11#aes192-gcm", new CipherSpec("aes-192-gcm", true, 24),
            "http://www.w3.org/2009/xmlenc11#aes256-gcm", new CipherSpec("aes-256-gcm", true, 32),
            "http://www.w3.org/2001/04/xmlenc#aes128-cbc", new CipherSpec("aes-128-cbc", false, 16),
            "http://www.w3.org/2001/04/xmlenc#aes192-cbc", new CipherSpec("aes-192-cbc", false, 24),
            "http://www.w3.org/2001/04/xmlenc#aes256-cbc", new CipherSpec("aes-256-cbc", false, 32));

    private XmlEncryption() {}

    public static String decryptElement(Element encrypted, PrivateKey key) {
        Element data = Xmls.is(encrypted, Xmls.XENC, "EncryptedData") ? encrypted : Xmls.child(encrypted, Xmls.XENC, "EncryptedData");
        if (data == null) fail("<" + encrypted.getLocalName() + "> has no EncryptedData");
        Element method = Xmls.child(data, Xmls.XENC, "EncryptionMethod");
        String alg = method == null ? null : Xmls.attr(method, "Algorithm");
        CipherSpec cipher = CIPHERS.get(alg == null ? "" : alg);
        if (cipher == null) fail("the content is encrypted with " + (alg == null || alg.isEmpty() ? "(none)" : alg) + ", which is not supported");
        var keys = Xmls.descendants(encrypted, Xmls.XENC, "EncryptedKey");
        if (keys.isEmpty()) fail("<" + encrypted.getLocalName() + "> carries no EncryptedKey");
        byte[] contentKey = unwrap(keys.get(0), key);
        if (contentKey.length != cipher.keyLength) {
            fail("the content key is " + contentKey.length + " bytes; " + cipher.name + " needs " + cipher.keyLength);
        }
        Element cipherData = Xmls.child(data, Xmls.XENC, "CipherData");
        Element value = cipherData == null ? null : Xmls.child(cipherData, Xmls.XENC, "CipherValue");
        byte[] raw = b64(value == null ? "" : value.getTextContent());
        try {
            if (cipher.gcm) {
                if (raw.length < 28) fail("the ciphertext is too short");
                byte[] iv = java.util.Arrays.copyOfRange(raw, 0, 12);
                byte[] ct = java.util.Arrays.copyOfRange(raw, 12, raw.length);
                Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
                aes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(contentKey, "AES"), new GCMParameterSpec(128, iv));
                return new String(aes.doFinal(ct), StandardCharsets.UTF_8);
            }
            if (raw.length < 32 || raw.length % 16 != 0) fail("the ciphertext is not a whole number of blocks");
            byte[] iv = java.util.Arrays.copyOfRange(raw, 0, 16);
            byte[] ct = java.util.Arrays.copyOfRange(raw, 16, raw.length);
            Cipher aes = Cipher.getInstance("AES/CBC/NoPadding");
            aes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(contentKey, "AES"), new IvParameterSpec(iv));
            byte[] plain = aes.doFinal(ct);
            int pad = plain[plain.length - 1] & 0xff;
            if (pad < 1 || pad > 16) fail("the decrypted content is not padded as XML Encryption pads it");
            return new String(plain, 0, plain.length - pad, StandardCharsets.UTF_8);
        } catch (WsFedError err) {
            throw err;
        } catch (Exception err) {
            Caught.error(err);
            fail("the content could not be decrypted", err);
        }
        throw new AssertionError("unreachable");
    }

    private static byte[] unwrap(Element encryptedKey, PrivateKey key) {
        Element method = Xmls.child(encryptedKey, Xmls.XENC, "EncryptionMethod");
        String alg = method == null ? "" : (Xmls.attr(method, "Algorithm") == null ? "" : Xmls.attr(method, "Algorithm"));
        if (!OAEP_MGF1P.equals(alg) && !OAEP.equals(alg)) {
            fail("the content key is wrapped with " + (alg.isEmpty() ? "(none)" : alg) + "; only RSA-OAEP is accepted");
        }
        Element digestMethod = method == null ? null : Xmls.child(method, Xmls.DS, "DigestMethod");
        String digestAlg = digestMethod == null ? null : Xmls.attr(digestMethod, "Algorithm");
        String digest = digestAlg == null ? "SHA-1" : DIGESTS.get(digestAlg);
        if (digestAlg != null && digest == null) fail("the OAEP digest " + digestAlg + " is not supported");
        String mgf = "SHA-1";
        if (OAEP.equals(alg) && method != null) {
            Element mgfEl = Xmls.child(method, Xmls.XENC11, "MGF");
            String mgfAlg = mgfEl == null ? null : Xmls.attr(mgfEl, "Algorithm");
            if (mgfAlg != null) {
                if (!MGFS.containsKey(mgfAlg)) fail("the OAEP mask generation function " + mgfAlg + " is not supported");
                mgf = MGFS.get(mgfAlg);
            }
        }
        if (!mgf.equals(digest)) {
            fail("OAEP with digest " + digest + " and MGF1 " + mgf + " is not supported; node:crypto uses one hash for both");
        }
        var values = Xmls.descendants(encryptedKey, Xmls.XENC, "CipherValue");
        try {
            OAEPParameterSpec spec = new OAEPParameterSpec(digest, "MGF1", mgfSpec(digest), PSource.PSpecified.DEFAULT);
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, spec);
            return cipher.doFinal(b64(values.isEmpty() ? "" : values.get(0).getTextContent()));
        } catch (WsFedError err) {
            throw err;
        } catch (Exception err) {
            Caught.error(err);
            fail("the content key could not be unwrapped with this relying party's key", err);
        }
        throw new AssertionError("unreachable");
    }

    private static MGF1ParameterSpec mgfSpec(String digest) {
        return switch (digest) {
            case "SHA-1" -> MGF1ParameterSpec.SHA1;
            case "SHA-256" -> MGF1ParameterSpec.SHA256;
            case "SHA-384" -> MGF1ParameterSpec.SHA384;
            case "SHA-512" -> MGF1ParameterSpec.SHA512;
            default -> throw new WsFedError("decryption", "the OAEP digest " + digest + " is not supported");
        };
    }

    private static byte[] b64(String value) {
        return Base64.getMimeDecoder().decode(value.replaceAll("\\s+", ""));
    }

    private static void fail(String message) {
        throw new WsFedError("decryption", message);
    }

    private static void fail(String message, Throwable cause) {
        throw new WsFedError("decryption", message, cause);
    }
}
