// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.wsfed;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/** Read wsfed.json. JSON keys stay the Node names. signals omitted or true stays off the result. */
public final class Config {
    private Config() {}

    public static Resolved resolve(Map<String, Object> config, String baseDir) {
        if (config == null) throw new WsFedError("config", "the configuration must be an object");
        String base = baseDir == null || baseDir.isEmpty() ? Path.of("").toAbsolutePath().toString() : baseDir;
        Object realmValue = config.get("realm");
        if (!(realmValue instanceof String realm) || realm.isBlank()) throw new WsFedError("config", "realm is required");
        String reply = absoluteUrl(config.get("replyUrl"), "replyUrl");
        Object rawMetadata = config.get("idpMetadata");
        if (!(rawMetadata instanceof String metadata) || metadata.isBlank()) throw new WsFedError("config", "idpMetadata is required");
        Object skewValue = config.containsKey("clockSkewSeconds") ? config.get("clockSkewSeconds") : 60;
        if (skewValue instanceof Boolean || !(skewValue instanceof Number skew)) {
            throw new WsFedError("config", "clockSkewSeconds must be a number from 0 to 600");
        }
        double skewDouble = skew.doubleValue();
        if (skewDouble < 0 || skewDouble > 600 || Double.isNaN(skewDouble)) {
            throw new WsFedError("config", "clockSkewSeconds must be a number from 0 to 600");
        }
        Resolved out = new Resolved();
        out.realm = realm;
        out.replyUrl = reply;
        out.idpMetadata = idpMetadata(metadata, base);
        boolean fractional = skew instanceof Json.Num num ? !num.integral() : skew instanceof Double || skew instanceof Float;
        out.clockSkewMs = fractional ? (long) (skewDouble * 1000) : skew.longValue() * 1000;
        out.wantAssertionsEncrypted = flag(config, "wantAssertionsEncrypted", false);
        out.allowUnsolicited = flag(config, "allowUnsolicited", false);
        out.requestTokenType = flag(config, "requestTokenType", true);
        if (config.containsKey("signals") && !flag(config, "signals", true)) out.signals = Boolean.FALSE;
        boolean hasKey = config.get("privateKey") != null;
        boolean hasCert = config.get("certificate") != null;
        if (hasKey != hasCert) throw new WsFedError("config", "privateKey and certificate go together: give both or neither");
        if (hasKey) {
            try {
                PrivateKey key = privateKey(material(String.valueOf(config.get("privateKey")), base, "privateKey"));
                X509Certificate certificate = certificate(material(String.valueOf(config.get("certificate")), base, "certificate"));
                if (!(key instanceof RSAPrivateCrtKey rsa) || !(certificate.getPublicKey() instanceof RSAPublicKey pub)
                        || !rsa.getModulus().equals(pub.getModulus()) || !rsa.getPublicExponent().equals(pub.getPublicExponent())) {
                    throw new WsFedError("config", "the certificate is not for the private key");
                }
                out.privateKey = key;
                out.certificate = certificate;
            } catch (WsFedError err) {
                throw err;
            } catch (Exception err) {
                Caught.error(err);
                throw new WsFedError("config", "the private key or certificate cannot be read: " + err.getMessage(), err);
            }
        } else if (out.wantAssertionsEncrypted) {
            throw new WsFedError("config", "wantAssertionsEncrypted needs privateKey and certificate: the assertion is encrypted to them");
        }
        if (config.get("idpCa") instanceof String ca && !ca.isBlank()) out.idpCa = material(ca, base, "idpCa");
        if (config.get("idpEntityId") instanceof String entity && !entity.isBlank()) out.idpEntityId = entity;
        return out;
    }

    public static Resolved readFile(String path, Map<String, Object> overrides) {
        Map<String, Object> parsed;
        try {
            Object value = Json.parse(Files.readString(Path.of(path)));
            parsed = Json.object(value);
            if (parsed == null) throw new WsFedError("config", "the configuration must be an object");
        } catch (WsFedError err) {
            throw new WsFedError("config", path + " cannot be read as JSON: " + err.getMessage(), err);
        } catch (Exception err) {
            Caught.error(err);
            throw new WsFedError("config", path + " cannot be read as JSON: " + err.getMessage(), err);
        }
        Map<String, Object> merged = new LinkedHashMap<>(parsed);
        if (overrides != null) {
            for (Map.Entry<String, Object> entry : overrides.entrySet()) {
                if (entry.getValue() != null) merged.put(entry.getKey(), entry.getValue());
            }
        }
        return resolve(merged, Path.of(path).toAbsolutePath().getParent().toString());
    }

    private static boolean flag(Map<String, Object> config, String key, boolean fallback) {
        if (!config.containsKey(key) || config.get(key) == null) return fallback;
        Object value = config.get(key);
        if (!(value instanceof Boolean on)) throw new WsFedError("config", key + " must be true or false");
        return on;
    }

    private static String absoluteUrl(Object value, String what) {
        if (!(value instanceof String text) || text.isBlank()) throw new WsFedError("config", what + " is required");
        try {
            URI uri = URI.create(text);
            if ((!"https".equals(uri.getScheme()) && !"http".equals(uri.getScheme())) || uri.getHost() == null) {
                throw new IllegalArgumentException("not http(s)");
            }
        } catch (Exception err) {
            Caught.error(err);
            throw new WsFedError("config", what + " must be an absolute http(s) URL, not " + value);
        }
        return (String) value;
    }

    private static String idpMetadata(String value, String base) {
        String text = value.strip();
        if (text.startsWith("env:")) {
            String name = text.substring(4);
            String env = System.getenv(name);
            if (env == null || env.isEmpty()) throw new WsFedError("config", "idpMetadata environment variable " + name + " is not set");
            text = env.strip();
        }
        if (text.startsWith("file:")) text = text.substring(5);
        if (text.startsWith("http://") || text.startsWith("https://") || text.startsWith("<")) return text;
        Path path = Path.of(text);
        return path.isAbsolute() ? path.toString() : Path.of(base).resolve(path).toString();
    }

    private static String material(String value, String base, String what) {
        String text = value;
        if (text.startsWith("env:")) {
            String name = text.substring(4);
            String env = System.getenv(name);
            if (env == null || env.isEmpty()) throw new WsFedError("config", what + " environment variable " + name + " is not set");
            text = env;
        }
        if (text.startsWith("file:")) text = text.substring(5);
        if (text.contains("-----BEGIN ")) return text;
        Path path = Path.of(text);
        Path file = path.isAbsolute() ? path : Path.of(base).resolve(path);
        try {
            return Files.readString(file);
        } catch (Exception err) {
            Caught.error(err);
            throw new WsFedError("config", what + " is neither a PEM nor a readable file (" + file + ")", err);
        }
    }

    static PrivateKey privateKey(String pem) throws Exception {
        String body = pem.replaceAll("-----(BEGIN|END) [A-Z0-9 ]+-----", "").replaceAll("\\s+", "");
        byte[] der = Base64.getMimeDecoder().decode(body);
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    static X509Certificate certificate(String pem) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
    }
}
