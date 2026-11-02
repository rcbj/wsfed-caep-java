// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.wsfed.ssf;

import com.iyasec.wsfed.Caught;
import com.iyasec.wsfed.Json;
import com.iyasec.wsfed.WsFedError;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Verify a Security Event Token (compact JWS). none and HMAC are refused. */
public final class Jws {
    public static final List<String> SUPPORTED = List.of(
            "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA", "Ed25519");
    private static final Set<String> RSA = Set.of("RS256", "RS384", "RS512", "PS256", "PS384", "PS512");
    private static final Set<String> EC = Set.of("ES256", "ES384", "ES512");
    private static final Set<String> OKP = Set.of("EdDSA", "Ed25519");

    public static final class Verified {
        public final Map<String, Object> header;
        public final Map<String, Object> payload;

        public Verified(Map<String, Object> header, Map<String, Object> payload) {
            this.header = header;
            this.payload = payload;
        }
    }

    private Jws() {}

    private static String pad(String value) {
        int mod = value.length() % 4;
        if (mod == 0) return value;
        return value + "=".repeat(4 - mod);
    }

    public static Verified verify(String token, List<Map<String, Object>> keys) {
        try {
            String[] parts = token == null ? new String[0] : token.split("\\.");
            if (parts.length != 3) throw new WsFedError("signature", "the SET is not a compact JWS");
            Object headerJson = Json.parse(new String(java.util.Base64.getUrlDecoder().decode(pad(parts[0])), java.nio.charset.StandardCharsets.UTF_8));
            Map<String, Object> headerMap = Json.object(headerJson);
            if (headerMap == null) throw new WsFedError("signature", "the SET's header or payload is not a JSON object");
            String name = headerMap.get("alg") == null ? "" : String.valueOf(headerMap.get("alg"));
            if (!SUPPORTED.contains(name)) {
                throw new WsFedError("signature", "the SET is signed with " + (name.isEmpty() ? "(no alg)" : name)
                        + ", which this receiver does not verify (" + String.join(", ", SUPPORTED) + ")");
            }
            SignedJWT jwt = SignedJWT.parse(token);
            if (jwt.getHeader().getCriticalParams() != null && !jwt.getHeader().getCriticalParams().isEmpty()) {
                throw new WsFedError("signature", "the SET's header has a crit member this receiver does not understand");
            }
            String kid = jwt.getHeader().getKeyID();
            String kty = RSA.contains(name) ? "RSA" : EC.contains(name) ? "EC" : "OKP";
            List<Map<String, Object>> candidates = new ArrayList<>();
            for (Map<String, Object> key : keys) {
                if (kid != null && !kid.equals(key.get("kid"))) continue;
                if (!kty.equals(key.get("kty"))) continue;
                if (key.get("use") != null && !key.get("use").equals("sig")) continue;
                if (key.get("alg") != null && !key.get("alg").equals(name)) continue;
                candidates.add(key);
            }
            if (candidates.isEmpty()) {
                throw new WsFedError("signature", "the transmitter publishes no " + kty + " signing key" + (kid == null ? "" : " with kid " + kid));
            }
            for (Map<String, Object> jwk : candidates) {
                try {
                    JWK parsed = JWK.parse(Json.stringify(jwk));
                    boolean ok;
                    if (parsed instanceof RSAKey rsa) ok = jwt.verify(new RSASSAVerifier(rsa));
                    else if (parsed instanceof ECKey ec) ok = jwt.verify(new ECDSAVerifier(ec));
                    else if (parsed instanceof OctetKeyPair okp) ok = jwt.verify(new Ed25519Verifier(okp));
                    else ok = false;
                    if (!ok) continue;
                    Object header = Json.parse(jwt.getHeader().toString());
                    Object payload = Json.parse(jwt.getPayload().toString());
                    Map<String, Object> verifiedHeader = Json.object(header);
                    Map<String, Object> payloadMap = Json.object(payload);
                    if (verifiedHeader == null || payloadMap == null) {
                        throw new WsFedError("signature", "the SET's header or payload is not a JSON object");
                    }
                    return new Verified(verifiedHeader, payloadMap);
                } catch (WsFedError err) {
                    throw err;
                } catch (Exception ignored) {
                    // try the next published key
                }
            }
            throw new WsFedError("signature", "the SET's signature does not verify against the transmitter's keys");
        } catch (WsFedError err) {
            throw err;
        } catch (Exception err) {
            Caught.error(err);
            throw new WsFedError("signature", "the SET is not a compact JWS", err);
        }
    }
}
