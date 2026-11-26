// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.wsfed.pep;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.iyasec.pep.Decision;
import com.iyasec.pep.Mode;
import com.iyasec.pep.Pep;
import com.iyasec.pep.PepConfig;
import com.iyasec.pep.PepException;
import com.iyasec.pep.key.SigningKey;
import com.iyasec.pep.Status;
import com.iyasec.pep.Subject;
import com.iyasec.wsfed.Caught;
import com.iyasec.wsfed.Json;
import com.iyasec.wsfed.Resolved;
import com.iyasec.wsfed.WsFedError;
import com.iyasec.wsfed.WsFedLogin;
import java.math.BigInteger;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

/**
 * Wires {@code com.iyasec:iya-pep} into this relying party. The PEP knows no
 * WS-Federation: this class fills the {@code pep} section's defaults, refuses
 * a key this library already uses, and turns a validated sign-in into the
 * PEP's subject.
 */
public final class EmbeddedPep {
    /**
     * The claim iya-sts puts the person's username in (its directory's
     * canonical uid). It is the PEP subject id. {@code nameidentifier} is the
     * opaque {@code sub} and is never the id.
     */
    public static final String NAME_CLAIM = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name";
    /** The claim that says how the person authenticated. Its values are {@code amr}. */
    public static final String AUTHENTICATION_METHOD_CLAIM = "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod";

    private static final ObjectMapper JSON = new ObjectMapper();

    private EmbeddedPep() {}

    /**
     * Builds the PEP from the configuration's {@code pep} section, or null
     * when there is none. {@code issuer} is the identity provider's entityID,
     * the default {@code pdpUrl}. Does not start it.
     */
    public static Pep build(Resolved config, String issuer) {
        if (config == null || config.pep == null) return null;
        Map<String, Object> map = new LinkedHashMap<>(config.pep);
        if (!map.containsKey("signals")) map.put("signals", !Boolean.FALSE.equals(config.signals));
        if (!map.containsKey("tlsCa") && config.idpCa != null && config.idpCa.contains("-----BEGIN")) {
            map.put("tlsCa", config.idpCa);
        }
        PepConfig pepConfig;
        try {
            pepConfig = PepConfig.fromJson(JSON.readTree(Json.stringify(map)), issuer == null ? "" : issuer, config.realm);
        } catch (PepException err) {
            throw new WsFedError("config", err.detail(), err);
        } catch (Exception err) {
            Caught.error(err);
            throw new WsFedError("config", "pep must be an object", err);
        }
        Pep pep;
        try {
            pep = Pep.create(pepConfig);
        } catch (PepException err) {
            throw new WsFedError("config", err.detail(), err);
        }
        if (config.privateKey != null) {
            String thumbprint = rsaThumbprint(config.privateKey);
            if (thumbprint != null && thumbprint.equals(pep.keyThumbprint())) {
                throw new WsFedError("config", "pep.assertionKey is the relying party's privateKey (its signing and decryption key); the PEP needs a key of its own");
            }
        }
        return pep;
    }

    /** Whether a receiver given this PEP asks for {@code pep-policies-changed}. */
    public static boolean wantsEvents(Pep pep) {
        PepConfig section = pep.config();
        return section.mode == Mode.LOCAL || section.permitCacheMs > 0;
    }

    /**
     * The PEP's subject for a validated sign-in. The id is the {@code name}
     * claim, else the NameID. {@code nameidentifier} is never the id.
     * Properties are attributes keyed by FriendlyName, else the Name's last
     * segment, then {@code acr}, {@code amr} and {@code auth_time}. No request
     * header is read.
     */
    public static Subject subjectOf(WsFedLogin login) {
        Map<String, JsonNode> properties = new LinkedHashMap<>();
        Map<String, List<String>> attributes = login.attributes == null ? Map.of() : login.attributes;
        for (String name : new TreeSet<>(attributes.keySet())) {
            String key = propertyName(name, login.attributeFriendlyNames == null ? null : login.attributeFriendlyNames.get(name));
            if (key == null || properties.containsKey(key)) continue;
            JsonNode value = propertyValue(attributes.get(name));
            if (value != null) properties.put(key, value);
        }
        if (login.authnContextClassRef != null && !login.authnContextClassRef.isEmpty()) {
            properties.put("acr", JSON.valueToTree(login.authnContextClassRef));
        }
        JsonNode methods = propertyValue(attributes.get(AUTHENTICATION_METHOD_CLAIM));
        if (methods != null) {
            if (methods.isArray()) properties.put("amr", methods);
            else {
                var array = JSON.createArrayNode();
                array.add(methods.asText());
                properties.put("amr", array);
            }
        }
        if (login.authnInstant != null) properties.put("auth_time", JSON.valueToTree(login.authnInstant.getEpochSecond()));
        String id = "";
        List<String> names = attributes.get(NAME_CLAIM);
        if (names != null) {
            for (String name : names) {
                if (name != null && !name.isBlank()) {
                    id = name;
                    break;
                }
            }
        }
        if (id.isEmpty() && login.nameId != null) id = login.nameId;
        return Subject.user(id, properties);
    }

    /** A Deny that did not ask the engine. */
    public static Decision deny(String why) {
        return Decision.deny(why);
    }

    /** No {@code pep} section is configured, so nothing is permitted. */
    public static Decision unavailable(String why) {
        return Decision.unavailable(why);
    }

    /** The event body as the JSON {@link Pep#onPolicyEvent} takes. */
    public static JsonNode toJson(Object value) {
        return JSON.valueToTree(value == null ? Map.of() : value);
    }

    /** {@link Pep#status()} as a map a health page can write. It holds no secret. */
    public static Map<String, Object> statusMap(Pep pep) {
        if (pep == null) return null;
        try {
            Status status = pep.status();
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("name", status.name);
            out.put("mode", status.mode == null ? null : status.mode.asString());
            out.put("application", status.application);
            out.put("registered", status.registered);
            out.put("running", status.running);
            out.put("holdsPolicy", status.holdsPolicy);
            out.put("policyCount", status.policyCount);
            out.put("syncToken", status.syncToken);
            out.put("decisions", status.decisions);
            out.put("allowed", status.allowed);
            out.put("refused", status.refused);
            out.put("unavailable", status.unavailable);
            out.put("keyThumbprint", status.keyThumbprint);
            out.put("lastError", status.lastError);
            out.put("pdpUrl", status.pdpUrl);
            out.put("eventStream", status.eventStream == null ? null : status.eventStream.asString());
            out.put("eventsReceived", status.eventsReceived);
            out.put("catalogueSubjectProperties", status.catalogueSubjectProperties);
            return out;
        } catch (RuntimeException err) {
            Caught.warn(err);
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("error", "status could not be read");
            return out;
        }
    }

    /**
     * An attribute's property name: its FriendlyName, else the last segment
     * of its Name, when it is one the catalogue can declare
     * ({@code [A-Za-z0-9_$@:-]}, 1 to 64). A dot is not in that set, so an
     * OID with no usable segment is left out.
     */
    static String propertyName(String name, String friendly) {
        if (segment(friendly)) return friendly;
        String last = name == null ? "" : name;
        int slash = last.lastIndexOf('/');
        if (slash >= 0) last = last.substring(slash + 1);
        return segment(last) ? last : null;
    }

    private static boolean segment(String text) {
        if (text == null || text.isEmpty() || text.length() > 64) return false;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            boolean ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '_' || c == '$' || c == '@' || c == ':' || c == '-';
            if (!ok) return false;
        }
        return true;
    }

    /** A single remaining value is a string, several an array. Empty values are skipped. */
    private static JsonNode propertyValue(List<String> values) {
        if (values == null || values.isEmpty()) return null;
        List<String> kept = new ArrayList<>();
        for (String value : values) if (value != null && !value.isEmpty()) kept.add(value);
        if (kept.isEmpty()) return null;
        if (kept.size() == 1) return JSON.valueToTree(kept.get(0));
        return JSON.valueToTree(kept);
    }

    /** The RFC 7638 thumbprint of an RSA key's public half, or null when it cannot be taken. */
    private static String rsaThumbprint(java.security.PrivateKey key) {
        if (!(key instanceof RSAPrivateCrtKey rsa)) return null;
        try {
            ObjectNode jwk = JSON.createObjectNode();
            jwk.put("kty", "RSA");
            jwk.put("n", b64(unsigned(rsa.getModulus())));
            jwk.put("e", b64(unsigned(rsa.getPublicExponent())));
            String thumbprint = SigningKey.jwkThumbprint(jwk);
            return thumbprint == null || thumbprint.isEmpty() ? null : thumbprint;
        } catch (RuntimeException err) {
            Caught.warn(err);
            return null;
        }
    }

    private static byte[] unsigned(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            byte[] trimmed = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, trimmed, 0, trimmed.length);
            return trimmed;
        }
        return bytes;
    }

    private static String b64(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }
}
