// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.wsfed;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.iyasec.pep.Access;
import com.iyasec.pep.Decision;
import com.iyasec.pep.Mode;
import com.iyasec.pep.Pep;
import com.iyasec.wsfed.pep.EmbeddedPep;
import com.iyasec.wsfed.ssf.SignalsReceiver;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The embedded PEP's subject, and the decisions that do not ask it. */
class PepTest {
    @Test
    void subjectIdIsTheNameClaimElseTheNameId() {
        WsFedLogin login = login();
        login.attributes.put(EmbeddedPep.NAME_CLAIM, List.of("alice"));
        login.attributes.put("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier", List.of("urn:uuid:alice"));
        login.nameId = "alice";
        var subject = EmbeddedPep.subjectOf(login);
        assertEquals("alice", subject.id);
        assertEquals("user", subject.kind);
        assertEquals("urn:uuid:alice", subject.properties.get("nameidentifier").asText());
        assertFalse(subject.id.equals(subject.properties.get("nameidentifier").asText()));
    }

    @Test
    void anEmptyNameClaimFallsThroughToTheNameId() {
        WsFedLogin login = login();
        login.attributes.put(EmbeddedPep.NAME_CLAIM, List.of("", "  "));
        login.nameId = "from-nameid";
        assertEquals("from-nameid", EmbeddedPep.subjectOf(login).id);
    }

    @Test
    void propertiesUseFriendlyNameElseTheLastSegmentThenAuthentication() {
        WsFedLogin login = login();
        login.nameId = "alice";
        login.attributes.put("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", List.of("alice@example.com"));
        login.attributeFriendlyNames.put("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "mail");
        login.attributes.put("urn:oid:0.9.2342.19200300.100.1.1", List.of("dropped"));
        login.attributes.put("http://example.test/role", List.of("one", "", "two"));
        login.attributes.put("http://example.test/z-first", List.of("later"));
        login.attributes.put("http://example.test/a-first", List.of("earlier"));
        login.attributeFriendlyNames.put("http://example.test/z-first", "shared");
        login.attributeFriendlyNames.put("http://example.test/a-first", "shared");
        login.attributes.put(EmbeddedPep.AUTHENTICATION_METHOD_CLAIM, List.of("pwd", ""));
        login.authnContextClassRef = "urn:example:acr";
        login.authnInstant = Instant.ofEpochSecond(1_700_000_000L);
        login.attributes.put("http://example.test/acr", List.of("from-attribute"));
        var properties = EmbeddedPep.subjectOf(login).properties;
        assertEquals("alice@example.com", properties.get("mail").asText());
        assertNull(properties.get("emailaddress"));
        assertNull(properties.get("urn:oid:0.9.2342.19200300.100.1.1"));
        assertEquals(2, properties.get("role").size());
        assertEquals("one", properties.get("role").get(0).asText());
        assertEquals("earlier", properties.get("shared").asText());
        assertEquals("urn:example:acr", properties.get("acr").asText());
        assertTrue(properties.get("amr").isArray());
        assertEquals(1, properties.get("amr").size());
        assertEquals("pwd", properties.get("amr").get(0).asText());
        assertEquals(1_700_000_000L, properties.get("auth_time").asLong());
    }

    @Test
    void aSingleAuthenticationMethodIsStillAnArray() {
        WsFedLogin login = login();
        login.attributes.put(EmbeddedPep.AUTHENTICATION_METHOD_CLAIM, List.of("pwd"));
        assertTrue(EmbeddedPep.subjectOf(login).properties.get("amr").isArray());
    }

    @Test
    void noPepSectionIsUnavailable() {
        RelyingParty party = RelyingParty.create(base());
        Decision decision = party.decide(login(), Access.of("read", "order", "42"));
        assertEquals(Decision.Kind.UNAVAILABLE, decision.kind());
        assertEquals(403, decision.httpStatus());
        assertTrue(decision.why().contains("no pep section is configured"));
    }

    @Test
    void aSessionThatEndedOrIsUntrackedIsDenied() {
        RelyingParty party = RelyingParty.create(base());
        SignalsReceiver receiver = new SignalsReceiver("http://127.0.0.1:9", (ids, event) -> { });
        WsFedLogin login = login();
        receiver.track("local", login);
        WsFedLogin endedLogin = login();
        endedLogin.sessionNotOnOrAfter = Instant.now().minusSeconds(5);
        Decision ended = party.decideSession(receiver, "local", endedLogin, Access.of("read", "order", "42"));
        assertEquals(Decision.Kind.DENY, ended.kind());
        assertEquals(403, ended.httpStatus());
        assertTrue(ended.why().contains("session has ended"));
        Decision missing = party.decideSession(receiver, "other", login, Access.of("read", "order", "42"));
        assertEquals(Decision.Kind.DENY, missing.kind());
        assertTrue(missing.why().contains("no signed-in session"));
        assertTrue(receiver.isTracked("local"));
    }

    @Test
    void pepMustBeAnObject() {
        Map<String, Object> config = base();
        config.put("pep", "local");
        WsFedError error = assertThrows(WsFedError.class, () -> RelyingParty.create(config));
        assertTrue(error.getMessage().contains("pep must be an object"));
    }

    @Test
    void thePepKeyMustDifferFromTheRelyingPartyKey(@TempDir Path dir) throws Exception {
        Path key = dir.resolve("same.pem");
        Files.writeString(key, StubIdp.RP_KEY);
        Map<String, Object> config = base();
        config.put("pep", Map.of(
                "name", "pep-demo",
                "assertionKey", key.toString(),
                "timeoutMs", 500,
                "pollIntervalMs", 60000,
                "fallbackPollMs", 60000,
                "heartbeatIntervalMs", 60000));
        WsFedError error = assertThrows(WsFedError.class, () -> RelyingParty.create(config));
        assertTrue(error.getMessage().contains("pep.assertionKey is the relying party's privateKey"));
    }

    @Test
    void aSectionWithoutAModeIsLocalAndUsesTheLibraryDefaults(@TempDir Path dir) throws Exception {
        Path key = dir.resolve("pep.pem");
        Files.writeString(key, StubIdp.IDP_KEY);
        Map<String, Object> section = new LinkedHashMap<>();
        section.put("name", "pep-demo");
        section.put("assertionKey", key.toString());
        section.put("timeoutMs", 500);
        section.put("pollIntervalMs", 60000);
        section.put("fallbackPollMs", 60000);
        section.put("heartbeatIntervalMs", 60000);
        Map<String, Object> config = base();
        config.put("idpCa", StubIdp.IDP_CERT);
        config.put("pep", section);
        RelyingParty party = RelyingParty.create(config);
        try {
            Pep pep = party.pep();
            assertEquals(Mode.LOCAL, pep.config().mode);
            assertEquals(StubIdp.IDP_ENTITY, pep.config().pdpUrl);
            assertEquals(StubIdp.REALM, pep.config().application);
            assertTrue(pep.config().assertionKey.endsWith("pep.pem"));
            assertTrue(pep.config().tlsCa.contains("BEGIN"));
            assertTrue(pep.config().signals);
            assertTrue(pep.status().running);
        } finally {
            if (party.pep() != null) party.pep().stop();
        }
    }

    @Test
    void theReceiverRefusesATlsClientKeyThatIsThePepKey(@TempDir Path dir) throws Exception {
        Path key = dir.resolve("pep.pem");
        Files.writeString(key, StubIdp.IDP_KEY);
        Map<String, Object> config = base();
        config.put("pep", Map.of(
                "name", "pep-demo",
                "mode", "central",
                "assertionKey", key.toString(),
                "pdpUrl", "http://127.0.0.1:9",
                "timeoutMs", 500,
                "pollIntervalMs", 60000,
                "fallbackPollMs", 60000,
                "heartbeatIntervalMs", 60000));
        RelyingParty party = RelyingParty.create(config);
        try {
            SignalsReceiver.Options options = new SignalsReceiver.Options();
            options.pep = party.pep();
            options.tls = new com.iyasec.wsfed.HttpClient.Tls();
            options.tls.key = StubIdp.IDP_KEY;
            options.tls.cert = StubIdp.IDP_CERT;
            WsFedError error = assertThrows(WsFedError.class, () -> new SignalsReceiver("http://127.0.0.1:9", (ids, event) -> { }, options));
            assertTrue(error.getMessage().contains("the receiver's TLS client key is pep.assertionKey"));
            assertFalse(party.pep().config().mode == Mode.LOCAL);
        } finally {
            party.pep().stop();
        }
    }

    private static WsFedLogin login() {
        WsFedLogin login = new WsFedLogin();
        login.nameId = "alice";
        login.attributes = new LinkedHashMap<>();
        login.attributeFriendlyNames = new LinkedHashMap<>();
        return login;
    }

    private static Map<String, Object> base() {
        Map<String, Object> config = new LinkedHashMap<>();
        config.put("realm", StubIdp.REALM);
        config.put("replyUrl", StubIdp.REPLY);
        config.put("privateKey", StubIdp.RP_KEY);
        config.put("certificate", StubIdp.RP_CERT);
        config.put("idpMetadata", StubIdp.idpMetadata());
        return config;
    }
}
