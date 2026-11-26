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
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The embedded PEP's subject, and the decisions the relying party gives. */
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

    @Test
    void localModeFailsClosedThenDecidesInProcess(@TempDir Path dir) throws Exception {
        OrdersPdp pdp = null;
        RelyingParty party = null;
        try {
            pdp = OrdersPdp.open();
            Map<String, Object> section = new LinkedHashMap<>();
            section.put("name", "pep-demo");
            section.put("mode", "local");
            section.put("signals", false);
            section.put("pollIntervalMs", 1000);
            section.put("heartbeatIntervalMs", 60000);
            section.put("assertionKey", ecPkcs8(dir.resolve("pep.pem")));
            section.put("pdpUrl", pdp.url);
            Map<String, Object> config = base();
            config.put("signals", false);
            config.put("pep", section);
            party = RelyingParty.create(config);
            assertEquals(Decision.Kind.UNAVAILABLE, party.decide(login(), Access.of("read", "order", "42")).kind());
            pdp.policiesUp.set(true);
            long deadline = System.nanoTime() + 8_000_000_000L;
            while (System.nanoTime() < deadline && !party.pep().status().holdsPolicy) {
                Thread.sleep(100);
            }
            assertTrue(party.pep().status().holdsPolicy, party.pep().status().lastError);
            assertTrue(party.decide(login(), Access.of("read", "order", "42")).isPermit());
            assertEquals(Decision.Kind.DENY, party.decide(login(), Access.of("write", "order", "42")).kind());
            assertEquals(0, pdp.evaluations.get());
            assertTrue(pdp.policies.get() > 0);
        } finally {
            if (party != null && party.pep() != null) party.pep().stop();
            if (pdp != null) pdp.close();
        }
    }

    /** An EC P-256 key in PKCS#8 PEM, at an absolute path, distinct from the relying party's key. */
    private static String ecPkcs8(Path path) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        var pair = generator.generateKeyPair();
        String encoded = Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(pair.getPrivate().getEncoded());
        Files.writeString(path, "-----BEGIN PRIVATE KEY-----\n" + encoded + "\n-----END PRIVATE KEY-----\n");
        return path.toAbsolutePath().toString();
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

    /**
     * A loopback PDP. The policy pull is 503 until {@link #policiesUp}, then
     * one root policy that permits {@code read} and nothing else.
     */
    private static final class OrdersPdp implements AutoCloseable {
        private static final String READ_ONLY = "<Policy xmlns=\"urn:oasis:names:tc:xacml:3.0:core:schema:wd-17\" PolicyId=\"orders\" Version=\"1.0\" RuleCombiningAlgId=\"urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-unless-permit\"><Target/><Rule RuleId=\"read\" Effect=\"Permit\"><Target><AnyOf><AllOf><Match MatchId=\"urn:oasis:names:tc:xacml:1.0:function:string-equal\"><AttributeValue DataType=\"http://www.w3.org/2001/XMLSchema#string\">read</AttributeValue><AttributeDesignator Category=\"urn:oasis:names:tc:xacml:3.0:attribute-category:action\" AttributeId=\"urn:oasis:names:tc:xacml:1.0:action:action-id\" DataType=\"http://www.w3.org/2001/XMLSchema#string\" MustBePresent=\"false\"/></Match></AllOf></AnyOf></Target></Rule></Policy>";

        final String url;
        final AtomicBoolean policiesUp = new AtomicBoolean();
        final AtomicInteger policies = new AtomicInteger();
        final AtomicInteger evaluations = new AtomicInteger();
        private final HttpServer server;
        private final ExecutorService executor;

        private OrdersPdp(HttpServer server, ExecutorService executor) {
            this.server = server;
            this.executor = executor;
            this.url = "http://127.0.0.1:" + server.getAddress().getPort();
        }

        static OrdersPdp open() throws IOException {
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            ExecutorService executor = Executors.newCachedThreadPool(runnable -> {
                Thread thread = new Thread(runnable, "orders-pdp");
                thread.setDaemon(true);
                return thread;
            });
            server.setExecutor(executor);
            OrdersPdp pdp = new OrdersPdp(server, executor);
            server.createContext("/", pdp::handle);
            server.start();
            return pdp;
        }

        @Override
        public void close() {
            server.stop(0);
            executor.shutdownNow();
        }

        private void handle(HttpExchange exchange) {
            try {
                exchange.getRequestBody().readAllBytes();
                String method = exchange.getRequestMethod();
                String path = exchange.getRequestURI().getPath();
                if (path == null) path = "";
                Reply reply = answer(method, path, exchange.getRequestHeaders().getFirst("Authorization"));
                byte[] out = reply.body.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("content-type", "application/json");
                exchange.sendResponseHeaders(reply.status, out.length);
                exchange.getResponseBody().write(out);
            } catch (IOException err) {
                try {
                    exchange.sendResponseHeaders(500, -1);
                } catch (IOException ignored) {
                    // The exchange is already gone.
                }
            } finally {
                exchange.close();
            }
        }

        private Reply answer(String method, String path, String authorization) {
            if (!"/oauth2/token".equals(path) && (authorization == null || !authorization.startsWith("DPoP "))) {
                return new Reply(401, Json.stringify(Map.of("error", "invalid_token")));
            }
            if ("POST".equals(method) && "/oauth2/token".equals(path)) {
                return new Reply(200, Json.stringify(Map.of("access_token", "pep-token", "token_type", "DPoP", "expires_in", 300)));
            }
            if ("POST".equals(method) && "/xacml/pep/register".equals(path)) {
                return new Reply(201, Json.stringify(Map.of("registered", true)));
            }
            if ("POST".equals(method) && "/xacml/pep/heartbeat".equals(path)) {
                return new Reply(200, Json.stringify(Map.of("acknowledged", true, "current", true)));
            }
            if ("GET".equals(method) && "/xacml/pep/authzen-catalogue".equals(path)) {
                return new Reply(200, Json.stringify(Map.of(
                        "syncToken", "c1",
                        "rows", List.of(Map.of("object", "subject", "property", "acr", "attributeId", "urn:example:acr")),
                        "settings", Map.of("obligationsProfile", false))));
            }
            if ("GET".equals(method) && "/xacml/pep/policies".equals(path)) {
                policies.incrementAndGet();
                if (!policiesUp.get()) {
                    Map<String, Object> down = new LinkedHashMap<>();
                    down.put("error", "server_error");
                    down.put("error_description", "not now");
                    return new Reply(503, Json.stringify(down));
                }
                Map<String, Object> policy = new LinkedHashMap<>();
                policy.put("name", "orders");
                policy.put("policyId", "orders");
                policy.put("kind", "Policy");
                policy.put("version", "1.0");
                policy.put("isRoot", Boolean.TRUE);
                policy.put("description", "");
                policy.put("combiningAlgId", "urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-unless-permit");
                policy.put("document", READ_ONLY);
                Map<String, Object> body = new LinkedHashMap<>();
                body.put("syncToken", "p1");
                body.put("root", "orders");
                body.put("policies", List.of(policy));
                body.put("withheld", List.of());
                body.put("note", "");
                return new Reply(200, Json.stringify(body));
            }
            if ("POST".equals(method) && "/admin-api/pep-audit".equals(path)) {
                return new Reply(200, Json.stringify(Map.of("acknowledged", 0)));
            }
            if ("POST".equals(method) && "/access/v1/evaluation".equals(path)) {
                evaluations.incrementAndGet();
                return new Reply(200, Json.stringify(Map.of("decision", true)));
            }
            return new Reply(404, Json.stringify(Map.of("error", "not_found")));
        }
    }

    private static final class Reply {
        final int status;
        final String body;

        Reply(int status, String body) {
            this.status = status;
            this.body = body;
        }
    }
}
