// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.wsfed;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.iyasec.wsfed.ssf.Events;
import com.iyasec.wsfed.ssf.Jws;
import com.iyasec.wsfed.ssf.SessionIndex;
import com.iyasec.wsfed.ssf.SignalsReceiver;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class SsfTest {
    private static final KeyPair PRIVATE = rsa();
    private static final KeyPair OTHER = rsa();
    private static final Map<String, Object> JWK = jwk((RSAPublicKey) PRIVATE.getPublic(), "k1");

    @Test
    void verifiesASetAndRefusesTheWrongKey() {
        String token = jws(Map.of("a", 1), PRIVATE, null);
        assertEquals(1L, ((Number) Jws.verify(token, List.of(JWK)).payload.get("a")).longValue());
        WsFedError wrong = assertThrows(WsFedError.class, () -> Jws.verify(jws(Map.of("a", 1), OTHER, null), List.of(JWK)));
        assertTrue(wrong.getMessage().contains("does not verify"));
        Map<String, Object> nope = new LinkedHashMap<>();
        nope.put("alg", "RS256");
        nope.put("kid", "nope");
        WsFedError missing = assertThrows(WsFedError.class, () -> Jws.verify(jws(Map.of("a", 1), PRIVATE, nope), List.of(JWK)));
        assertTrue(missing.getMessage().contains("no RSA signing key with kid nope"));
        WsFedError none = assertThrows(WsFedError.class, () -> Jws.verify(jws(Map.of("a", 1), PRIVATE, Map.of("alg", "none")), List.of(JWK)));
        assertTrue(none.getMessage().contains("does not verify"));
        WsFedError hmac = assertThrows(WsFedError.class, () -> Jws.verify(jws(Map.of("a", 1), PRIVATE, Map.of("alg", "HS256", "kid", "k1")), List.of(JWK)));
        assertTrue(hmac.getMessage().contains("does not verify"));
    }

    @Test
    void subjects() {
        Map<String, Object> complex = new LinkedHashMap<>();
        complex.put("format", "complex");
        complex.put("user", Map.of("format", "iss_sub", "iss", "https://i", "sub", "urn:uuid:a"));
        complex.put("session", Map.of("format", "opaque", "id", "S1"));
        assertEquals(Map.of("person", "urn:uuid:a", "idp_session", "S1"), Events.subjectOf(complex, "https://i"));
        assertEquals(Map.of(), Events.subjectOf(Map.of("format", "iss_sub", "iss", "https://other", "sub", "urn:uuid:a"), "https://i"));
        assertEquals(Map.of("email", "A@x.com"), Events.subjectOf(Map.of("format", "email", "email", "A@x.com"), "https://i"));
    }

    @Test
    void pollStreamEndsTheNamedSessions() throws Exception {
        try (Stub stub = Stub.start()) {
            List<List<String>> ended = new ArrayList<>();
            List<SignalsReceiver.SignalEvent> seen = new ArrayList<>();
            SignalsReceiver.Options options = new SignalsReceiver.Options();
            options.pollIntervalMs = 60_000;
            options.log = new Quiet();
            SignalsReceiver receiver = new SignalsReceiver(stub.url, (ids, event) -> ended.add(List.copyOf(ids)), options);
            receiver.on("*", seen::add);
            receiver.start();
            receiver.stop();
            assertEquals(1, stub.created.get());
            assertEquals("s1", receiver.stream().get("stream_id"));
            receiver.track("L-a1", login("alice", "IDP-A1"));
            receiver.track("L-a2", login("alice", "IDP-A2"));
            receiver.track("L-b1", login("bob", "IDP-B1"));
            String j1 = stub.set(Events.EVENT.get("session_revoked"), complex(stub.url, "urn:uuid:alice", "IDP-A1"), null, null, null);
            Map<String, Object> change = new LinkedHashMap<>();
            change.put("credential_type", "password");
            change.put("change_type", "update");
            String j2 = stub.set(Events.EVENT.get("credential_change"), complex(stub.url, "urn:uuid:bob", null), change, null, null);
            receiver.pollOnce();
            assertEquals(List.of(List.of("L-a1")), ended);
            SignalsReceiver.SignalEvent found = seen.stream().filter(event -> j2.equals(event.jti)).findFirst().orElseThrow();
            assertFalse(found.ended);
            assertEquals(List.of("L-b1"), found.sessions);
            String j3 = stub.set(Events.EVENT.get("account_disabled"), Map.of("format", "iss_sub", "iss", stub.url, "sub", "urn:uuid:alice"), null, null, null);
            receiver.pollOnce();
            assertEquals(List.of(List.of("L-a1"), List.of("L-a2")), ended);
            assertTrue(stub.acked.contains(j1) && stub.acked.contains(j2));
            stub.set(Events.EVENT.get("credential_compromise"), Map.of("format", "email", "email", "BOB@example.com"), Map.of("credential_type", "password"), null, null);
            receiver.pollOnce();
            assertEquals(List.of("L-b1"), ended.get(2));
            receiver.pollOnce();
            assertTrue(stub.acked.contains(j3));
            SignalsReceiver again = new SignalsReceiver(stub.url, (ids, event) -> { }, options);
            again.start();
            again.stop();
            assertEquals(1, stub.created.get());
            assertEquals("s1", again.stream().get("stream_id"));
        }
    }

    @Test
    void forgedSetsAreReported() throws Exception {
        try (Stub stub = Stub.start()) {
            List<List<String>> ended = new ArrayList<>();
            SessionIndex index = new SessionIndex();
            SignalsReceiver.Options options = new SignalsReceiver.Options();
            options.sessionIndex = index;
            options.log = new Quiet();
            SignalsReceiver receiver = new SignalsReceiver(stub.url, (ids, event) -> ended.add(ids), options);
            receiver.start();
            receiver.stop();
            receiver.track("L-c1", login("carol", "IDP-C1"));
            Map<String, Object> subject = complex(stub.url, "urn:uuid:carol", "IDP-C1");
            String forged = stub.set(Events.EVENT.get("session_revoked"), subject, null, OTHER, null);
            String misaddressed = stub.set(Events.EVENT.get("session_revoked"), subject, null, null, "someone-else");
            String foreign = stub.set(Events.EVENT.get("session_revoked"), subject, null, null, null, "https://evil.example");
            receiver.pollOnce();
            assertEquals(List.of(), ended);
            assertEquals(List.of("L-c1"), index.byPerson("urn:uuid:carol"));
            receiver.pollOnce();
            assertTrue(stub.errs.containsKey(forged) && stub.errs.containsKey(misaddressed) && stub.errs.containsKey(foreign));
        }
    }

    @Test
    void eventCatalog() {
        assertEquals(8, Events.CAEP_EVENTS.size());
        assertEquals(14, Events.RISC_EVENTS.size());
        assertTrue(Events.CAEP_EVENTS.contains(Events.EVENT.get("risk_level_change")));
        assertTrue(Events.RISC_EVENTS.contains(Events.EVENT.get("opt_out_effective")));
    }

    @Test
    void handlerAndOnEndErrorsAreStillAcknowledged() throws Exception {
        try (Stub stub = Stub.start()) {
            Quiet log = new Quiet();
            List<String> seen = new ArrayList<>();
            SignalsReceiver.Options options = new SignalsReceiver.Options();
            options.log = log;
            SignalsReceiver receiver = new SignalsReceiver(stub.url, (ids, event) -> { throw new RuntimeException("store down"); }, options);
            receiver.on(Events.EVENT.get("credential_change"), event -> { throw new RuntimeException("handler bug"); });
            receiver.on("*", event -> seen.add(event.jti));
            receiver.start();
            receiver.stop();
            receiver.track("L-d1", login("dave", "IDP-D1"));
            Map<String, Object> extra = Map.of("credential_type", "password", "change_type", "update");
            String j1 = stub.set(Events.EVENT.get("credential_change"), complex(stub.url, "urn:uuid:dave", null), extra, null, null);
            String j2 = stub.set(Events.EVENT.get("session_revoked"), complex(stub.url, "urn:uuid:dave", "IDP-D1"), null, null, null);
            receiver.pollOnce();
            receiver.pollOnce();
            receiver.pollOnce();
            assertTrue(stub.acked.contains(j1) && stub.acked.contains(j2));
            assertFalse(stub.errs.containsKey(j1) || stub.errs.containsKey(j2));
            assertEquals(seen.stream().sorted().toList(), List.of(j1, j2).stream().sorted().toList());
            assertTrue(log.errors.stream().anyMatch(message -> message.contains("handler for") && message.contains("credential-change") && message.contains("threw")));
            assertTrue(log.errors.stream().anyMatch(message -> message.contains("onEndSessions threw")));
        }
    }

    @Test
    void overlappingPollsHandleASetOnce() throws Exception {
        try (Stub stub = Stub.start()) {
            List<String> seen = new ArrayList<>();
            SignalsReceiver.Options options = new SignalsReceiver.Options();
            options.log = new Quiet();
            SignalsReceiver receiver = new SignalsReceiver(stub.url, (ids, event) -> { }, options);
            receiver.on("*", event -> seen.add(event.jti));
            receiver.start();
            receiver.stop();
            String jti = stub.set(Events.EVENT.get("account_enabled"), Map.of("format", "iss_sub", "iss", stub.url, "sub", "urn:uuid:erin"), null, null, null);
            List<Thread> threads = new ArrayList<>();
            for (int i = 0; i < 3; i++) threads.add(new Thread(receiver::pollOnce));
            for (Thread thread : threads) thread.start();
            for (Thread thread : threads) thread.join();
            receiver.pollOnce();
            assertEquals(List.of(jti), seen.stream().filter(jti::equals).toList());
        }
    }

    @Test
    void refusesATransmitterWithoutPollDelivery() throws Exception {
        try (Stub stub = Stub.startWithoutPoll()) {
            SignalsReceiver receiver = new SignalsReceiver(stub.url, (ids, event) -> { }, quiet());
            WsFedError err = assertThrows(WsFedError.class, receiver::start);
            assertEquals("ssf", err.code);
            assertTrue(err.getMessage().contains("poll delivery"));
        }
    }

    private static SignalsReceiver.Options quiet() {
        SignalsReceiver.Options options = new SignalsReceiver.Options();
        options.log = new Quiet();
        return options;
    }

    private static Map<String, Object> complex(String iss, String sub, String session) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("format", "complex");
        out.put("user", Map.of("format", "iss_sub", "iss", iss, "sub", sub));
        if (session != null) out.put("session", Map.of("format", "opaque", "id", session));
        return out;
    }

    private static WsFedLogin login(String person, String sessionIndex) {
        WsFedLogin who = new WsFedLogin();
        who.nameId = person;
        who.issuer = "x";
        who.realm = "https://rp.test/";
        who.trustVersion = "2005/02";
        who.assertionId = UUID.randomUUID().toString();
        who.attributes.put("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier", List.of("urn:uuid:" + person));
        who.attributes.put("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", List.of(person + "@example.com"));
        who.sessionIndex = sessionIndex;
        return who;
    }

    private static final class Quiet implements SignalsReceiver.Log {
        private final List<String> errors = new ArrayList<>();
        @Override public void info(String message) {}
        @Override public void warn(String message) {}
        @Override public void error(String message) { errors.add(message); }
    }

    private static final class Stub implements AutoCloseable {
        private final HttpServer server;
        final String url;
        final Map<String, String> queue = new LinkedHashMap<>();
        final List<String> acked = new ArrayList<>();
        final Map<String, Object> errs = new LinkedHashMap<>();
        final AtomicInteger created = new AtomicInteger();
        final List<Map<String, Object>> streams = new ArrayList<>();
        final boolean poll;
        private final Object lock = new Object();

        private Stub(HttpServer server, boolean poll) {
            this.server = server;
            this.poll = poll;
            this.url = "http://127.0.0.1:" + server.getAddress().getPort();
        }

        static Stub start() throws Exception {
            return open(true);
        }

        static Stub startWithoutPoll() throws Exception {
            return open(false);
        }

        private static Stub open(boolean poll) throws Exception {
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.setExecutor(Executors.newCachedThreadPool());
            Stub[] box = new Stub[1];
            box[0] = new Stub(server, poll);
            server.createContext("/", exchange -> {
                byte[] raw = exchange.getRequestBody().readAllBytes();
                String text = new String(raw, StandardCharsets.UTF_8);
                String path = exchange.getRequestURI().getPath();
                String method = exchange.getRequestMethod();
                Object body;
                int status = 200;
                synchronized (box[0].lock) {
                    if ("/.well-known/ssf-configuration".equals(path)) {
                        Map<String, Object> config = new LinkedHashMap<>();
                        config.put("issuer", box[0].url);
                        config.put("jwks_uri", box[0].url + "/jwks");
                        config.put("configuration_endpoint", box[0].url + "/ssf/stream");
                        config.put("verification_endpoint", box[0].url + "/ssf/verify");
                        config.put("delivery_methods_supported", poll ? List.of("urn:ietf:rfc:8936") : List.of("urn:ietf:rfc:8935"));
                        body = config;
                    } else if ("/jwks".equals(path)) {
                        body = Map.of("keys", List.of(JWK));
                    } else if ("/ssf/stream".equals(path) && "GET".equals(method)) {
                        body = box[0].streams;
                    } else if ("/ssf/stream".equals(path) && "POST".equals(method)) {
                        Map<String, Object> posted = Json.object(Json.parse(text));
                        int n = box[0].created.incrementAndGet();
                        Map<String, Object> stream = new LinkedHashMap<>();
                        stream.put("stream_id", "s" + n);
                        stream.put("iss", box[0].url);
                        stream.put("aud", "my-app");
                        Map<String, Object> delivery = Json.object(posted.get("delivery"));
                        stream.put("delivery", Map.of("method", delivery.get("method"), "endpoint_url", box[0].url + "/ssf/poll/s" + n));
                        stream.put("events_requested", posted.get("events_requested"));
                        stream.put("events_delivered", posted.get("events_requested"));
                        box[0].streams.add(stream);
                        status = 201;
                        body = stream;
                    } else if (path.startsWith("/ssf/poll/")) {
                        Map<String, Object> posted = text.isBlank() ? Map.of() : Json.object(Json.parse(text));
                        Object ack = posted.get("ack");
                        if (ack instanceof List<?> list) {
                            for (Object jti : list) {
                                box[0].acked.add(String.valueOf(jti));
                                box[0].queue.remove(String.valueOf(jti));
                            }
                        }
                        Object setErrs = posted.get("setErrs");
                        if (setErrs instanceof Map<?, ?> map) {
                            for (Map.Entry<?, ?> entry : map.entrySet()) {
                                box[0].errs.put(String.valueOf(entry.getKey()), entry.getValue());
                                box[0].queue.remove(String.valueOf(entry.getKey()));
                            }
                        }
                        body = Map.of("sets", new LinkedHashMap<>(box[0].queue), "moreAvailable", Boolean.FALSE);
                    } else {
                        status = 404;
                        body = Map.of("err", "not found");
                    }
                }
                byte[] out = Json.stringify(body).getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("content-type", "application/json");
                exchange.sendResponseHeaders(status, out.length);
                exchange.getResponseBody().write(out);
                exchange.close();
            });
            server.start();
            return box[0];
        }

        String set(String eventType, Map<String, Object> subId, Map<String, Object> extra, KeyPair key, String aud) {
            return set(eventType, subId, extra, key, aud, null);
        }

        String set(String eventType, Map<String, Object> subId, Map<String, Object> extra, KeyPair key, String aud, String iss) {
            String jti = UUID.randomUUID().toString();
            Map<String, Object> event = new LinkedHashMap<>();
            event.put("event_timestamp", 1);
            if (extra != null) event.putAll(extra);
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("iss", iss == null ? url : iss);
            payload.put("aud", aud == null ? "my-app" : aud);
            payload.put("jti", jti);
            payload.put("iat", 1);
            payload.put("sub_id", subId);
            payload.put("events", Map.of(eventType, event));
            synchronized (lock) {
                queue.put(jti, jws(payload, key == null ? PRIVATE : key, null));
            }
            return jti;
        }

        @Override public void close() {
            server.stop(0);
        }
    }

    private static String jws(Map<String, Object> payload, KeyPair key, Map<String, Object> header) {
        Map<String, Object> head = header == null ? new LinkedHashMap<>(Map.of("alg", "RS256", "kid", "k1", "typ", "secevent+jwt")) : new LinkedHashMap<>(header);
        String h = b64(Json.stringify(head).getBytes(StandardCharsets.UTF_8));
        String p = b64(Json.stringify(payload).getBytes(StandardCharsets.UTF_8));
        if ("none".equals(head.get("alg")) || "HS256".equals(head.get("alg"))) return h + "." + p + "." + b64(new byte[] {1});
        try {
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(key.getPrivate());
            signer.update((h + "." + p).getBytes(StandardCharsets.US_ASCII));
            return h + "." + p + "." + b64(signer.sign());
        } catch (Exception err) {
            throw new IllegalStateException(err);
        }
    }

    private static Map<String, Object> jwk(RSAPublicKey key, String kid) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("kty", "RSA");
        out.put("kid", kid);
        out.put("alg", "RS256");
        out.put("use", "sig");
        out.put("n", b64(unsigned(key.getModulus())));
        out.put("e", b64(unsigned(key.getPublicExponent())));
        return out;
    }

    private static byte[] unsigned(java.math.BigInteger value) {
        byte[] raw = value.toByteArray();
        if (raw.length > 1 && raw[0] == 0) {
            byte[] trimmed = new byte[raw.length - 1];
            System.arraycopy(raw, 1, trimmed, 0, trimmed.length);
            return trimmed;
        }
        return raw;
    }

    private static String b64(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    private static KeyPair rsa() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception err) {
            throw new IllegalStateException(err);
        }
    }
}
