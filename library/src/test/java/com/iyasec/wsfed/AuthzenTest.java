// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.wsfed;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.iyasec.pep.Access;
import com.iyasec.pep.Decision;
import com.iyasec.pep.Json;
import com.iyasec.pep.Obligation;
import com.iyasec.pep.Pep;
import com.iyasec.pep.Status;
import com.iyasec.wsfed.pep.EmbeddedPep;
import com.iyasec.wsfed.ssf.SignalsReceiver;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The AuthZEN table, decided in process through {@link RelyingParty#decide}
 * and {@link RelyingParty#decideSession}. The catalogue, cases and compiled
 * policy documents are test resources.
 */
class AuthzenTest {
    private static final String ACCESS_SUBJECT = "urn:oasis:names:tc:xacml:1.0:subject-category:access-subject";
    private static final String XS_STRING = "http://www.w3.org/2001/XMLSchema#string";
    /** The entry DN the registration answer names, written as the caller fact. */
    private static final String STUB_PEP_DN = "uid=pep-wsfed-authzen,ou=users,dc=example,dc=com";

    @Test
    void theTableCoversWhatItMustAndMatchesItsCompiledPolicies() {
        JsonNode table = resource("test_authzen.json");
        JsonNode documents = resource("test_authzen_policies.json");
        assertTrue(table.path("cases").isArray());
        assertTrue(table.path("phases").isArray());
        Set<String> ids = new HashSet<>();
        for (JsonNode kase : table.path("cases")) {
            String id = kase.path("id").asText();
            assertTrue(ids.add(id), "case " + id + " twice");
            assertTrue(Set.of("Permit", "Deny", "Unavailable").contains(kase.path("expect").asText()), id);
            assertTrue(listed(table.path("phases"), kase.path("phase").asText()), id);
            loginFor(table, kase.path("login"), StubIdp.REALM);
            accessFor(kase.path("access"));
        }
        for (JsonNode policy : table.path("policies")) {
            String name = policy.path("name").asText();
            JsonNode held = documents.path("policies").path(name);
            assertTrue(held.path("policyId").isTextual(), name + " is not compiled");
            String alfa = String.join("\n", strings(policy.get("alfa")));
            String policyId = held.get("policyId").asText();
            assertTrue(alfa.contains("id = \"" + policyId + "\""), name + "'s compiled PolicyId " + policyId + " is not in its ALFA");
        }
        List<String[]> kinds = new ArrayList<>();
        for (JsonNode row : table.path("catalogue")) {
            JsonNode dataType = row.get("dataType");
            String type = dataType != null && dataType.isTextual() ? dataType.asText() : "string";
            kinds.add(new String[] {row.path("object").asText(), type});
        }
        for (String wanted : List.of("integer", "double", "boolean", "dateTime")) {
            boolean found = false;
            for (String[] kind : kinds) if (wanted.equals(kind[1])) found = true;
            assertTrue(found, "a " + wanted + " row");
        }
        for (String object : List.of("subject", "resource", "action", "context")) {
            boolean found = false;
            for (String[] kind : kinds) if (object.equals(kind[0])) found = true;
            assertTrue(found, "a " + object + " row");
        }
    }

    @Test
    void everyCaseAnswersAsTheTableSaysInLocalMode(@TempDir Path dir) throws Exception {
        JsonNode table = resource("test_authzen.json");
        JsonNode documents = resource("test_authzen_policies.json");
        Pdp pdp = Pdp.open(table);
        SignalsReceiver receiver = new SignalsReceiver("http://127.0.0.1:1", (sessions, event) -> { });
        try {
            List<String> failures = new ArrayList<>();
            int ran = 0;
            for (JsonNode phaseNode : table.path("phases")) {
                String phase = phaseNode.asText();
                pdp.serve(phase, pulledPolicies(table, documents, phase, StubIdp.REALM));
                RelyingParty party = null;
                try {
                    party = RelyingParty.create(config(pdp.url, ecPkcs8(dir.resolve("pep-" + phase + ".pem"))));
                    waitFor(party, "registered and held the policy", status -> status.registered && status.holdsPolicy);
                    for (JsonNode kase : cases(table, phase)) {
                        ran++;
                        Decision decision = runCase(table, party, receiver, kase, StubIdp.REALM);
                        ObjectNode answer = answerOf(decision);
                        if (!asExpected(answer, kase)) {
                            failures.add(kase.path("id").asText() + " (" + phase + "): got " + answer
                                    + " (" + whyOf(decision) + "), want " + kase.get("expect"));
                        }
                    }
                } finally {
                    if (party != null && party.pep() != null) party.pep().stop();
                }
            }
            assertEquals(table.path("cases").size(), ran, "every case is in a phase");
            assertTrue(failures.isEmpty(), failures.size() + " of " + ran + " cases:\n" + String.join("\n", failures));
            assertEquals(0, pdp.evaluations.get(), "a local decision never asks the AuthZEN endpoint");
        } finally {
            pdp.close();
        }
    }

    private static JsonNode pick(JsonNode spec, JsonNode base, String key) {
        if (spec != null && spec.has(key)) return spec.get(key);
        if (base != null && base.has(key)) return base.get(key);
        return Json.MAPPER.nullNode();
    }

    /** The base object with {@code over} laid on it. A null removes a member. */
    private static ObjectNode overlay(JsonNode base, JsonNode over) {
        ObjectNode out = Json.object();
        if (base != null && base.isObject()) {
            base.fields().forEachRemaining(entry -> out.set(entry.getKey(), entry.getValue().deepCopy()));
        }
        if (over != null && over.isObject()) {
            over.fields().forEachRemaining(entry -> {
                if (entry.getValue().isNull()) out.remove(entry.getKey());
                else out.set(entry.getKey(), entry.getValue().deepCopy());
            });
        }
        return out;
    }

    private static List<String> strings(JsonNode value) {
        List<String> out = new ArrayList<>();
        if (value != null && value.isArray()) {
            for (JsonNode item : value) if (item.isTextual()) out.add(item.asText());
        }
        return out;
    }

    private static String uri(JsonNode table, String shortName) {
        JsonNode value = table.path("claims").get(shortName);
        if (value == null || !value.isTextual()) throw new IllegalStateException("no claim called " + shortName);
        return value.asText();
    }

    private static String text(JsonNode node, String key) {
        JsonNode value = node == null ? null : node.get(key);
        if (value == null || !value.isTextual()) throw new IllegalStateException(key);
        return value.asText();
    }

    private static WsFedLogin loginFor(JsonNode table, JsonNode spec, String application) {
        JsonNode base = table.path("logins").path(text(spec, "base"));
        if (!base.isObject()) throw new IllegalStateException("a login names its base");
        WsFedLogin login = new WsFedLogin();
        login.attributes = new LinkedHashMap<>();
        login.attributeFriendlyNames = new LinkedHashMap<>();
        ObjectNode claims = overlay(base.get("claims"), spec.get("claims"));
        claims.fields().forEachRemaining(entry -> login.attributes.put(uri(table, entry.getKey()), strings(entry.getValue())));
        List<String> amr = strings(pick(spec, base, "amr"));
        if (!amr.isEmpty()) login.attributes.put(EmbeddedPep.AUTHENTICATION_METHOD_CLAIM, amr);
        ObjectNode friendly = overlay(base.get("friendly"), spec.get("friendly"));
        friendly.fields().forEachRemaining(entry -> {
            if (!entry.getValue().isTextual()) throw new IllegalStateException("friendly " + entry.getKey());
            login.attributeFriendlyNames.put(uri(table, entry.getKey()), entry.getValue().asText());
        });
        JsonNode authTime = pick(spec, base, "auth_time");
        if (!authTime.isIntegralNumber()) throw new IllegalStateException("auth_time");
        login.authnInstant = Instant.ofEpochSecond(authTime.asLong());
        JsonNode nameId = pick(spec, base, "name_id");
        if (!nameId.isTextual()) throw new IllegalStateException("name_id");
        login.nameId = nameId.asText();
        login.nameIdFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
        login.issuer = "https://iya-sts.test";
        login.realm = application;
        login.trustVersion = "2005/02";
        login.assertionId = "_authzen";
        login.notOnOrAfter = Instant.now().plusSeconds(3600);
        login.sessionIndex = "authzen-session";
        if (spec.path("session_over").asBoolean(false)) login.sessionNotOnOrAfter = Instant.now().minusSeconds(1);
        JsonNode acr = pick(spec, base, "acr");
        if (acr.isTextual()) login.authnContextClassRef = acr.asText();
        return login;
    }

    private static Map<String, JsonNode> mapOf(JsonNode spec, String key) {
        Map<String, JsonNode> out = new LinkedHashMap<>();
        JsonNode node = spec == null ? null : spec.get(key);
        if (node != null && node.isObject()) {
            node.fields().forEachRemaining(entry -> out.put(entry.getKey(), entry.getValue().deepCopy()));
        }
        return out;
    }

    private static Access accessFor(JsonNode spec) {
        Access access = Access.of(text(spec, "action"), text(spec, "type"), text(spec, "id"));
        access.resourceProperties = mapOf(spec, "resource");
        access.actionProperties = mapOf(spec, "action_properties");
        access.context = mapOf(spec, "context");
        return access;
    }

    private static Decision runCase(JsonNode table, RelyingParty party, SignalsReceiver receiver, JsonNode kase, String application) {
        WsFedLogin login = loginFor(table, kase.path("login"), application);
        Access access = accessFor(kase.path("access"));
        JsonNode session = kase.get("session");
        if (session == null || !session.isTextual()) return party.decide(login, access);
        String localId = "authzen-" + kase.path("id").asText();
        receiver.track(localId, login);
        if ("ended".equals(session.asText())) receiver.untrack(localId);
        return party.decideSession(receiver, localId, login, access);
    }

    /** The decision the host sees. A Permit keeps each obligation's type and properties. */
    private static ObjectNode answerOf(Decision decision) {
        if (decision.kind() == Decision.Kind.PERMIT) {
            List<ObjectNode> handed = new ArrayList<>();
            for (Obligation obligation : decision.obligations()) {
                ObjectNode one = Json.object();
                one.put("type", obligation.kind);
                one.set("properties", obligation.properties.deepCopy());
                handed.add(one);
            }
            handed.sort((left, right) -> left.toString().compareTo(right.toString()));
            ArrayNode obligations = Json.array();
            for (ObjectNode one : handed) obligations.add(one);
            ObjectNode answer = Json.object();
            answer.put("decision", "Permit");
            answer.set("obligations", obligations);
            return answer;
        }
        ObjectNode answer = Json.object();
        answer.put("decision", decision.kind() == Decision.Kind.DENY ? "Deny" : "Unavailable");
        return answer;
    }

    private static String whyOf(Decision decision) {
        return decision.kind() == Decision.Kind.PERMIT ? "" : decision.why();
    }

    /** The decision, and for a Permit the obligation types (none when the case lists none). */
    private static boolean asExpected(ObjectNode answer, JsonNode kase) {
        if (!answer.path("decision").asText().equals(kase.path("expect").asText())) return false;
        if (!"Permit".equals(answer.path("decision").asText())) return true;
        List<String> handed = new ArrayList<>();
        JsonNode obligations = answer.get("obligations");
        if (obligations != null && obligations.isArray()) {
            for (JsonNode obligation : obligations) {
                if (obligation.path("type").isTextual()) handed.add(obligation.get("type").asText());
            }
        }
        List<String> wanted = strings(kase.has("obligations") ? kase.get("obligations") : Json.array());
        Collections.sort(handed);
        Collections.sort(wanted);
        return handed.equals(wanted);
    }

    private static List<JsonNode> cases(JsonNode table, String phase) {
        List<JsonNode> out = new ArrayList<>();
        for (JsonNode kase : table.path("cases")) {
            if (phase.equals(kase.path("phase").asText())) out.add(kase);
        }
        return out;
    }

    /** The phase's policies: the root first, then the policies it references. */
    private static List<ObjectNode> pulledPolicies(JsonNode table, JsonNode documents, String phase, String application) {
        List<ObjectNode> rows = new ArrayList<>();
        for (JsonNode policy : table.path("policies")) {
            if (!phase.equals(policy.path("phase").asText())) continue;
            String name = policy.path("name").asText();
            JsonNode held = documents.path("policies").path(name);
            if (!held.isObject() || !held.path("policyId").isTextual() || !held.path("document").isTextual()) {
                throw new IllegalStateException("test_authzen_policies.json has no " + name);
            }
            ObjectNode row = Json.object();
            row.put("name", name);
            row.put("policyId", held.get("policyId").asText());
            row.put("kind", held.path("kind").asText());
            row.put("version", held.path("version").asText());
            row.put("isRoot", !"referenced".equals(policy.path("role").asText()));
            row.put("description", "");
            row.put("document", held.get("document").asText().replace("{{application}}", application));
            rows.add(row);
        }
        rows.sort((left, right) -> Boolean.compare(right.path("isRoot").asBoolean(), left.path("isRoot").asBoolean()));
        return rows;
    }

    private static Map<String, Object> config(String pdpUrl, String key) {
        Map<String, Object> pep = new LinkedHashMap<>();
        pep.put("name", "pep-wsfed-authzen");
        pep.put("mode", "local");
        pep.put("assertionKey", key);
        pep.put("pdpUrl", pdpUrl);
        pep.put("pollIntervalMs", 1000);
        pep.put("heartbeatIntervalMs", 60000);
        pep.put("supportedObligations", List.of("step-up"));
        Map<String, Object> config = new LinkedHashMap<>();
        config.put("realm", StubIdp.REALM);
        config.put("replyUrl", StubIdp.REPLY);
        config.put("signals", false);
        config.put("idpMetadata", StubIdp.idpMetadata());
        config.put("pep", pep);
        return config;
    }

    private static String ecPkcs8(Path path) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        var pair = generator.generateKeyPair();
        String encoded = Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(pair.getPrivate().getEncoded());
        Files.writeString(path, "-----BEGIN PRIVATE KEY-----\n" + encoded + "\n-----END PRIVATE KEY-----\n");
        return path.toAbsolutePath().toString();
    }

    private static void waitFor(RelyingParty party, String what, Predicate<Status> ready) throws InterruptedException {
        Pep pep = party.pep();
        assertTrue(pep != null, "a PEP");
        long deadline = System.nanoTime() + 90_000_000_000L;
        while (System.nanoTime() < deadline) {
            if (ready.test(pep.status())) return;
            try {
                Thread.sleep(200);
            } catch (InterruptedException err) {
                Thread.currentThread().interrupt();
                throw err;
            }
        }
        Status status = pep.status();
        assertTrue(ready.test(status), "the " + pep.config().name + " PEP never " + what + ": " + status.lastError);
    }

    private static boolean listed(JsonNode array, String text) {
        if (array == null || !array.isArray()) return false;
        for (JsonNode item : array) if (text.equals(item.asText())) return true;
        return false;
    }

    private static JsonNode resource(String name) {
        try (InputStream in = AuthzenTest.class.getResourceAsStream("/" + name)) {
            if (in == null) throw new IllegalStateException(name + " is not on the classpath");
            return Json.MAPPER.readTree(in);
        } catch (IOException err) {
            throw new IllegalStateException(name + " is not JSON", err);
        }
    }

    /** A stub PDP: catalogue, compiled policies, the directory's PIP, and a refused evaluation. */
    private static final class Pdp implements AutoCloseable {
        final String url;
        final AtomicInteger evaluations = new AtomicInteger();
        private final HttpServer server;
        private final ExecutorService executor;
        private final JsonNode rows;
        private final JsonNode directory;
        private String token = "";
        private List<ObjectNode> policies = List.of();
        private List<String> fga = List.of();

        private Pdp(HttpServer server, ExecutorService executor, JsonNode rows, JsonNode directory) {
            this.server = server;
            this.executor = executor;
            this.rows = rows;
            this.directory = directory;
            this.url = "http://127.0.0.1:" + server.getAddress().getPort();
        }

        static Pdp open(JsonNode table) throws IOException {
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            ExecutorService executor = Executors.newCachedThreadPool(runnable -> {
                Thread thread = new Thread(runnable, "authzen-pdp");
                thread.setDaemon(true);
                return thread;
            });
            server.setExecutor(executor);
            Pdp pdp = new Pdp(server, executor, table.path("catalogue"), table.path("directory"));
            server.createContext("/", pdp::handle);
            server.start();
            return pdp;
        }

        synchronized void serve(String phase, List<ObjectNode> policies) {
            this.token = "authzen-" + phase;
            this.policies = List.copyOf(policies);
            this.fga = "application".equals(phase) ? List.of(StubIdp.REALM) : List.of();
        }

        @Override
        public void close() {
            server.stop(0);
            executor.shutdownNow();
        }

        private void handle(HttpExchange exchange) {
            try {
                String text = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                String path = exchange.getRequestURI().getPath();
                if (path == null) path = "";
                Reply reply = answer(path, text);
                byte[] out = reply.body.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("content-type", reply.type);
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

        private Reply answer(String path, String body) {
            if ("/oauth2/token".equals(path)) {
                ObjectNode token = Json.object();
                token.put("access_token", "pep-token");
                token.put("token_type", "DPoP");
                token.put("expires_in", 300);
                return Reply.json(200, token);
            }
            if ("/xacml/pep/register".equals(path)) {
                ObjectNode registered = Json.object();
                registered.put("registered", true);
                registered.put("identity", STUB_PEP_DN);
                return Reply.json(201, registered);
            }
            if ("/xacml/pep/heartbeat".equals(path)) {
                ObjectNode heartbeat = Json.object();
                heartbeat.put("acknowledged", true);
                heartbeat.put("current", true);
                return Reply.json(200, heartbeat);
            }
            if ("/xacml/pep/authzen-catalogue".equals(path)) return Reply.json(200, catalogue());
            if ("/xacml/pep/policies".equals(path)) return Reply.json(200, policies());
            if ("/xacml/pip".equals(path)) return new Reply(200, "application/xml", pipAnswer(directory, body));
            if ("/admin-api/pep-audit".equals(path)) {
                ObjectNode audit = Json.object();
                audit.put("acknowledged", 0);
                return Reply.json(200, audit);
            }
            if ("/access/v1/evaluation".equals(path)) {
                evaluations.incrementAndGet();
                ObjectNode error = Json.object();
                error.put("error", "server_error");
                return Reply.json(500, error);
            }
            ObjectNode missing = Json.object();
            missing.put("error", "not_found");
            return Reply.json(404, missing);
        }

        private ObjectNode catalogue() {
            List<String> applications = fga();
            ObjectNode body = Json.object();
            body.put("syncToken", "authzen-rows-" + applications.size());
            body.set("rows", rows.deepCopy());
            ArrayNode fgaApplications = Json.array();
            for (String application : applications) fgaApplications.add(application);
            body.set("fgaApplications", fgaApplications);
            ObjectNode settings = Json.object();
            settings.put("obligationsProfile", true);
            body.set("settings", settings);
            return body;
        }

        private ObjectNode policies() {
            String sync;
            List<ObjectNode> held;
            synchronized (this) {
                sync = token;
                held = policies;
            }
            ObjectNode body = Json.object();
            body.put("syncToken", sync);
            JsonNode root = Json.MAPPER.nullNode();
            ArrayNode list = Json.array();
            for (ObjectNode row : held) {
                list.add(row.deepCopy());
                if (root.isNull() && row.path("isRoot").asBoolean(false) && row.get("name") != null) {
                    root = row.get("name").deepCopy();
                }
            }
            if (root == null || root.isNull()) body.putNull("root");
            else body.set("root", root);
            body.set("policies", list);
            body.set("withheld", Json.array());
            body.put("note", "");
            return body;
        }

        private synchronized List<String> fga() {
            return fga;
        }

        /** The subject id's person, and each designator by its attribute name. */
        private static String pipAnswer(JsonNode directory, String query) {
            String subject = "";
            int subjectAt = query.indexOf("subject:subject-id");
            if (subjectAt >= 0) {
                int valueAt = query.indexOf("<AttributeValue", subjectAt);
                if (valueAt >= 0) {
                    Slice span = between(query, valueAt, "\">", "</AttributeValue>");
                    if (span != null) subject = span.text;
                }
            }
            JsonNode person = null;
            if (directory != null && directory.isArray()) {
                for (JsonNode entry : directory) {
                    JsonNode username = entry.get("username");
                    if (username != null && username.isTextual() && subject.equals(username.asText())) {
                        person = entry;
                        break;
                    }
                }
            }
            StringBuilder attributes = new StringBuilder();
            int from = 0;
            while (true) {
                Slice designator = between(query, from, "<AttributeDesignator", "/>");
                if (designator == null) break;
                from = designator.at;
                Slice id = between(designator.text, 0, "AttributeId=\"", "\"");
                Slice category = between(designator.text, 0, "Category=\"", "\"");
                Slice dataType = between(designator.text, 0, "DataType=\"", "\"");
                String attributeId = id == null ? "" : id.text;
                JsonNode value = person == null ? null : person.path("attributes").get(attributeId);
                if (value == null || !value.isTextual()) continue;
                if (!ACCESS_SUBJECT.equals(category == null ? "" : category.text) || !XS_STRING.equals(dataType == null ? "" : dataType.text)) {
                    continue;
                }
                attributes.append("<Attribute AttributeId=\"").append(attributeId)
                        .append("\" IncludeInResult=\"false\"><AttributeValue DataType=\"")
                        .append(XS_STRING).append("\">").append(value.asText())
                        .append("</AttributeValue></Attribute>");
            }
            return "<PIPResponse xmlns=\"urn:sts:xacml:pip:1.0\"><Attributes xmlns=\"urn:oasis:names:tc:xacml:3.0:core:schema:wd-17\" Category=\""
                    + ACCESS_SUBJECT + "\">" + attributes + "</Attributes></PIPResponse>";
        }
    }

    private static Slice between(String text, int from, String start, String end) {
        if (text == null || from < 0 || from > text.length()) return null;
        int at = text.indexOf(start, from);
        if (at < 0) return null;
        int value = at + start.length();
        int stop = text.indexOf(end, value);
        if (stop < 0) return null;
        return new Slice(text.substring(value, stop), stop);
    }

    private static final class Slice {
        final String text;
        final int at;

        Slice(String text, int at) {
            this.text = text;
            this.at = at;
        }
    }

    private static final class Reply {
        final int status;
        final String type;
        final String body;

        Reply(int status, String type, String body) {
            this.status = status;
            this.type = type;
            this.body = body;
        }

        static Reply json(int status, JsonNode body) {
            return new Reply(status, "application/json", body.toString());
        }
    }
}
