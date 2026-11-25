// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.wsfed.ssf;

import com.iyasec.pep.EventStream;
import com.iyasec.pep.Pep;
import com.iyasec.pep.key.SigningKey;
import com.iyasec.wsfed.Caught;
import com.iyasec.wsfed.HttpClient;
import com.iyasec.wsfed.Json;
import com.iyasec.wsfed.WsFedError;
import com.iyasec.wsfed.WsFedLogin;
import com.iyasec.wsfed.pep.EmbeddedPep;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.function.Consumer;
import java.util.function.Supplier;

/** Shared Signals poll receiver (OpenID SSF 1.0, RFC 8936). The relying party does not start one. */
public final class SignalsReceiver {
    public static final String POLL_METHOD = "urn:ietf:rfc:8936";

    public interface Log {
        void info(String message);
        void warn(String message);
        void error(String message);
    }

    public interface OnEndSessions {
        void end(List<String> sessions, SignalEvent event);
    }

    public static final class SignalEvent {
        public String type;
        public Object payload;
        public Map<String, String> subject;
        public String jti;
        public List<String> sessions;
        public boolean ended;
        public Number iat;
        public String txn;
    }

    public static final class Options {
        public HttpClient.Tls tls;
        public Supplier<Map<String, String>> headers;
        public List<String> eventsRequested;
        public List<String> endOn;
        public SessionIndex sessionIndex;
        public String subjectAttribute;
        public String description;
        public int pollIntervalMs = 5000;
        public int maxEvents = 50;
        public Log log;
        /** Add Subject and Remove Subject. Default true. The demo reads {@code ssf.addSubjects}. */
        public boolean addSubjects = true;
        /** The relying party's embedded PEP. Null when there is none. */
        public Pep pep;
    }

    /** What Add Subject and Remove Subject have done since the receiver was made. */
    public static final class SubjectsHealth {
        public long added;
        public long removed;
        public long refused;
        public long failed;
        public String lastError = "";
    }

    private final String transmitter;
    private final OnEndSessions onEnd;
    private final HttpClient.Tls tls;
    private final Supplier<Map<String, String>> headers;
    private final List<String> eventsRequested;
    private final List<String> endOn;
    private final SessionIndex index;
    private final String subjectAttribute;
    private final String description;
    private final int pollIntervalMs;
    private final int maxEvents;
    private final Log log;
    private final boolean addSubjects;
    /** The PEP whose policy events this stream carries. Null unless it wants them. */
    private final Pep pep;
    /** What the stream carries ({@code requested} or {@code excluded}), once {@code start} knows. */
    private volatile EventStream pepStream;
    private final SubjectsHealth health = new SubjectsHealth();
    private final Object healthLock = new Object();
    private Map<String, Object> config;
    private Map<String, Object> stream;
    private List<Map<String, Object>> keys = List.of();
    private long keysAt;
    private volatile boolean running;
    private final List<String> ack = new ArrayList<>();
    private final Map<String, Object> errs = new LinkedHashMap<>();
    private final Map<String, List<Consumer<SignalEvent>>> handlers = new LinkedHashMap<>();
    private final Object pollLock = new Object();
    private Flight inflight;
    private Thread thread;

    public SignalsReceiver(String transmitter, OnEndSessions onEnd) {
        this(transmitter, onEnd, null);
    }

    public SignalsReceiver(String transmitter, OnEndSessions onEnd, Options options) {
        if (onEnd == null) throw new WsFedError("config", "onEndSessions is required");
        if (transmitter == null || !(transmitter.startsWith("http://") || transmitter.startsWith("https://"))) {
            throw new WsFedError("config", "transmitter must be an http(s) URL");
        }
        Options opts = options == null ? new Options() : options;
        this.transmitter = transmitter.endsWith("/") ? transmitter.substring(0, transmitter.length() - 1) : transmitter;
        this.onEnd = onEnd;
        this.tls = opts.tls;
        this.headers = opts.headers;
        List<String> requested = opts.eventsRequested == null ? new ArrayList<>(Events.DEFAULT_EVENTS_REQUESTED) : new ArrayList<>(opts.eventsRequested);
        Pep given = opts.pep;
        Pep kept = null;
        if (given != null) {
            String client = opts.tls == null || opts.tls.key == null ? null : SigningKey.pemThumbprint(opts.tls.key);
            String pepKey = given.keyThumbprint();
            if (client != null && !client.isEmpty() && pepKey != null && !pepKey.isEmpty() && client.equals(pepKey)) {
                throw new WsFedError("config", "the receiver's TLS client key is pep.assertionKey; the PEP needs a key of its own");
            }
            if (EmbeddedPep.wantsEvents(given)) {
                final Pep policyPep = given;
                kept = policyPep;
                if (!requested.contains(Pep.POLICIES_CHANGED_EVENT)) requested.add(Pep.POLICIES_CHANGED_EVENT);
                handlers.computeIfAbsent(Pep.POLICIES_CHANGED_EVENT, key -> new ArrayList<>()).add(event -> {
                    try {
                        policyPep.onPolicyEvent(EmbeddedPep.toJson(event.payload));
                    } catch (RuntimeException err) {
                        Caught.warn(err);
                    }
                });
            }
        }
        this.eventsRequested = requested;
        this.endOn = opts.endOn == null ? List.copyOf(Events.DEFAULT_ENDING_EVENTS) : List.copyOf(opts.endOn);
        this.index = opts.sessionIndex == null ? new SessionIndex() : opts.sessionIndex;
        this.subjectAttribute = opts.subjectAttribute;
        this.description = opts.description;
        this.pollIntervalMs = opts.pollIntervalMs;
        this.maxEvents = opts.maxEvents;
        this.log = opts.log == null ? new PrintLog() : opts.log;
        this.addSubjects = opts.addSubjects;
        this.pep = kept;
    }

    public Map<String, Object> stream() {
        return stream;
    }

    /** The event types this receiver asks its stream for. */
    public List<String> eventsRequested() {
        return List.copyOf(eventsRequested);
    }

    /** Tracked, not untracked, not past its expiry, and not ended by an event. */
    public boolean isTracked(String localId) {
        return index.contains(localId);
    }

    /** What Add Subject and Remove Subject have done. */
    public SubjectsHealth subjectsHealth() {
        synchronized (healthLock) {
            SubjectsHealth copy = new SubjectsHealth();
            copy.added = health.added;
            copy.removed = health.removed;
            copy.refused = health.refused;
            copy.failed = health.failed;
            copy.lastError = health.lastError;
            return copy;
        }
    }

    /**
     * Tracks a local session and, when {@code addSubjects} is on and the
     * receiver is running, asks the transmitter to send events about that
     * person. The call is inline and never fails the sign-in.
     */
    public void track(String localId, WsFedLogin login) {
        SessionIndex.Session session = SessionIndex.trackedFrom(localId, login, subjectAttribute, null);
        index.add(session);
        subjectCall(true, session);
    }

    /** Stops tracking a local session and removes the subject when it was the last one. */
    public void untrack(String localId) {
        forget(localId);
    }

    public SignalsReceiver on(String eventType, Consumer<SignalEvent> handler) {
        handlers.computeIfAbsent(eventType, key -> new ArrayList<>()).add(handler);
        return this;
    }

    public void start() {
        if (running) return;
        config = discover();
        jwks(true);
        stream = ensureStream();
        Object delivery = stream.get("delivery");
        Object endpoint = delivery instanceof Map<?, ?> map ? map.get("endpoint_url") : null;
        if (!(endpoint instanceof String) || ((String) endpoint).isEmpty()) {
            throw new WsFedError("ssf", "the stream has no poll endpoint_url");
        }
        if (pep != null) {
            boolean carried = carries(stream, "events_delivered");
            if (!(stream.get("events_delivered") instanceof List<?>)) carried = carries(stream, "events_requested");
            if (!(stream.get("events_delivered") instanceof List<?>) && !(stream.get("events_requested") instanceof List<?>)) carried = true;
            EventStream state = carried ? EventStream.REQUESTED : EventStream.EXCLUDED;
            pep.setEventStream(state);
            pepStream = state;
        }
        running = true;
        Object delivered = stream.get("events_delivered");
        int count = delivered instanceof List<?> list ? list.size() : 0;
        log.info("ssf: polling stream " + stream.get("stream_id") + " at " + endpoint + ", delivering " + count + " event type(s)");
        if (addSubjects && pep != null) {
            Map<String, Object> subject = new LinkedHashMap<>();
            subject.put("format", "opaque");
            subject.put("id", pep.config().application);
            sendSubject(true, subject);
        }
        thread = new Thread(this::loop, "ssf-poll");
        thread.setDaemon(true);
        thread.start();
    }

    public void stop() {
        running = false;
        reportPepStream(EventStream.DOWN);
        Thread current = thread;
        if (current != null && current != Thread.currentThread()) {
            current.interrupt();
            try {
                current.join(20_000);
            } catch (InterruptedException err) {
                Caught.error(err);
                Thread.currentThread().interrupt();
            }
            thread = null;
        }
    }

    public boolean pollOnce() {
        Flight flight;
        boolean owner;
        synchronized (pollLock) {
            if (inflight == null) {
                inflight = new Flight();
                owner = true;
            } else {
                owner = false;
            }
            flight = inflight;
        }
        if (!owner) {
            try {
                flight.done.await();
            } catch (InterruptedException err) {
                Caught.error(err);
                Thread.currentThread().interrupt();
                throw new WsFedError("ssf", "the poll was interrupted", err);
            }
            if (flight.error != null) throw flight.error;
            return flight.result;
        }
        try {
            flight.result = pollNow();
            reportPepStream(pepStream);
            return flight.result;
        } catch (RuntimeException err) {
            Caught.error(err);
            reportPepStream(EventStream.DOWN);
            flight.error = err;
            throw err;
        } finally {
            synchronized (pollLock) {
                if (inflight == flight) inflight = null;
            }
            flight.done.countDown();
        }
    }

    private void loop() {
        while (running && !Thread.currentThread().isInterrupted()) {
            long delay = pollIntervalMs;
            try {
                if (pollOnce()) delay = 0;
            } catch (Exception err) {
                Caught.warn(err);
                log.warn("ssf: poll failed: " + err.getMessage());
                delay = Math.min(pollIntervalMs * 4L, 60_000);
            }
            if (!running) return;
            try {
                Thread.sleep(delay);
            } catch (InterruptedException err) {
                Caught.warn(err);
                return;
            }
        }
    }

    private boolean pollNow() {
        String url = String.valueOf(map(stream.get("delivery")).get("endpoint_url"));
        List<String> pendingAck;
        Map<String, Object> pendingErrs;
        synchronized (ack) {
            pendingAck = new ArrayList<>(ack);
            ack.clear();
            pendingErrs = new LinkedHashMap<>(errs);
            errs.clear();
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("maxEvents", maxEvents);
        body.put("returnImmediately", Boolean.TRUE);
        if (!pendingAck.isEmpty()) body.put("ack", pendingAck);
        if (!pendingErrs.isEmpty()) body.put("setErrs", pendingErrs);
        Answer response = call("POST", url, body);
        if (response.status != 200) {
            synchronized (ack) {
                pendingAck.addAll(ack);
                ack.clear();
                ack.addAll(pendingAck);
                pendingErrs.putAll(errs);
                errs.clear();
                errs.putAll(pendingErrs);
            }
            throw new WsFedError("ssf", "the poll answered " + response.status + ": " + clip(Json.stringify(response.json)));
        }
        Map<String, Object> payload = response.json instanceof Map<?, ?> ? Json.object(response.json) : Map.of();
        Object sets = payload.get("sets");
        if (sets instanceof Map<?, ?> map) {
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                String jti = String.valueOf(entry.getKey());
                try {
                    handle(jti, String.valueOf(entry.getValue()));
                    synchronized (ack) { ack.add(jti); }
                } catch (Exception err) {
                    Caught.warn(err);
                    log.warn("ssf: SET " + jti + " refused: " + err.getMessage());
                    String code = err instanceof WsFedError wsfed && "signature".equals(wsfed.code) ? "invalid_key" : "invalid_request";
                    Map<String, Object> problem = new LinkedHashMap<>();
                    problem.put("err", code);
                    problem.put("description", String.valueOf(err.getMessage()));
                    synchronized (ack) { errs.put(jti, problem); }
                }
            }
        }
        return Boolean.TRUE.equals(payload.get("moreAvailable"));
    }

    private void handle(String jti, String token) {
        Jws.Verified verified;
        try {
            verified = Jws.verify(token, jwks(false));
        } catch (WsFedError err) {
            String message = String.valueOf(err.getMessage());
            if (!message.contains("publishes no") && !message.contains("does not verify")) throw err;
            verified = Jws.verify(token, jwks(true));
        }
        Object typ = verified.header.get("typ");
        if (typ != null && !"secevent+jwt".equalsIgnoreCase(String.valueOf(typ))) {
            throw new WsFedError("validation", "the SET's typ is " + typ);
        }
        if (!String.valueOf(config.get("issuer")).equals(String.valueOf(verified.payload.get("iss")))) {
            throw new WsFedError("validation", "the SET was issued by " + verified.payload.get("iss") + ", not " + config.get("issuer"));
        }
        List<String> want = strings(stream.get("aud"));
        List<String> aud = strings(verified.payload.get("aud"));
        if (!want.isEmpty() && aud.stream().noneMatch(want::contains)) {
            throw new WsFedError("validation", "the SET is for " + String.join(", ", aud) + ", not this stream");
        }
        if (verified.payload.get("jti") != null && !jti.equals(String.valueOf(verified.payload.get("jti")))) {
            throw new WsFedError("validation", "the SET's jti is not the one it was delivered under");
        }
        Object events = verified.payload.get("events");
        if (!(events instanceof Map<?, ?> eventMap) || eventMap.isEmpty()) throw new WsFedError("validation", "the SET carries no events");
        for (Map.Entry<?, ?> entry : eventMap.entrySet()) {
            String eventType = String.valueOf(entry.getKey());
            Object body = entry.getValue();
            Object subId = verified.payload.get("sub_id");
            if (subId == null && body instanceof Map<?, ?> bodyMap) subId = bodyMap.get("subject");
            Map<String, String> subject = Events.subjectOf(subId, String.valueOf(config.get("issuer")));
            List<String> sessions = sessionsFor(eventType, subject);
            boolean ends = endOn.contains(eventType) && !sessions.isEmpty();
            SignalEvent event = new SignalEvent();
            event.type = eventType;
            event.payload = body == null ? Map.of() : body;
            event.subject = subject;
            event.jti = jti;
            event.sessions = sessions;
            event.ended = ends;
            Object iat = verified.payload.get("iat");
            if (iat instanceof Number number && !(iat instanceof Boolean)) event.iat = number;
            if (verified.payload.get("txn") instanceof String txn) event.txn = txn;
            if (ends) {
                try {
                    onEnd.end(sessions, event);
                } catch (Exception err) {
                    Caught.error(err);
                    log.error("ssf: onEndSessions threw for " + eventType + " (SET " + jti + " is still acknowledged): " + err.getMessage());
                    event.ended = false;
                }
                if (event.ended) {
                    for (String localId : sessions) forget(localId);
                }
            }
            List<Consumer<SignalEvent>> both = new ArrayList<>();
            if (handlers.get(eventType) != null) both.addAll(handlers.get(eventType));
            if (handlers.get("*") != null) both.addAll(handlers.get("*"));
            for (Consumer<SignalEvent> handler : both) {
                try {
                    handler.accept(event);
                } catch (Exception err) {
                    Caught.error(err);
                    log.error("ssf: a handler for " + eventType + " threw (SET " + jti + " is still acknowledged): " + err.getMessage());
                }
            }
        }
    }

    private List<String> sessionsFor(String eventType, Map<String, String> subject) {
        if (Events.EVENT.get("verification").equals(eventType) || Events.EVENT.get("stream_updated").equals(eventType)) return List.of();
        if (subject.get("idp_session") != null) {
            List<String> found = index.byIdpSession(subject.get("idp_session"));
            if (!found.isEmpty() || Events.EVENT.get("session_revoked").equals(eventType)) return found;
        }
        if (subject.get("person") != null) return index.byPerson(subject.get("person"));
        if (subject.get("email") != null) return index.byEmail(subject.get("email"));
        return List.of();
    }

    private Map<String, Object> discover() {
        String url = transmitter + "/.well-known/ssf-configuration";
        Answer response = call("GET", url, null);
        if (response.status != 200 || !(response.json instanceof Map<?, ?>)) {
            throw new WsFedError("ssf", url + " answered " + response.status + " without a usable transmitter configuration");
        }
        Map<String, Object> found = Json.object(response.json);
        if (found.get("configuration_endpoint") == null || found.get("jwks_uri") == null) {
            throw new WsFedError("ssf", url + " answered " + response.status + " without a usable transmitter configuration");
        }
        Object supported = found.get("delivery_methods_supported");
        if (supported instanceof List<?> list && list.stream().noneMatch(POLL_METHOD::equals)) {
            throw new WsFedError("ssf", "the transmitter does not offer poll delivery (RFC 8936)");
        }
        return found;
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> jwks(boolean force) {
        if (!force && !keys.isEmpty() && System.currentTimeMillis() - keysAt < 3_600_000) return keys;
        Answer response = call("GET", String.valueOf(config.get("jwks_uri")), null);
        Object raw = response.json instanceof Map<?, ?> map ? map.get("keys") : null;
        if (response.status != 200 || !(raw instanceof List<?> list)) {
            throw new WsFedError("ssf", "the transmitter's JWKS answered " + response.status);
        }
        List<Map<String, Object>> parsed = new ArrayList<>();
        for (Object item : list) if (item instanceof Map<?, ?>) parsed.add(Json.object(item));
        keys = parsed;
        keysAt = System.currentTimeMillis();
        return keys;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> ensureStream() {
        String endpoint = String.valueOf(config.get("configuration_endpoint"));
        Answer listed = call("GET", endpoint, null);
        if (listed.status == 200) {
            List<Object> all = new ArrayList<>();
            if (listed.json instanceof List<?> list) all.addAll(list);
            else if (listed.json != null) all.add(listed.json);
            for (Object item : all) {
                if (!(item instanceof Map<?, ?> raw)) continue;
                Map<String, Object> one = Json.object(item);
                Object delivery = one.get("delivery");
                if (delivery instanceof Map<?, ?> map && POLL_METHOD.equals(map.get("method")) && one.get("stream_id") != null) {
                    return withRequestedEvents(one, endpoint);
                }
            }
        } else if (listed.status != 404) {
            throw new WsFedError("ssf", "listing the streams at " + endpoint + " answered " + listed.status + ": " + clip(Json.stringify(listed.json)));
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("delivery", Map.of("method", POLL_METHOD));
        body.put("events_requested", eventsRequested);
        if (description != null) body.put("description", description);
        Answer created = call("POST", endpoint, body);
        Map<String, Object> made = created.json instanceof Map<?, ?> ? Json.object(created.json) : Map.of();
        if ((created.status != 200 && created.status != 201) || made.get("stream_id") == null) {
            throw new WsFedError("ssf", "creating a stream at " + endpoint + " answered " + created.status + ": " + clip(Json.stringify(created.json)));
        }
        return made;
    }

    /**
     * A stream found rather than created can predate an event type this
     * receiver asks for now. PATCH merges the missing types in. A transmitter
     * that refuses leaves the stream as it was; the receiver still starts.
     */
    private Map<String, Object> withRequestedEvents(Map<String, Object> found, String endpoint) {
        List<String> requested = eventNames(found.get("events_requested"));
        if (requested == null) requested = eventNames(found.get("events_delivered"));
        if (requested == null) return found;
        List<String> missing = new ArrayList<>();
        for (String event : eventsRequested) if (!requested.contains(event)) missing.add(event);
        if (missing.isEmpty()) return found;
        String streamId = String.valueOf(found.get("stream_id"));
        List<String> merged = new ArrayList<>(requested);
        merged.addAll(missing);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("stream_id", streamId);
        body.put("events_requested", merged);
        try {
            Answer updated = call("PATCH", endpoint, body);
            if (updated.status == 200 && updated.json instanceof Map<?, ?> raw) {
                Map<String, Object> next = Json.object(raw);
                if (streamId.equals(String.valueOf(next.get("stream_id")))) {
                    if (!next.containsKey("delivery") && found.get("delivery") != null) next.put("delivery", found.get("delivery"));
                    return next;
                }
            }
            log.error("ssf: adding " + String.join(", ", missing) + " to stream " + streamId + " answered " + updated.status + ": " + clip(Json.stringify(updated.json)));
        } catch (RuntimeException err) {
            Caught.error(err);
            log.error("ssf: adding " + String.join(", ", missing) + " to stream " + streamId + " failed: " + err.getMessage());
        }
        return found;
    }

    private Answer call(String method, String url, Object body) {
        Map<String, String> header = new LinkedHashMap<>();
        header.put("accept", "application/json");
        if (headers != null && headers.get() != null) header.putAll(headers.get());
        String payload = null;
        if (body != null) {
            header.put("content-type", "application/json");
            payload = Json.stringify(body);
        }
        HttpClient.Response answer = HttpClient.send(url, method, header, payload, tls, "ssf");
        Object parsed = null;
        if (answer.body != null && !answer.body.isEmpty()) {
            try {
                parsed = Json.parse(answer.body);
            } catch (WsFedError err) {
                parsed = answer.body;
            }
        }
        return new Answer(answer.status, parsed);
    }

    private void forget(String localId) {
        SessionIndex.Session session = index.take(localId);
        if (session == null) return;
        List<String> others;
        if (session.person != null && !session.person.isEmpty()) others = index.byPerson(session.person);
        else if (session.email != null && !session.email.isEmpty()) others = index.byEmail(session.email);
        else others = List.of();
        if (others.isEmpty()) subjectCall(false, session);
    }

    /** Add Subject or Remove Subject for a tracked person. Never retried, never an error to the caller. */
    private void subjectCall(boolean add, SessionIndex.Session session) {
        if (!addSubjects || !running) return;
        String issuer = config == null || config.get("issuer") == null ? "" : String.valueOf(config.get("issuer"));
        Map<String, Object> subject = subjectOfSession(session, issuer);
        if (subject == null) return;
        sendSubject(add, subject);
    }

    private static Map<String, Object> subjectOfSession(SessionIndex.Session session, String issuer) {
        if (session.person != null && !session.person.isEmpty() && issuer != null && !issuer.isEmpty()) {
            Map<String, Object> subject = new LinkedHashMap<>();
            subject.put("format", "iss_sub");
            subject.put("iss", issuer);
            subject.put("sub", session.person);
            return subject;
        }
        if (session.email != null && !session.email.isEmpty()) {
            Map<String, Object> subject = new LinkedHashMap<>();
            subject.put("format", "email");
            subject.put("email", session.email);
            return subject;
        }
        return null;
    }

    /** Add Subject or Remove Subject for {@code subject} on this stream, once. Counted, never thrown. */
    private void sendSubject(boolean add, Map<String, Object> subject) {
        String name = add ? "add_subject_endpoint" : "remove_subject_endpoint";
        String endpoint = config == null || config.get(name) == null ? "" : String.valueOf(config.get(name));
        String streamId = stream == null || stream.get("stream_id") == null ? "" : String.valueOf(stream.get("stream_id"));
        if (endpoint.isEmpty() || "null".equals(endpoint) || streamId.isEmpty() || "null".equals(streamId)) return;
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("stream_id", streamId);
        body.put("subject", subject);
        if (add) body.put("verified", Boolean.TRUE);
        String what = add ? "adding" : "removing";
        Object format = subject.get("format");
        try {
            Answer outcome = call("POST", endpoint, body);
            synchronized (healthLock) {
                if (outcome.status >= 200 && outcome.status < 300) {
                    if (add) health.added++;
                    else health.removed++;
                    return;
                }
                String line = "ssf: " + what + " a subject (" + format + ") on stream " + streamId + " answered " + outcome.status + ": " + clip(Json.stringify(outcome.json));
                if (outcome.status >= 400 && outcome.status < 500) health.refused++;
                else health.failed++;
                health.lastError = line;
                if (outcome.status == 403) log.warn(line);
                else log.error(line);
            }
        } catch (RuntimeException err) {
            Caught.error(err);
            String line = "ssf: " + what + " a subject (" + format + ") on stream " + streamId + " failed: " + err.getMessage();
            synchronized (healthLock) {
                health.failed++;
                health.lastError = line;
            }
            log.error(line);
        }
    }

    private void reportPepStream(EventStream state) {
        if (pep != null && state != null) pep.setEventStream(state);
    }

    private static boolean carries(Map<String, Object> stream, String name) {
        if (!(stream.get(name) instanceof List<?> list)) return false;
        for (Object item : list) if (Pep.POLICIES_CHANGED_EVENT.equals(String.valueOf(item))) return true;
        return false;
    }

    private static List<String> eventNames(Object value) {
        if (!(value instanceof List<?> list)) return null;
        List<String> out = new ArrayList<>();
        for (Object item : list) if (item != null) out.add(String.valueOf(item));
        return out;
    }

    private static List<String> strings(Object value) {
        List<String> out = new ArrayList<>();
        if (value instanceof List<?> list) {
            for (Object item : list) if (item != null) out.add(String.valueOf(item));
        } else if (value != null) {
            out.add(String.valueOf(value));
        }
        return out;
    }

    private static Map<String, Object> map(Object value) {
        Map<String, Object> out = Json.object(value);
        return out == null ? Map.of() : out;
    }

    private static String clip(String text) {
        if (text == null) return "";
        return text.length() <= 300 ? text : text.substring(0, 300);
    }

    private record Answer(int status, Object json) {}

    private static final class Flight {
        private final CountDownLatch done = new CountDownLatch(1);
        private boolean result;
        private RuntimeException error;
    }

    private static final class PrintLog implements Log {
        @Override public void info(String message) { System.out.println(message); }
        @Override public void warn(String message) { System.err.println(message); }
        @Override public void error(String message) { System.err.println(message); }
    }
}
