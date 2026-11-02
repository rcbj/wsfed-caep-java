// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.wsfed;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** WS-Federation 1.2 passive requestor. It does not start the Shared Signals receiver. */
public final class RelyingParty {
    public static final int MAX_RELAY_STATE = 1024;
    private static final Set<String> PROTOCOL = Set.of("wa", "wtrealm", "wreply", "wctx", "wct", "wreq", "wreqptr", "wfresh", "wauth", "whr");
    private static final DateTimeFormatter WCT = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'").withZone(ZoneOffset.UTC);

    public final Resolved config;
    private IdpMetadata idp;
    private final MemoryReplayCache replayCache;

    public RelyingParty(Resolved config, IdpMetadata idp, MemoryReplayCache replayCache) {
        this.config = config;
        this.idp = idp;
        this.replayCache = replayCache == null ? new MemoryReplayCache() : replayCache;
    }

    public static Resolved resolveConfig(Map<String, Object> config, String baseDir) {
        return Config.resolve(config, baseDir);
    }

    public static Resolved resolveConfig(Map<String, Object> config) {
        return Config.resolve(config, null);
    }

    public static Resolved readConfigFile(String path, Map<String, Object> overrides) {
        return Config.readFile(path, overrides);
    }

    public static Resolved readConfigFile(String path) {
        return Config.readFile(path, null);
    }

    public static RelyingParty create(Map<String, Object> config) {
        RelyingParty party = new RelyingParty(resolveConfig(config), null, null);
        party.refreshMetadata();
        return party;
    }

    public static RelyingParty fromFile(String path) {
        return fromFile(path, null);
    }

    public static RelyingParty fromFile(String path, Map<String, Object> overrides) {
        RelyingParty party = new RelyingParty(readConfigFile(path, overrides), null, null);
        party.refreshMetadata();
        return party;
    }

    public IdpMetadata getIdp() {
        if (idp == null) throw new WsFedError("metadata", "the identity provider's metadata has not been loaded");
        return idp;
    }

    public IdpMetadata refreshMetadata() {
        String source = config.idpMetadata;
        String xml;
        if (source.startsWith("<")) {
            xml = source;
        } else if (source.startsWith("http://") || source.startsWith("https://")) {
            HttpClient.Tls tls = null;
            if (config.idpCa != null) {
                tls = new HttpClient.Tls();
                tls.ca = config.idpCa;
            }
            HttpClient.Response answer = HttpClient.send(source, "GET", Map.of("accept", "application/samlmetadata+xml, application/xml, text/xml"), null, tls, "metadata");
            if (answer.status != 200) throw new WsFedError("metadata", source + " answered HTTP " + answer.status);
            xml = answer.body;
        } else {
            try {
                xml = Files.readString(Path.of(source));
            } catch (Exception err) {
                throw new WsFedError("metadata", "the identity provider metadata file " + source + " cannot be read", err);
            }
        }
        idp = IdpMetadata.read(xml, config.idpEntityId);
        return idp;
    }

    public String metadata() {
        return IdpMetadata.writeRp(config.realm, config.replyUrl, config.certificate);
    }

    public static final class LoginRequest {
        public final String id;
        public final String url;
        public final String wctx;

        public LoginRequest(String id, String url, String wctx) {
            this.id = id;
            this.url = url;
            this.wctx = wctx;
        }
    }

    public LoginRequest login() {
        return login(Map.of());
    }

    public LoginRequest login(Map<String, ?> options) {
        Map<String, ?> opts = options == null ? Map.of() : options;
        String relay = opts.get("relayState") == null ? null : String.valueOf(opts.get("relayState"));
        if (relay != null && relay.getBytes(StandardCharsets.UTF_8).length > MAX_RELAY_STATE) {
            throw new WsFedError("config", "relayState is longer than " + MAX_RELAY_STATE + " bytes");
        }
        String id = hex(20);
        StringBuilder wctx = new StringBuilder("id=").append(encode(id));
        if (relay != null) wctx.append("&ru=").append(encode(relay));
        List<String[]> pairs = new ArrayList<>();
        pairs.add(new String[] {"wa", "wsignin1.0"});
        pairs.add(new String[] {"wtrealm", config.realm});
        pairs.add(new String[] {"wreply", config.replyUrl});
        pairs.add(new String[] {"wctx", wctx.toString()});
        pairs.add(new String[] {"wct", WCT.format(ZonedDateTime.now(ZoneOffset.UTC))});
        if (config.requestTokenType) {
            pairs.add(new String[] {"wreq", "<wst:RequestSecurityToken xmlns:wst=\"" + Xmls.TRUST13 + "\"><wst:TokenType>" + Xmls.SAML2_TOKEN + "</wst:TokenType></wst:RequestSecurityToken>"});
        }
        boolean force = Boolean.TRUE.equals(opts.get("forceAuthn"));
        if (force) {
            pairs.add(new String[] {"wfresh", "0"});
        } else if (opts.get("freshness") != null) {
            Object freshness = opts.get("freshness");
            if (freshness instanceof Boolean || !(freshness instanceof Number number) || number.doubleValue() != number.longValue() || number.longValue() < 0) {
                throw new WsFedError("config", "freshness is a whole number of minutes");
            }
            pairs.add(new String[] {"wfresh", Long.toString(number.longValue())});
        }
        if (opts.get("authenticationMethod") != null) pairs.add(new String[] {"wauth", String.valueOf(opts.get("authenticationMethod"))});
        if (opts.get("homeRealm") != null) pairs.add(new String[] {"whr", String.valueOf(opts.get("homeRealm"))});
        Object extra = opts.get("params");
        if (extra instanceof Map<?, ?> map) {
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                String key = String.valueOf(entry.getKey());
                if (PROTOCOL.contains(key)) throw new WsFedError("config", "params cannot set " + key + "; it is the protocol's own");
                pairs.add(new String[] {key, String.valueOf(entry.getValue())});
            }
        }
        String endpoint = getIdp().passiveRequestorEndpoint;
        String joiner = endpoint.contains("?") ? "&" : "?";
        return new LoginRequest(id, endpoint + joiner + form(pairs), wctx.toString());
    }

    public WsFedLogin handleReply(Map<String, ?> request, Object requestId) {
        IdpMetadata provider = getIdp();
        Params params = paramsOf(request);
        String wa = params.form.containsKey("wa") ? params.form.get("wa") : params.query.get("wa");
        if ("wsignoutcleanup1.0".equals(wa) || "wsignout1.0".equals(wa)) {
            throw new WsFedError("message", "the request is " + wa + ", a sign-out, not a sign-in response; see isSignOutCleanup()");
        }
        String method = request.get("method") == null ? "" : String.valueOf(request.get("method"));
        if (!"POST".equalsIgnoreCase(method)) {
            throw new WsFedError("message", "a sign-in response is POSTed (WS-Federation 13.2.2); this request is a GET");
        }
        if (!"wsignin1.0".equals(wa)) {
            throw new WsFedError("message", "the request's wa is " + (wa == null || wa.isEmpty() ? "(none)" : wa) + ", not wsignin1.0");
        }
        if (params.form.containsKey("wresultptr")) {
            throw new WsFedError("message", "the response is by reference (wresultptr), which is never dereferenced; only wresult is accepted");
        }
        String wresult = params.form.get("wresult");
        if (wresult == null || wresult.isEmpty()) throw new WsFedError("message", "the request carries no wresult");
        Map<String, String> wctx = query(params.form.getOrDefault("wctx", ""));
        String got = wctx.get("id");
        List<String> expected = expected(requestId);
        if (got != null) {
            if (!expected.contains(got)) {
                throw new WsFedError("validation", "the response answers " + got + ", which is not a sign-in this browser has outstanding");
            }
        } else if (!config.allowUnsolicited) {
            throw new WsFedError("validation", "the response is unsolicited (its wctx names no request), and unsolicited responses are not accepted");
        }
        TokenValidator.Context ctx = new TokenValidator.Context();
        ctx.realm = config.realm;
        ctx.replyUrl = config.replyUrl;
        ctx.idpEntityId = provider.entityId;
        ctx.idpCertificates = provider.signingCertificates;
        ctx.decryptionKey = config.privateKey;
        ctx.clockSkewMs = config.clockSkewMs;
        ctx.wantAssertionsEncrypted = config.wantAssertionsEncrypted;
        ctx.replayCache = replayCache;
        WsFedLogin token = TokenValidator.validate(wresult, ctx);
        if (got != null) token.requestId = got;
        if (wctx.containsKey("ru")) token.relayState = wctx.get("ru");
        return token;
    }

    public boolean isSignOutCleanup(Map<String, ?> request) {
        Params params = paramsOf(request);
        String wa = params.form.containsKey("wa") ? params.form.get("wa") : params.query.get("wa");
        return "wsignoutcleanup1.0".equals(wa) || "wsignout1.0".equals(wa);
    }

    public String logout(String reply) {
        List<String[]> pairs = new ArrayList<>();
        pairs.add(new String[] {"wa", "wsignout1.0"});
        pairs.add(new String[] {"wtrealm", config.realm});
        if (reply != null && !reply.isEmpty()) pairs.add(new String[] {"wreply", reply});
        String endpoint = getIdp().passiveRequestorEndpoint;
        String joiner = endpoint.contains("?") ? "&" : "?";
        return endpoint + joiner + form(pairs);
    }

    private static List<String> expected(Object requestId) {
        List<String> out = new ArrayList<>();
        if (requestId == null) return out;
        if (requestId instanceof String text) {
            out.add(text);
            return out;
        }
        if (requestId instanceof Iterable<?> list) {
            for (Object item : list) if (item != null) out.add(String.valueOf(item));
            return out;
        }
        out.add(String.valueOf(requestId));
        return out;
    }

    private record Params(Map<String, String> form, Map<String, String> query) {}

    private static Params paramsOf(Map<String, ?> request) {
        String url = request.get("url") == null ? "" : String.valueOf(request.get("url"));
        String query = "";
        int mark = url.indexOf('?');
        if (mark >= 0) {
            query = url.substring(mark + 1);
            int hash = query.indexOf('#');
            if (hash >= 0) query = query.substring(0, hash);
        }
        String method = request.get("method") == null ? "" : String.valueOf(request.get("method"));
        Map<String, String> form = "POST".equalsIgnoreCase(method) ? formOf(request.get("body")) : new LinkedHashMap<>();
        return new Params(form, query(query));
    }

    private static Map<String, String> formOf(Object body) {
        if (body == null) return new LinkedHashMap<>();
        if (body instanceof String text) return query(text);
        if (body instanceof Map<?, ?> map) {
            Map<String, String> out = new LinkedHashMap<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (entry.getValue() instanceof String value && !out.containsKey(String.valueOf(entry.getKey()))) {
                    out.put(String.valueOf(entry.getKey()), value);
                }
            }
            return out;
        }
        return new LinkedHashMap<>();
    }

    private static Map<String, String> query(String text) {
        Map<String, String> out = new LinkedHashMap<>();
        if (text == null || text.isEmpty()) return out;
        for (String part : text.split("&", -1)) {
            if (part.isEmpty()) continue;
            int eq = part.indexOf('=');
            String key = decode(eq < 0 ? part : part.substring(0, eq));
            String value = decode(eq < 0 ? "" : part.substring(eq + 1));
            out.putIfAbsent(key, value);
        }
        return out;
    }

    private static String form(List<String[]> pairs) {
        StringBuilder out = new StringBuilder();
        for (String[] pair : pairs) {
            if (out.length() > 0) out.append('&');
            out.append(encode(pair[0])).append('=').append(encode(pair[1]));
        }
        return out.toString();
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static String decode(String value) {
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }

    private static String hex(int bytes) {
        byte[] raw = new byte[bytes];
        new SecureRandom().nextBytes(raw);
        StringBuilder out = new StringBuilder(bytes * 2);
        for (byte b : raw) out.append(String.format("%02x", b));
        return out.toString();
    }
}
