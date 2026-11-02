// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.wsfed.demo;

import com.iyasec.wsfed.Json;
import com.iyasec.wsfed.RelyingParty;
import com.iyasec.wsfed.WsFedLogin;
import com.iyasec.wsfed.ssf.SignalsReceiver;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * WS-Federation demo. GET /healthz is 200 ok before the identity provider is reachable.
 * A loopback realm and reply URL follow PORT. PUBLIC_URL or --public-url replaces the origin
 * and keeps the path. The default http://localhost:3000 is not an explicit public URL.
 */
public final class Demo {
    private static final byte[] GIF = Base64.getDecoder().decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7");

    public static final class Result {
        public final int status;
        public final List<String[]> headers;
        public final byte[] body;

        public Result(int status, List<String[]> headers, byte[] body) {
            this.status = status;
            this.headers = headers;
            this.body = body;
        }
    }

    public static final class App {
        private final RelyingParty rp;
        public SignalsReceiver receiver;
        public final Map<String, WsFedLogin> sessions = new LinkedHashMap<>();
        private final byte[] secret = new byte[32];
        private final String replyPath;
        private final String secure;

        public App(RelyingParty rp) {
            this(rp, null);
        }

        public App(RelyingParty rp, SignalsReceiver receiver) {
            this.rp = rp;
            this.receiver = receiver;
            new SecureRandom().nextBytes(secret);
            String path = URI.create(rp.config.replyUrl).getRawPath();
            this.replyPath = path == null || path.isEmpty() ? "/wsfed" : path;
            this.secure = "https".equals(URI.create(rp.config.replyUrl).getScheme()) ? "; Secure" : "";
        }

        public Result handle(String method, String target, Map<String, String> headers, byte[] body) {
            URI url = URI.create(target.startsWith("http") ? target : "http://localhost" + (target.startsWith("/") ? target : "/" + target));
            String path = url.getRawPath() == null || url.getRawPath().isEmpty() ? "/" : url.getRawPath();
            Map<String, String> cookies = cookies(headers == null ? null : headers.get("cookie"));
            String sid = unsign(cookies.get("sid"));
            method = method == null ? "" : method.toUpperCase();
            if ("/healthz".equals(path) && "GET".equals(method)) return text(200, "text/plain", "ok");
            if ("/login".equals(path) && "GET".equals(method)) {
                RelyingParty.LoginRequest request = rp.login(Map.of("relayState", "/"));
                return new Result(302, List.of(
                        new String[] {"location", request.url},
                        new String[] {"set-cookie", pending(sign(request.id), 600)}), new byte[0]);
            }
            if (path.equals(replyPath) && rp.isSignOutCleanup(Map.of("method", method, "url", target))) {
                if (sid != null) {
                    sessions.remove(sid);
                    if (receiver != null) receiver.untrack(sid);
                }
                return new Result(200, List.of(
                        new String[] {"content-type", "image/gif"},
                        new String[] {"set-cookie", "sid=; Path=/; HttpOnly; Max-Age=0" + secure}), GIF);
            }
            if (path.equals(replyPath) && "POST".equals(method)) {
                try {
                    WsFedLogin who = rp.handleReply(Map.of(
                            "method", "POST",
                            "url", target,
                            "body", new String(body == null ? new byte[0] : body, StandardCharsets.UTF_8)), unsign(cookies.get("wsfed_pending")));
                    String sessionId = Base64.getUrlEncoder().withoutPadding().encodeToString(random(24));
                    sessions.put(sessionId, who);
                    if (receiver != null) receiver.track(sessionId, who);
                    String relay = who.relayState;
                    String next = relay != null && relay.startsWith("/") && !relay.startsWith("//") ? relay : "/";
                    return new Result(303, List.of(
                            new String[] {"location", next},
                            new String[] {"set-cookie", pending("", 0)},
                            new String[] {"set-cookie", "sid=" + sign(sessionId) + "; Path=/; HttpOnly; SameSite=Lax" + secure}), new byte[0]);
                } catch (Exception err) {
                    return text(400, "text/plain", "Sign-in failed.");
                }
            }
            if ("/logout".equals(path) && "POST".equals(method)) {
                if (sid != null) {
                    sessions.remove(sid);
                    if (receiver != null) receiver.untrack(sid);
                }
                URI reply = URI.create(rp.config.replyUrl);
                String origin = reply.getScheme() + "://" + reply.getRawAuthority() + "/";
                return new Result(303, List.of(
                        new String[] {"location", rp.logout(origin)},
                        new String[] {"set-cookie", "sid=; Path=/; HttpOnly; Max-Age=0" + secure}), new byte[0]);
            }
            if ("/FederationMetadata/2007-06/FederationMetadata.xml".equals(path) && "GET".equals(method)) {
                return text(200, "application/samlmetadata+xml", rp.metadata());
            }
            if ("/".equals(path) && "GET".equals(method)) {
                WsFedLogin who = sid == null ? null : sessions.get(sid);
                String page = who == null
                        ? "<p><a href=\"/login\">Sign in with WS-Federation</a></p>"
                        : "<p>Signed in as <strong>" + esc(who.nameId) + "</strong> by " + esc(who.issuer) + ".</p>"
                        + "<form method=\"post\" action=\"/logout\"><button>Sign out</button></form>";
                String html = "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>WS-Federation</title>"
                        + "<link rel=\"stylesheet\" href=\"/styles.css\"></head><body><main>" + page + "</main></body></html>";
                return text(200, "text/html; charset=utf-8", html);
            }
            if ("/styles.css".equals(path) && "GET".equals(method)) {
                try {
                    byte[] css = Files.readAllBytes(Path.of("demo", "public", "styles.css"));
                    return new Result(200, headers(new String[] {"content-type", "text/css"}), css);
                } catch (Exception err) {
                    return text(200, "text/css", "body{font-family:sans-serif}\n");
                }
            }
            return text(404, "text/plain", "Not found");
        }

        private String pending(String value, int age) {
            return "wsfed_pending=" + value + "; Path=" + replyPath + "; HttpOnly; SameSite=None" + (secure.isEmpty() ? "; Secure" : secure) + "; Max-Age=" + age;
        }

        private String sign(String value) {
            return value + "." + mac(value);
        }

        private String unsign(String signed) {
            if (signed == null || !signed.contains(".")) return null;
            String value = signed.substring(0, signed.lastIndexOf('.'));
            if (MessageDigest.isEqual(sign(value).getBytes(StandardCharsets.UTF_8), signed.getBytes(StandardCharsets.UTF_8))) return value;
            return null;
        }

        private String mac(String value) {
            try {
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(new SecretKeySpec(secret, "HmacSHA256"));
                return Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(value.getBytes(StandardCharsets.UTF_8)));
            } catch (Exception err) {
                throw new IllegalStateException(err);
            }
        }
    }

    private Demo() {}

    public static void main(String[] args) throws Exception {
        String[] argv = args == null ? new String[0] : args;
        int port = portOf(argv);
        boolean given = System.getenv("PUBLIC_URL") != null && !System.getenv("PUBLIC_URL").isBlank();
        String publicUrl = given ? System.getenv("PUBLIC_URL").replaceAll("/+$", "") : "";
        for (int i = 0; i < argv.length; i++) {
            if ("--public-url".equals(argv[i])) {
                if (i + 1 >= argv.length || argv[i + 1].isBlank()) throw new IllegalStateException("--public-url is empty");
                publicUrl = argv[i + 1].replaceAll("/+$", "");
                given = true;
            }
        }
        Path configPath = configOf(argv);
        boolean explicit = given;
        String published = publicUrl;
        App[] holder = new App[1];
        HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", port), 0);
        server.setExecutor(Executors.newCachedThreadPool());
        server.createContext("/", exchange -> {
            String path = exchange.getRequestURI().getPath();
            if ("/healthz".equals(path) && "GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                write(exchange, 200, headers(new String[] {"content-type", "text/plain"}), "ok".getBytes(StandardCharsets.UTF_8));
                return;
            }
            try {
                if (holder[0] == null) holder[0] = load(configPath, port, published, explicit);
            } catch (Exception err) {
                write(exchange, 503, headers(new String[] {"content-type", "text/plain"}), ("not ready: " + err.getMessage() + "\n").getBytes(StandardCharsets.UTF_8));
                return;
            }
            byte[] body = exchange.getRequestBody().readAllBytes();
            Map<String, String> headers = new LinkedHashMap<>();
            exchange.getRequestHeaders().forEach((name, values) -> headers.put(name.toLowerCase(), values.isEmpty() ? "" : values.get(0)));
            String target = exchange.getRequestURI().getRawPath();
            if (exchange.getRequestURI().getRawQuery() != null) target += "?" + exchange.getRequestURI().getRawQuery();
            Result result = holder[0].handle(exchange.getRequestMethod(), target, headers, body);
            write(exchange, result.status, result.headers, result.body);
        });
        server.start();
        System.out.println("wsfed-caep demo on port " + port);
    }

    static App load(Path configPath, int port, String publicUrl, boolean given) throws Exception {
        Map<String, Object> raw = Json.object(Json.parse(Files.readString(configPath)));
        Map<String, String> endpoints = endpoints(String.valueOf(raw.getOrDefault("realm", "")), String.valueOf(raw.getOrDefault("replyUrl", "")), publicUrl, given, port);
        Map<String, Object> overrides = new LinkedHashMap<>();
        if (endpoints.get("realm") != null) overrides.put("realm", endpoints.get("realm"));
        if (endpoints.get("replyUrl") != null) overrides.put("replyUrl", endpoints.get("replyUrl"));
        RelyingParty rp = RelyingParty.fromFile(configPath.toString(), overrides);
        App app = new App(rp, null);
        Object ssf = raw.get("ssf");
        if (!Boolean.FALSE.equals(raw.get("signals")) && ssf instanceof Map<?, ?> map && map.get("transmitter") != null && rp.config.privateKey != null) {
            SignalsReceiver.Options options = new SignalsReceiver.Options();
            Object interval = map.get("pollIntervalMs");
            options.pollIntervalMs = interval instanceof Number number ? number.intValue() : 5000;
            SignalsReceiver receiver = new SignalsReceiver(String.valueOf(map.get("transmitter")), (ids, event) -> {
                for (String id : ids) app.sessions.remove(id);
            }, options);
            try {
                receiver.start();
                app.receiver = receiver;
            } catch (Exception err) {
                System.out.println("ssf: not started: " + err.getMessage());
            }
        }
        return app;
    }

    public static Map<String, String> endpoints(String realm, String reply, String publicUrl, boolean given, int port) {
        if (given && publicUrl != null && !publicUrl.isEmpty()) {
            URI base = URI.create(publicUrl.endsWith("/") ? publicUrl : publicUrl + "/");
            return Map.of("realm", move(realm, base), "replyUrl", move(reply, base));
        }
        if (port > 0) return Map.of("realm", onPort(realm, port), "replyUrl", onPort(reply, port));
        return Map.of("realm", realm, "replyUrl", reply);
    }

    private static String move(String value, URI base) {
        URI next = URI.create(value);
        String host = base.getHost() == null ? "" : base.getHost();
        String netloc = host.contains(":") ? "[" + host + "]" : host;
        if (base.getPort() >= 0) netloc += ":" + base.getPort();
        String path = next.getRawPath() == null ? "" : next.getRawPath();
        String query = next.getRawQuery() == null ? "" : "?" + next.getRawQuery();
        String fragment = next.getRawFragment() == null ? "" : "#" + next.getRawFragment();
        return base.getScheme() + "://" + netloc + path + query + fragment;
    }

    public static String onPort(String url, int port) {
        try {
            URI uri = URI.create(url);
            String host = uri.getHost();
            if (host == null || (!"localhost".equals(host) && !"127.0.0.1".equals(host) && !"::1".equals(host))) return url;
            String netloc = host.contains(":") ? "[" + host + "]:" + port : host + ":" + port;
            String path = uri.getRawPath() == null ? "" : uri.getRawPath();
            String query = uri.getRawQuery() == null ? "" : "?" + uri.getRawQuery();
            String fragment = uri.getRawFragment() == null ? "" : "#" + uri.getRawFragment();
            return uri.getScheme() + "://" + netloc + path + query + fragment;
        } catch (Exception err) {
            return url;
        }
    }

    private static int portOf(String[] argv) {
        int port = 3000;
        String env = System.getenv("PORT");
        if (env != null && !env.isBlank()) port = Integer.parseInt(env.trim());
        for (int i = 0; i < argv.length; i++) {
            if ("--port".equals(argv[i]) && i + 1 < argv.length) port = Integer.parseInt(argv[i + 1]);
        }
        return port;
    }

    private static Path configOf(String[] argv) {
        String configured = System.getenv("WSFED_CONFIG");
        for (int i = 0; i < argv.length; i++) {
            if ("--config".equals(argv[i]) && i + 1 < argv.length) configured = argv[i + 1];
        }
        return configured == null || configured.isBlank() ? Path.of("demo", "wsfed.json") : Path.of(configured);
    }

    private static void write(HttpExchange exchange, int status, List<String[]> headers, byte[] body) throws java.io.IOException {
        byte[] payload = body == null ? new byte[0] : body;
        for (String[] header : headers) exchange.getResponseHeaders().add(header[0], header[1]);
        exchange.sendResponseHeaders(status, payload.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(payload);
        }
    }

    private static List<String[]> headers(String[]... pairs) {
        return java.util.Arrays.asList(pairs);
    }

    private static Result text(int status, String type, String body) {
        return new Result(status, headers(new String[] {"content-type", type}), body.getBytes(StandardCharsets.UTF_8));
    }

    private static Map<String, String> cookies(String header) {
        Map<String, String> out = new LinkedHashMap<>();
        if (header == null) return out;
        for (String part : header.split(";")) {
            int eq = part.indexOf('=');
            if (eq <= 0) continue;
            String name = part.substring(0, eq).trim();
            String value = part.substring(eq + 1).trim();
            if (!name.isEmpty() && !value.isEmpty()) out.put(name, value);
        }
        return out;
    }

    private static String esc(String value) {
        return String.valueOf(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    private static byte[] random(int n) {
        byte[] raw = new byte[n];
        new SecureRandom().nextBytes(raw);
        return raw;
    }
}
