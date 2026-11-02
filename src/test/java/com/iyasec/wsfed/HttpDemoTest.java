// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.wsfed;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.iyasec.wsfed.demo.Demo;
import com.sun.net.httpserver.HttpServer;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class HttpDemoTest {
    private HttpServer server;
    private String base;

    @BeforeEach
    void start() throws Exception {
        RelyingParty rp = RelyingParty.create(config(
                "realm", StubIdp.REALM,
                "replyUrl", StubIdp.REPLY,
                "privateKey", StubIdp.RP_KEY,
                "certificate", StubIdp.RP_CERT,
                "idpMetadata", StubIdp.idpMetadata()));
        Demo.App app = new Demo.App(rp);
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setExecutor(Executors.newCachedThreadPool());
        server.createContext("/", exchange -> {
            byte[] body = exchange.getRequestBody().readAllBytes();
            Map<String, String> headers = new LinkedHashMap<>();
            exchange.getRequestHeaders().forEach((name, values) -> headers.put(name.toLowerCase(), values.isEmpty() ? "" : String.join(", ", values)));
            String target = exchange.getRequestURI().getRawPath();
            if (exchange.getRequestURI().getRawQuery() != null) target += "?" + exchange.getRequestURI().getRawQuery();
            Demo.Result result = app.handle(exchange.getRequestMethod(), target, headers, body);
            for (String[] header : result.headers) exchange.getResponseHeaders().add(header[0], header[1]);
            exchange.sendResponseHeaders(result.status, result.body.length);
            exchange.getResponseBody().write(result.body);
            exchange.close();
        });
        server.start();
        base = "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @AfterEach
    void stop() {
        if (server != null) server.stop(0);
    }

    @Test
    void signInCleanupAndLogout() throws Exception {
        HttpURLConnection health = open("GET", "/healthz", null, null);
        assertEquals(200, health.getResponseCode());
        assertEquals("ok", new String(health.getInputStream().readAllBytes(), StandardCharsets.UTF_8));
        HttpURLConnection login = open("GET", "/login", null, null);
        assertEquals(302, login.getResponseCode());
        String location = login.getHeaderField("Location");
        URI uri = URI.create(location);
        assertEquals(StubIdp.PASSIVE, uri.getScheme() + "://" + uri.getRawAuthority() + uri.getRawPath());
        Map<String, String> params = query(uri.getRawQuery());
        assertEquals("wsignin1.0", params.get("wa"));
        String pending = cookie(login, "wsfed_pending");
        String form = "wa=wsignin1.0&wresult=" + URLEncoder.encode(StubIdp.wresult(), StandardCharsets.UTF_8) + "&wctx=" + URLEncoder.encode(params.get("wctx"), StandardCharsets.UTF_8);
        HttpURLConnection reply = open("POST", "/wsfed", form, "wsfed_pending=" + pending);
        assertEquals(303, reply.getResponseCode());
        String sid = cookie(reply, "sid");
        HttpURLConnection home = open("GET", "/", null, "sid=" + sid);
        String page = new String(home.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertTrue(page.contains("Signed in as <strong>alice-1234</strong>"));
        assertTrue(page.contains(StubIdp.IDP_ENTITY));
        HttpURLConnection cleanup = open("GET", "/wsfed?wa=wsignoutcleanup1.0", null, "sid=" + sid);
        assertEquals("image/gif", cleanup.getHeaderField("Content-Type"));
        cleanup.getInputStream().readAllBytes();
        HttpURLConnection signedOut = open("GET", "/", null, "sid=" + sid);
        assertTrue(new String(signedOut.getInputStream().readAllBytes(), StandardCharsets.UTF_8).contains("Sign in with WS-Federation"));
        HttpURLConnection logout = open("POST", "/logout", "", null);
        assertEquals("wsignout1.0", query(URI.create(logout.getHeaderField("Location")).getRawQuery()).get("wa"));
        HttpURLConnection refused = open("POST", "/wsfed", "wa=wsignin1.0&wresult=x&wctx=id%3Dabc", null);
        assertEquals(400, refused.getResponseCode());
    }

    @Test
    void loopbackRealmFollowsPortAndOtherHostsStay() {
        assertEquals("http://localhost:45124/", Demo.onPort("http://localhost:3000/", 45124));
        assertEquals("https://idp.example/wsfed", Demo.onPort("https://idp.example/wsfed", 45124));
        Map<String, String> moved = Demo.endpoints("http://localhost:3000/", "http://localhost:3000/wsfed", "https://app.example", true, 45124);
        assertEquals("https://app.example/", moved.get("realm"));
        assertEquals("https://app.example/wsfed", moved.get("replyUrl"));
    }

    private HttpURLConnection open(String method, String path, String body, String cookie) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) URI.create(base + path).toURL().openConnection();
        conn.setInstanceFollowRedirects(false);
        conn.setRequestMethod(method);
        if (cookie != null) conn.setRequestProperty("cookie", cookie);
        if (body != null) {
            byte[] raw = body.getBytes(StandardCharsets.UTF_8);
            conn.setDoOutput(true);
            conn.getOutputStream().write(raw);
        }
        return conn;
    }

    private static String cookie(HttpURLConnection conn, String name) {
        List<String> all = new java.util.ArrayList<>();
        conn.getHeaderFields().forEach((key, values) -> {
            if (key != null && key.equalsIgnoreCase("set-cookie")) all.addAll(values);
        });
        if (all.isEmpty()) throw new AssertionError("no set-cookie in " + conn.getHeaderFields());
        for (String raw : all) {
            String pair = raw.split(";", 2)[0];
            int eq = pair.indexOf('=');
            if (name.equals(pair.substring(0, eq))) return pair.substring(eq + 1);
        }
        throw new AssertionError("no cookie " + name);
    }

    private static Map<String, String> query(String raw) {
        Map<String, String> out = new LinkedHashMap<>();
        for (String part : raw.split("&")) {
            int eq = part.indexOf('=');
            out.put(java.net.URLDecoder.decode(part.substring(0, eq), StandardCharsets.UTF_8), java.net.URLDecoder.decode(part.substring(eq + 1), StandardCharsets.UTF_8));
        }
        return out;
    }

    private static Map<String, Object> config(String k1, String v1, String k2, String v2, String k3, String v3, String k4, String v4, String k5, String v5) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put(k1, v1);
        out.put(k2, v2);
        out.put(k3, v3);
        out.put(k4, v4);
        out.put(k5, v5);
        return out;
    }
}
