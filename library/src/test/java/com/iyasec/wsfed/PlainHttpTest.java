// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.wsfed;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.iyasec.wsfed.ssf.SignalsReceiver;
import com.sun.net.httpserver.HttpServer;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

/**
 * Plain http is refused for every fetch (federation metadata, the Shared
 * Signals transmitter) unless the host is loopback, before any connection is
 * opened, and the refusal names only the scheme and host.
 */
class PlainHttpTest {
    private static final String REFUSED = "is refused: plain http is allowed only to a loopback host";

    private static HttpServer server;
    private static final AtomicInteger hits = new AtomicInteger();
    private static String origin;

    @BeforeAll
    static void up() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/md", exchange -> {
            hits.incrementAndGet();
            byte[] body = StubIdp.idpMetadata().getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("content-type", "application/samlmetadata+xml");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.createContext("/away", exchange -> {
            hits.incrementAndGet();
            exchange.getResponseHeaders().set("location", "http://example.com/md");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });
        server.createContext("/ssf", exchange -> {
            hits.incrementAndGet();
            exchange.sendResponseHeaders(404, -1);
            exchange.close();
        });
        server.start();
        origin = "127.0.0.1:" + server.getAddress().getPort();
    }

    @AfterAll
    static void down() {
        if (server != null) server.stop(0);
    }

    @Test
    void refusesPlainHttpMetadataOffLoopback() {
        refused(() -> RelyingParty.create(config("http://example.com/federationmetadata.xml?token=s3cret")), "metadata", "http://example.com");
    }

    @Test
    void refusesAPlainHttpTransmitterOffLoopback() {
        refused(() -> receiver("http://example.com/ssf").start(), "ssf", "http://example.com");
    }

    @Test
    void refusesBeforeConnecting() throws Exception {
        // On Linux http://0.0.0.0:<port> reaches a listener on 127.0.0.1, so
        // an empty backlog on this listener shows no connection was opened.
        try (ServerSocket listener = new ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))) {
            String plain = "http://0.0.0.0:" + listener.getLocalPort();
            refused(() -> RelyingParty.create(config(plain + "/md")), "metadata", plain);
            refused(() -> receiver(plain).start(), "ssf", plain);
            listener.setSoTimeout(300);
            assertThrows(SocketTimeoutException.class, listener::accept, "a refused fetch opened a connection");
        }
    }

    @Test
    void userinfoIsNeverLoopbackAndNeverShown() {
        int before = hits.get();
        WsFedError err = refused(() -> RelyingParty.create(config("http://alice:s3cret@" + origin + "/md")), "metadata", "http://" + origin);
        assertFalse(err.getMessage().contains("alice"), err.getMessage());
        refused(() -> RelyingParty.create(config("http://localhost:80@example.com/md")), "metadata", "http://example.com");
        refused(() -> receiver("http://alice:s3cret@" + origin + "/ssf").start(), "ssf", "http://" + origin);
        assertEquals(before, hits.get());
    }

    @Test
    void refusesWhitespaceAndControlCharacters() {
        int before = hits.get();
        for (String url : new String[] {"http://127.0.0.1 @example.com/md", "http://127.0.0.1\t/md", "http://127.0.0.1\u0000@example.com/md", "https://example.com/m\nd"}) {
            WsFedError err = assertThrows(WsFedError.class, () -> RelyingParty.create(config(url)));
            assertEquals("metadata", err.code);
            assertTrue(err.getMessage().contains("whitespace or a control character"), err.getMessage());
        }
        assertEquals(before, hits.get());
    }

    @Test
    void aRedirectIsNotFollowed() {
        // Redirects are never followed, so a 302 to plain http off loopback
        // is the answer, and example.com is never dialled.
        WsFedError err = assertThrows(WsFedError.class, () -> RelyingParty.create(config("http://" + origin + "/away")));
        assertEquals("metadata", err.code);
        assertTrue(err.getMessage().contains("answered HTTP 302"), err.getMessage());
    }

    @Test
    void plainHttpToLoopbackStillWorks() {
        int port = server.getAddress().getPort();
        for (String host : new String[] {"127.0.0.1", "localhost"}) {
            assertEquals(StubIdp.IDP_ENTITY, RelyingParty.create(config("http://" + host + ":" + port + "/md")).getIdp().entityId);
            int before = hits.get();
            WsFedError err = assertThrows(WsFedError.class, () -> receiver("http://" + host + ":" + port + "/ssf").start());
            assertEquals("ssf", err.code);
            assertFalse(err.getMessage().contains(REFUSED), err.getMessage());
            assertTrue(hits.get() > before, "the transmitter on " + host + " was not reached");
        }
        assertTrue(HttpClient.isLoopbackHost("[::1]"));
        assertTrue(HttpClient.isLoopbackHost("127.200.0.9"));
        assertFalse(HttpClient.isLoopbackHost("127.0.0.1.example.com"));
        assertFalse(HttpClient.isLoopbackHost("0.0.0.0"));
    }

    @Test
    void httpsToAnUnreachableHostIsAConnectionErrorNotThisRefusal() throws Exception {
        int closed;
        try (ServerSocket probe = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            closed = probe.getLocalPort();
        }
        String https = "https://127.0.0.1:" + closed;
        for (Executable fn : new Executable[] {
            () -> RelyingParty.create(config(https + "/md")),
            () -> receiver(https).start(),
        }) {
            WsFedError err = assertThrows(WsFedError.class, fn);
            assertFalse(err.getMessage().contains(REFUSED), err.getMessage());
            assertTrue(err.getMessage().startsWith(https), err.getMessage());
        }
    }

    private static SignalsReceiver receiver(String transmitter) {
        SignalsReceiver.Options options = new SignalsReceiver.Options();
        options.log = new SignalsReceiver.Log() {
            @Override public void info(String message) {}
            @Override public void warn(String message) {}
            @Override public void error(String message) {}
        };
        return new SignalsReceiver(transmitter, (ids, event) -> { }, options);
    }

    private static WsFedError refused(Executable fn, String code, String shown) {
        WsFedError err = assertThrows(WsFedError.class, fn);
        assertEquals(code, err.code, err.getMessage());
        assertTrue(err.getMessage().startsWith(shown + " " + REFUSED), err.getMessage());
        assertFalse(err.getMessage().contains("s3cret"), err.getMessage());
        assertFalse(err.getMessage().contains("/md") || err.getMessage().contains("/ssf") || err.getMessage().contains("federationmetadata"), err.getMessage());
        return err;
    }

    private static Map<String, Object> config(String metadataUrl) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("realm", StubIdp.REALM);
        out.put("replyUrl", StubIdp.REPLY);
        out.put("privateKey", StubIdp.RP_KEY);
        out.put("certificate", StubIdp.RP_CERT);
        out.put("idpMetadata", metadataUrl);
        return out;
    }
}
