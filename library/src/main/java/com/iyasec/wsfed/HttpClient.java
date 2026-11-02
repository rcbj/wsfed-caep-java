// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.wsfed;

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Collection;
import java.util.Map;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/**
 * Back channel for metadata and the Shared Signals transmitter. Redirects are
 * not followed, so the URL checked here is the only one ever dialled.
 */
public final class HttpClient {
    public static final int MAX_BYTES = 2 * 1024 * 1024;
    public static final int TIMEOUT_MS = 15_000;

    public static final class Tls {
        public String ca;
        public String cert;
        public String key;
    }

    public static final class Response {
        public final int status;
        public final String contentType;
        public final String body;

        public Response(int status, String contentType, String body) {
            this.status = status;
            this.contentType = contentType;
            this.body = body;
        }
    }

    private HttpClient() {}

    public static Response send(String url, String method, Map<String, String> headers, String body, Tls tls, String code) {
        // Every fetch this library makes comes through here: the identity
        // provider's federation metadata (its signing keys) and the Shared
        // Signals transmitter (configuration, JWKS, stream and poll: the SETs
        // and the bearer token). None of them may travel in the clear off this
        // machine, so plain http is refused before any DNS lookup or
        // connection unless the host is loopback.
        refuseUnsafeCharacters(url, code);
        try {
            URI uri = URI.create(url);
            if (!"https".equals(uri.getScheme()) && !"http".equals(uri.getScheme())) {
                throw new WsFedError(code, url + " is not an http(s) URL");
            }
            refusePlainHttpOffLoopback(uri, code);
            HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
            if (conn instanceof HttpsURLConnection https && tls != null && (tls.ca != null || tls.cert != null)) {
                https.setSSLSocketFactory(context(tls).getSocketFactory());
            }
            conn.setInstanceFollowRedirects(false);
            conn.setConnectTimeout(TIMEOUT_MS);
            conn.setReadTimeout(TIMEOUT_MS);
            conn.setRequestMethod(method == null ? "GET" : method);
            if (headers != null) {
                for (Map.Entry<String, String> entry : headers.entrySet()) conn.setRequestProperty(entry.getKey(), entry.getValue());
            }
            if (body != null) {
                byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
                conn.setDoOutput(true);
                conn.setFixedLengthStreamingMode(bytes.length);
                conn.getOutputStream().write(bytes);
            }
            int status = conn.getResponseCode();
            String type = conn.getContentType() == null ? "" : conn.getContentType();
            InputStream in = status >= 400 ? conn.getErrorStream() : conn.getInputStream();
            byte[] raw = read(in, url, code);
            return new Response(status, type, new String(raw, StandardCharsets.UTF_8));
        } catch (WsFedError err) {
            throw err;
        } catch (java.net.SocketTimeoutException err) {
            Caught.error(err);
            throw new WsFedError(code, url + " did not answer within " + (TIMEOUT_MS / 1000) + " s", err);
        } catch (Exception err) {
            Caught.error(err);
            throw new WsFedError(code, url + ": " + err.getMessage(), err);
        }
    }

    /**
     * Refuses a URL holding whitespace or a control character before it is
     * parsed, rather than risk two parsers disagreeing on its host. The URL
     * itself is not repeated: it may carry a secret.
     */
    static void refuseUnsafeCharacters(String url, String code) {
        if (url == null) throw new WsFedError(code, "no URL was given");
        for (int i = 0; i < url.length(); i++) {
            char c = url.charAt(i);
            if (c <= 0x20 || c == 0x7f || Character.isWhitespace(c) || Character.isISOControl(c)) {
                throw new WsFedError(code, "the URL is refused: it contains whitespace or a control character");
            }
        }
    }

    /**
     * Throws unless a plain http URI names a loopback host: 127.0.0.0/8, ::1
     * or the name localhost, where the bytes never leave the machine. A URI
     * with userinfo is never loopback, so "http://localhost:80@host/" cannot
     * pass as localhost. Nothing here resolves a name. The message names the
     * scheme and host[:port] only: never userinfo, path, query or a secret.
     */
    static void refusePlainHttpOffLoopback(URI uri, String code) {
        if (!"http".equalsIgnoreCase(uri.getScheme())) return;
        String host = uri.getHost();
        if (uri.getRawUserInfo() == null && host != null && isLoopbackHost(host)) return;
        String shown = host == null ? "(no host)" : host + (uri.getPort() == -1 ? "" : ":" + uri.getPort());
        throw new WsFedError(code, "http://" + shown + " is refused: plain http is allowed only to a loopback host (127.0.0.0/8, ::1, localhost); use https");
    }

    static boolean isLoopbackHost(String host) {
        if ("localhost".equalsIgnoreCase(host)) return true;
        if (host.matches("127\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}")) {
            for (String part : host.split("\\.")) {
                if (Integer.parseInt(part) > 255) return false;
            }
            return true;
        }
        if (host.startsWith("[") && host.endsWith("]")) {
            String literal = host.substring(1, host.length() - 1);
            if (!literal.matches("[0-9A-Fa-f:.]+")) return false;
            try {
                // A bracketed IPv6 literal: parsed, never looked up.
                InetAddress address = InetAddress.getByName(literal);
                return address instanceof Inet6Address && address.isLoopbackAddress();
            } catch (Exception err) {
                Caught.warn(err);
                return false;
            }
        }
        return false;
    }

    private static byte[] read(InputStream in, String url, String code) throws Exception {
        if (in == null) return new byte[0];
        try (InputStream stream = in) {
            byte[] out = new byte[0];
            byte[] buf = new byte[65536];
            int n;
            while ((n = stream.read(buf)) >= 0) {
                if (out.length + n > MAX_BYTES) throw new WsFedError(code, url + " answered more than " + MAX_BYTES + " bytes");
                byte[] next = new byte[out.length + n];
                System.arraycopy(out, 0, next, 0, out.length);
                System.arraycopy(buf, 0, next, out.length, n);
                out = next;
            }
            return out;
        }
    }

    private static SSLContext context(Tls tls) throws Exception {
        TrustManagerFactory trust = null;
        if (tls.ca != null && !tls.ca.isBlank()) {
            KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
            store.load(null, null);
            Collection<? extends Certificate> certs = CertificateFactory.getInstance("X.509")
                    .generateCertificates(new java.io.ByteArrayInputStream(tls.ca.getBytes(StandardCharsets.US_ASCII)));
            int i = 0;
            for (Certificate cert : certs) store.setCertificateEntry("ca" + (i++), cert);
            trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trust.init(store);
        }
        KeyManagerFactory keys = null;
        if (tls.cert != null && tls.key != null) {
            KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(null, null);
            char[] password = new char[0];
            store.setKeyEntry("client", Config.privateKey(tls.key), password, new Certificate[] {Config.certificate(tls.cert)});
            keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keys.init(store, password);
        }
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(keys == null ? null : keys.getKeyManagers(), trust == null ? null : trust.getTrustManagers(), new SecureRandom());
        return context;
    }
}
