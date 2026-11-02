// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.wsfed;

import java.io.InputStream;
import java.net.HttpURLConnection;
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

/** Back channel for metadata and the Shared Signals transmitter. Redirects are not followed. */
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
        try {
            URI uri = URI.create(url);
            if (!"https".equals(uri.getScheme()) && !"http".equals(uri.getScheme())) {
                throw new WsFedError(code, url + " is not an http(s) URL");
            }
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
