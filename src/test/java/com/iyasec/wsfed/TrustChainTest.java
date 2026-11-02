// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.wsfed;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * idpCa: the install script writes the whole listener CA trust chain to the
 * file the parameter names, and the library takes that file as its trust
 * store.
 *
 * keytool makes a four-certificate chain shaped like iya-sts's (leaf, TLS
 * Issuing CA, Intermediate, Root). The stub provider is HTTPS on that chain,
 * publishes it, leaf first, at GET /tls/server-certificate, and answers
 * WS-Federation metadata. A second stub presents a different leaf from the
 * same TLS Issuing CA (iya-sts reissuing its listener certificate), which only
 * a trust store holding every block of the file, not just the first, can
 * trust. A third presents a leaf of its own key, named for the TLS Issuing CA
 * but not signed by it, followed by the real CA certificates: those are
 * public, so their presence in a chain proves nothing, and the library must
 * refuse it. The leaf names IP 127.0.0.1 only, so "localhost" is the wrong
 * host name for the right chain.
 */
class TrustChainTest {
    static final String DEFAULT_IDP_CA = "file:generated/idp-ca.pem";
    static final String IDP_CA_FILE = "generated/idp-ca.pem";
    static final Path ROOT = Path.of(System.getProperty("user.dir"));
    static final Path SHIPPED_CONFIG = ROOT.resolve("demo/wsfed.json");

    static Path work;
    static String published;
    static X509Certificate root;
    static HttpsServer provider;
    static HttpsServer reissued;
    static HttpsServer impostor;
    static String origin;

    @BeforeAll
    static void up() throws Exception {
        work = Files.createTempDirectory("trust-chain-");
        Path store = work.resolve("ca.p12");
        String[] names = {"root", "intermediate", "issuing", "leaf", "leaf2", "impostor", "forged"};
        String[] subjects = {"CN=sts Root CA", "CN=sts Intermediate CA", "CN=sts TLS Issuing CA", "CN=127.0.0.1", "CN=127.0.0.1",
                "CN=sts TLS Issuing CA", "CN=127.0.0.1"};
        for (int i = 0; i < names.length; i++) {
            List<String> args = new ArrayList<>(List.of("-genkeypair", "-alias", names[i], "-keyalg", "EC", "-groupname", "secp256r1",
                    "-dname", subjects[i], "-validity", "2"));
            if (i < 3 || i == 5) args.addAll(List.of("-ext", "bc:c=ca:true"));
            keytool(store, args.toArray(String[]::new));
        }
        String rootPem = pem(keytool(store, "-exportcert", "-rfc", "-alias", "root"));
        String intermediatePem = sign(store, "intermediate", "root", "bc:c=ca:true", "ku:c=keyCertSign,cRLSign");
        String issuingPem = sign(store, "issuing", "intermediate", "bc:c=ca:true", "ku:c=keyCertSign,cRLSign");
        String leafPem = sign(store, "leaf", "issuing", "san=ip:127.0.0.1", "eku=serverAuth");
        String leaf2Pem = sign(store, "leaf2", "issuing", "san=ip:127.0.0.1", "eku=serverAuth");
        String forgedPem = sign(store, "forged", "impostor", "san=ip:127.0.0.1", "eku=serverAuth");
        published = leafPem + issuingPem + intermediatePem + rootPem;
        root = certificates(rootPem).get(0);
        provider = serve(store, "leaf", leafPem + issuingPem + intermediatePem);
        origin = port(provider);
        reissued = serve(store, "leaf2", leaf2Pem + issuingPem + intermediatePem);
        impostor = serve(store, "forged", forgedPem + issuingPem + intermediatePem);
    }

    @AfterAll
    static void down() {
        for (HttpsServer server : new HttpsServer[]{provider, reissued, impostor}) {
            if (server != null) server.stop(0);
        }
    }

    @Test
    void theShippedDemoNamesGeneratedIdpCaPem() throws Exception {
        assertEquals(DEFAULT_IDP_CA, Json.object(Json.parse(Files.readString(SHIPPED_CONFIG))).get("idpCa"));
    }

    @Test
    void theInstallScriptWritesTheWholeChainToIdpCa() throws Exception {
        Path demo = demoDir("install", true);
        String code = String.join("\n",
                "import json, sys",
                "sys.path.insert(0, 'scripts')",
                "import configure_iya_sts, trust_chain",
                "files = configure_iya_sts.files_of(sys.argv[1])",
                "saved = trust_chain.save_trust_chain(sys.argv[2], files['idp_ca'])",
                "print(json.dumps({'idpCa': files['idp_ca'], 'count': saved['count'],",
                "    'anchor': saved['anchor'].subject.rfc4514_string(), 'fingerprint': saved['fingerprint']}))");
        Map<String, Object> saved = Json.object(Json.parse(python("-c", code, demo.resolve("wsfed.json").toString(), origin)));
        Path target = demo.resolve(IDP_CA_FILE);
        assertEquals(target.toRealPath().toString(), saved.get("idpCa"));
        assertEquals(published, Files.readString(target));
        assertEquals(4, ((Number) saved.get("count")).intValue());
        assertEquals("CN=sts Root CA", saved.get("anchor"));
        assertEquals(fingerprint(root), saved.get("fingerprint"));
    }

    @Test
    void theTrustChainScriptWritesIdpCaAndNamesTheAnchor() throws Exception {
        Path demo = demoDir("refresh", true);
        String printed = python("scripts/trust_chain.py", "--config", demo.resolve("wsfed.json").toString(), "--idp", origin);
        Path target = demo.resolve(IDP_CA_FILE);
        assertEquals(published, Files.readString(target));
        assertTrue(printed.contains(target.toRealPath().toString()), printed);
        assertTrue(printed.contains("(4 certificate(s))"), printed);
        assertTrue(printed.contains("CN=sts Root CA"), printed);
        assertTrue(printed.contains("sha256 " + fingerprint(root)), printed);
    }

    @Test
    void withoutThePublishedChainTheHandshakeChainIsSaved() throws Exception {
        String code = String.join("\n",
                "import json, sys",
                "sys.path.insert(0, 'scripts')",
                "import trust_chain",
                "chain = trust_chain.fetch_handshake(sys.argv[1])",
                "print(json.dumps({'pem': chain['pem'], 'count': chain['count']}))");
        Map<String, Object> chain = Json.object(Json.parse(python("-c", code, origin)));
        // The stub's handshake sends leaf, TLS Issuing CA and Intermediate, as a
        // server that leaves the root out does; every block is kept.
        assertEquals(3, ((Number) chain.get("count")).intValue());
        assertEquals(certificates(published).subList(0, 3), certificates((String) chain.get("pem")));
    }

    @Test
    void theLibraryTrustsTheProviderThroughTheSavedFile() throws Exception {
        Path demo = demoDir("library", false);
        // No idpCa file yet: the configuration cannot be read, and the JDK's own
        // trust store does not know this CA either.
        assertThrows(WsFedError.class, () -> RelyingParty.fromFile(demo.resolve("wsfed.json").toString()));
        assertThrows(WsFedError.class, () -> HttpClient.send(origin + "/metadata", "GET", null, null, null, "metadata"));
        Files.createDirectories(demo.resolve("generated"));
        Files.writeString(demo.resolve(IDP_CA_FILE), published);
        RelyingParty party = RelyingParty.fromFile(demo.resolve("wsfed.json").toString());
        assertEquals(published, party.config.idpCa);
        assertEquals(StubIdp.IDP_ENTITY, party.getIdp().entityId);
        // A listener certificate the file does not hold, from the same TLS
        // Issuing CA: trusted through the CA certificates after the first block.
        assertEquals(200, HttpClient.send(port(reissued) + "/metadata", "GET", null, null, tls(), "metadata").status);
    }

    @Test
    void aLeafTheIssuingCaDidNotSignIsRefusedEvenWithTheRealCaCertificatesAfterIt() {
        WsFedError refused = assertThrows(WsFedError.class,
                () -> HttpClient.send(port(impostor) + "/metadata", "GET", null, null, tls(), "metadata"));
        String causes = causes(refused).toLowerCase();
        assertTrue(causes.contains("does not chain with any of the trust anchors")
                || causes.contains("certification path") || causes.contains("signature"), causes);
    }

    @Test
    void theRightChainUnderTheWrongNameIsRefused() {
        assertEquals(200, HttpClient.send(origin + "/metadata", "GET", null, null, tls(), "metadata").status);
        String wrong = "https://localhost:" + provider.getAddress().getPort() + "/metadata";
        WsFedError refused = assertThrows(WsFedError.class, () -> HttpClient.send(wrong, "GET", null, null, tls(), "metadata"));
        String causes = causes(refused);
        assertTrue(causes.contains("No name matching localhost") || causes.toLowerCase().contains("subject alternative"), causes);
    }

    static HttpClient.Tls tls() {
        HttpClient.Tls tls = new HttpClient.Tls();
        tls.ca = published;
        return tls;
    }

    static String port(HttpsServer server) {
        return "https://127.0.0.1:" + server.getAddress().getPort();
    }

    static String causes(Throwable err) {
        StringBuilder out = new StringBuilder();
        for (Throwable at = err; at != null; at = at.getCause()) out.append(at).append(" | ");
        return out.toString();
    }

    /**
     * The shipped wsfed.json. The install script needs it as shipped (file paths
     * it would write; it reads none of them here). The library's copy reads its
     * metadata from the stub provider and has no key pair, which it would read.
     */
    static Path demoDir(String name, boolean asShipped) throws Exception {
        Path demo = work.resolve(name).resolve("demo");
        Files.createDirectories(demo);
        Map<String, Object> raw = Json.object(Json.parse(Files.readString(SHIPPED_CONFIG)));
        if (!asShipped) {
            raw.put("idpMetadata", origin + "/metadata");
            raw.remove("privateKey");
            raw.remove("certificate");
        }
        raw.remove("ssf");
        Files.writeString(demo.resolve("wsfed.json"), Json.stringify(raw));
        return demo;
    }

    static String sign(Path store, String alias, String issuer, String... extensions) throws Exception {
        Path request = work.resolve(alias + ".csr");
        keytool(store, "-certreq", "-alias", alias, "-file", request.toString());
        List<String> args = new ArrayList<>(List.of("-gencert", "-rfc", "-alias", issuer, "-infile", request.toString(), "-validity", "2"));
        for (String extension : extensions) {
            args.add("-ext");
            args.add(extension);
        }
        return pem(keytool(store, args.toArray(String[]::new)));
    }

    /** One certificate as PEM in the form the install script writes it. */
    static String pem(String text) throws Exception {
        byte[] der = certificates(text).get(0).getEncoded();
        return "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der)
                + "\n-----END CERTIFICATE-----\n";
    }

    static String keytool(Path store, String... args) throws Exception {
        List<String> command = new ArrayList<>(List.of(Path.of(System.getProperty("java.home"), "bin", "keytool").toString()));
        command.addAll(List.of(args));
        command.addAll(List.of("-keystore", store.toString(), "-storetype", "PKCS12", "-storepass", "changeit", "-noprompt"));
        return run(command);
    }

    static String python(String... args) throws Exception {
        List<String> command = new ArrayList<>(List.of("python3"));
        command.addAll(List.of(args));
        return run(command);
    }

    static String run(List<String> command) throws Exception {
        Path errors = Files.createTempFile(work, "stderr-", ".txt");
        Process process = new ProcessBuilder(command).directory(ROOT.toFile())
                .redirectError(errors.toFile()).start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertTrue(process.waitFor(60, TimeUnit.SECONDS), command.get(0) + " did not finish");
        assertEquals(0, process.exitValue(), String.join(" ", command) + "\n" + output + Files.readString(errors));
        return output;
    }

    static List<X509Certificate> certificates(String pem) throws Exception {
        List<X509Certificate> out = new ArrayList<>();
        for (Certificate certificate : CertificateFactory.getInstance("X.509")
                .generateCertificates(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)))) {
            out.add((X509Certificate) certificate);
        }
        return out;
    }

    static String fingerprint(X509Certificate certificate) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded());
        return HexFormat.ofDelimiter(":").withUpperCase().formatHex(digest);
    }

    static HttpsServer serve(Path store, String alias, String chainPem) throws Exception {
        KeyStore source = KeyStore.getInstance("PKCS12");
        try (InputStream in = new FileInputStream(store.toFile())) {
            source.load(in, "changeit".toCharArray());
        }
        PrivateKey key = (PrivateKey) source.getKey(alias, "changeit".toCharArray());
        KeyStore served = KeyStore.getInstance("PKCS12");
        served.load(null, null);
        served.setKeyEntry("server", key, new char[0], certificates(chainPem).toArray(Certificate[]::new));
        KeyManagerFactory managers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        managers.init(served, new char[0]);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(managers.getKeyManagers(), null, null);
        HttpsServer server = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(context));
        server.createContext("/", TrustChainTest::handle);
        server.start();
        return server;
    }

    static void handle(HttpExchange exchange) {
        try (exchange) {
            String path = exchange.getRequestURI().getPath();
            byte[] body;
            String type;
            if ("/tls/server-certificate".equals(path)) {
                body = published.getBytes(StandardCharsets.US_ASCII);
                type = "text/plain";
            } else if ("/metadata".equals(path)) {
                body = StubIdp.idpMetadata().getBytes(StandardCharsets.UTF_8);
                type = "application/samlmetadata+xml";
            } else {
                exchange.sendResponseHeaders(404, -1);
                return;
            }
            exchange.getResponseHeaders().set("content-type", type);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
        } catch (Exception err) {
            Caught.warn(err);
        }
    }
}
