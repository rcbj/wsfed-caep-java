// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.wsfed;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import javax.security.auth.x500.X500Principal;

/** wsfed-caep command line: generate-keys and metadata. */
public final class Cli {
    static final String USAGE = """
            Usage:
              wsfed-caep generate-keys --config <wsfed.json> [--cn <name>] [--days <n>] [--bits <n>] [--force]
              wsfed-caep generate-keys --key <file> --cert <file> [--cn <name>] [--days <n>] [--bits <n>] [--force]
                  A new RSA key and a self-signed certificate, written where the configuration's privateKey and
                  certificate point (or to --key and --cert). Refuses to replace existing files without --force.
                  The key decrypts encrypted assertions and can authenticate the Shared Signals receiver (mutual
                  TLS); WS-Federation itself signs nothing. The common name defaults to one naming the realm.

              wsfed-caep metadata --config <wsfed.json> [--out <file>]
                  This relying party's federation metadata, from the configuration (and its certificate, when it
                  has one): give it to the identity provider. Written to --out, or to standard output.""";

    private Cli() {}

    public static void main(String[] args) {
        try {
            int code = run(args, System.out::print);
            if (code != 0) System.exit(code);
        } catch (RuntimeException err) {
            System.err.println(err.getMessage());
            System.exit(1);
        }
    }

    public static int run(String[] argv, java.util.function.Consumer<String> out) {
        Parsed parsed = parse(argv == null ? new String[0] : argv);
        if (parsed.command == null || parsed.args.containsKey("help") || "help".equals(parsed.command)) {
            out.accept(USAGE + "\n");
            return 0;
        }
        if ("generate-keys".equals(parsed.command)) {
            Paths paths = keyPaths(parsed.args);
            boolean force = parsed.args.containsKey("force");
            if (!force && (Files.exists(Path.of(paths.key)) || Files.exists(Path.of(paths.cert)))) {
                String which = Files.exists(Path.of(paths.key)) ? paths.key : paths.cert;
                throw new IllegalStateException(which + " already exists; pass --force to replace the key pair.\n"
                        + "Replacing it means giving the identity provider the new metadata before it next encrypts to this relying party.");
            }
            int days = parsed.args.get("days") == null ? 1095 : Integer.parseInt(parsed.args.get("days"));
            int bits = parsed.args.get("bits") == null ? 3072 : Integer.parseInt(parsed.args.get("bits"));
            if (days <= 0) throw new IllegalStateException("--days must be a positive whole number");
            if (bits != 2048 && bits != 3072 && bits != 4096) throw new IllegalStateException("--bits must be 2048, 3072 or 4096");
            X509Material pair = X509Material.createSelfSignedKeyPair(paths.commonName, days, bits);
            try {
                Files.createDirectories(Path.of(paths.key).getParent());
                Files.createDirectories(Path.of(paths.cert).getParent());
                Files.writeString(Path.of(paths.key), pair.privateKeyPem);
                Files.writeString(Path.of(paths.cert), pair.certificatePem);
                try {
                    Files.setPosixFilePermissions(Path.of(paths.key), Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
                    Files.setPosixFilePermissions(Path.of(paths.cert), Set.of(
                            PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
                            PosixFilePermission.GROUP_READ, PosixFilePermission.OTHERS_READ));
                } catch (UnsupportedOperationException ignored) {
                    // filesystems without POSIX modes keep the written files
                }
            } catch (RuntimeException err) {
                throw err;
            } catch (Exception err) {
                throw new WsFedError("config", "the key pair could not be written: " + err.getMessage(), err);
            }
            out.accept("Wrote the private key  " + paths.key + " (mode 600)\n");
            out.accept("Wrote the certificate  " + paths.cert + "\n");
            out.accept("  subject   " + subject(pair.certificate) + "\n");
            return 0;
        }
        if ("metadata".equals(parsed.command)) {
            String configPath = parsed.args.get("config");
            if (configPath == null) throw new IllegalStateException("metadata needs --config\n\n" + USAGE);
            try {
                Map<String, Object> raw = Json.object(Json.parse(Files.readString(Path.of(configPath))));
                raw.remove("idpCa");
                String xml = new RelyingParty(Config.resolve(raw, Path.of(configPath).toAbsolutePath().getParent().toString()), null, null).metadata();
                String target = parsed.args.get("out");
                if (target != null) {
                    Path path = Path.of(target).toAbsolutePath();
                    Files.createDirectories(path.getParent());
                    Files.writeString(path, xml);
                    out.accept("Wrote the relying party metadata to " + path + "\n");
                } else {
                    out.accept(xml);
                }
            } catch (RuntimeException err) {
                throw err;
            } catch (Exception err) {
                throw new WsFedError("config", configPath + " cannot be read as JSON: " + err.getMessage(), err);
            }
            return 0;
        }
        throw new IllegalStateException("unknown command " + parsed.command + "\n\n" + USAGE);
    }

    static String subject(X509Certificate certificate) {
        return certificate.getSubjectX500Principal().getName(X500Principal.RFC2253);
    }

    private record Parsed(String command, Map<String, String> args) {}
    private record Paths(String key, String cert, String commonName) {}

    private static Parsed parse(String[] argv) {
        if (argv.length == 0) return new Parsed(null, Map.of());
        String command = argv[0];
        Map<String, String> args = new LinkedHashMap<>();
        for (int i = 1; i < argv.length; i++) {
            String item = argv[i];
            if (!item.startsWith("--")) throw new IllegalStateException("unexpected argument " + item + "\n\n" + USAGE);
            String key = item.substring(2);
            if ("force".equals(key) || "help".equals(key)) {
                args.put(key, "true");
            } else {
                if (i + 1 >= argv.length || argv[i + 1].startsWith("--")) {
                    throw new IllegalStateException("--" + key + " needs a value\n\n" + USAGE);
                }
                args.put(key, argv[++i]);
            }
        }
        return new Parsed(command, args);
    }

    private static Paths keyPaths(Map<String, String> args) {
        String configPath = args.get("config");
        String key = args.get("key");
        String cert = args.get("cert");
        String commonName = args.get("cn");
        if (configPath != null) {
            try {
                Map<String, Object> raw = Json.object(Json.parse(Files.readString(Path.of(configPath))));
                Path base = Path.of(configPath).toAbsolutePath().getParent();
                if (key == null && raw.get("privateKey") != null) key = at(raw.get("privateKey"), "privateKey", configPath, base);
                if (cert == null && raw.get("certificate") != null) cert = at(raw.get("certificate"), "certificate", configPath, base);
                if (commonName == null && raw.get("realm") instanceof String realm) {
                    String full = "wsfed-caep-nodejs relying party " + realm;
                    commonName = full.length() <= 64 ? full : full.substring(0, 64);
                }
            } catch (RuntimeException err) {
                throw err;
            } catch (Exception err) {
                throw new WsFedError("config", configPath + " cannot be read as JSON: " + err.getMessage(), err);
            }
        }
        if (key == null || cert == null) throw new IllegalStateException("generate-keys needs --config, or --key and --cert\n\n" + USAGE);
        return new Paths(Path.of(key).toAbsolutePath().toString(), Path.of(cert).toAbsolutePath().toString(),
                commonName == null ? "wsfed-caep-nodejs relying party" : commonName);
    }

    private static String at(Object value, String what, String configPath, Path base) {
        if (!(value instanceof String text) || text.contains("-----BEGIN ")) {
            throw new IllegalStateException(configPath + "'s " + what + " must be a file path for generate-keys to write to");
        }
        if (text.startsWith("file:")) text = text.substring(5);
        Path path = Path.of(text);
        return (path.isAbsolute() ? path : base.resolve(path)).toString();
    }
}
