<!--
SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
SPDX-License-Identifier: MIT
-->

# wsfed-caep

Java 17 port of the server-side WS-Federation relying party. Group `com.iyasec`, artifact `wsfed-caep`, packages under `com.iyasec.wsfed`. License MIT (`LICENSE`). A pull request merged into `main` publishes the library (`library/` only; the demo never) to Maven Central after the test workflow succeeds on that commit. A direct push does not. `publish.yml` runs `mvn -Prelease -f library/pom.xml deploy` in the Maven container: the `release` profile adds the sources and javadoc jars, a GPG signature on every file, and the Central publishing plugin, which uploads, publishes and waits until the release is live. Maven Central has no trusted publishing, so the job uses four repository secrets: `CENTRAL_TOKEN_USERNAME` and `CENTRAL_TOKEN_PASSWORD` (a Central Portal user token) and `GPG_PRIVATE_KEY` and `GPG_PASSPHRASE` (the release signing key, whose public half is on a public key server). A release happens when the library's files changed since the last release's tag: `publish.yml` takes one patch above the highest published version, publishes it, and creates the matching tag and GitHub Release. A change to tests, the demo, or the docs releases nothing. To choose a version or start a new minor, raise `VERSION`; the version is stamped in CI and is not committed, so the manifests can trail what is published. `-Dcentral.skipPublishing=true` builds and signs everything and uploads nothing. When this tree is published, `develop` and `main` are the same commit.

## Usage

`RelyingParty.fromFile("wsfed.json")`, then `login` and `handleReply`. JSON keys are the Node keys. Methods are the TypeScript camelCase names: `fromFile`, `login`, `handleReply`, `resolveConfig`, `readConfigFile`.

The party accepts SAML 2.0 assertions with bearer confirmation `urn:oasis:names:tc:SAML:2.0:cm:bearer`. It reads IdP metadata, writes RP metadata, verifies XML signatures (rsa-sha256 is `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`), decrypts encrypted elements, and caches assertion ids. Status success is `urn:oasis:names:tc:SAML:2.0:status:Success`. The default subject attribute is `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier`. `com.iyasec.wsfed.Cli` `generate-keys` writes a self-signed RSA key pair.

## signals

Omitted or `true` means on. The resolved configuration leaves `signals` null in that case. `false` is stored as `Boolean.FALSE`, does not start the receiver, and does not require transmitter metadata. The relying party never starts the receiver itself; `SignalsReceiver` is separate. Sign-in does not change when signals are off, because WS-Federation does not send OAuth scopes. A non-boolean raises a config error: `signals must be true or false`. The shipped demo omits the key.

## Errors

`Caught.error` records a caught exception through `java.lang.System.Logger`, including the stack, and the method then throws the `WsFedError` it already threw. The caught exception is the cause. `Caught.warn` is the same record when the method recovers and does not throw: a later signing key, a poll retry, a false verification, sign-out cleanup, or a handler that must still acknowledge the Security Event Token. A `catch (WsFedError)` that only throws that error again is not logged a second time.

**Plain http (#17).** `HttpClient.send` is the one place every fetch goes through (metadata URL, SSF configuration, JWKS, stream and poll). `refusePlainHttpOffLoopback` refuses plain `http://` to a host that is not loopback (`127.0.0.0/8`, `::1`, `localhost`) before connecting, without resolving a name, naming only the scheme and host[:port]; userinfo is never loopback, and `refuseUnsafeCharacters` refuses whitespace and control characters first. Redirects are not followed (`setInstanceFollowRedirects(false)`), so the checked URL is the only one dialled. No opt-out. `PlainHttpTest` covers it; `http://0.0.0.0:<port>` reaches a 127.0.0.1 listener on Linux, so an empty backlog proves no connection was opened.

## Tests

```sh
docker build --target test .
```

The `test` stage runs `mvn -B test` in `maven:3.9.9-eclipse-temurin-17`. GitHub Actions uses that command. Do not run Maven on the host. The demo stage packages with `-DskipTests` in its own Maven image.

JUnit 5 covers the stub IdP (a signed SAML assertion the library accepts), replay, metadata, the self-signed certificate, the SSF poll receiver, the demo handler, and the trust chain (`TrustChainTest`: the install script's code and `scripts/trust_chain.py` write the four-certificate chain to `idpCa`'s path, the handshake fallback keeps every block, the library trusts the provider and a reissued leaf through that file, and refuses a forged leaf followed by the real CA certificates and the right chain under the wrong host name). The test stage installs python3 and openssl for it. The stub tests do not start iya-sts. `python3 scripts/live_iya_sts.py` does, unless `IYA_STS_URL` names one that is already running. It signs the demo in and checks two Shared Signals events on `GET /live-status`. iya-sts main sets the assertion SessionIndex to the assertion id, so a session-revoked subject that names the sign-on session matches nobody. The demo ends its one session from that handler. The nightly workflow, cron `51 6 * * *` plus workflow_dispatch, runs the unit image and that script. It never binds port 3000, 8081 or 18481-18495; its defaults are 18553 (iya-sts) and 18653 (the demo). It builds the demo the way a user does: install script first (writing the chain), then the image build, then the run with only `rp.key`, `rp.crt` and `idp-metadata.xml` mounted. No CA mount, no `idpCa` rewrite. Secrets go to docker as `-e NAME`; no log line carries a sign-in URL. `scripts/configure_iya_sts.py` is the same registration script as the Python tree; its plan is exercised there. Configure is host Python and does not import this library.

## Layout

Two Maven modules under an aggregator `pom.xml`, which builds both and is never published; keep its version, the library's and the demo's equal to `VERSION`. `library/` is `com.iyasec:wsfed-caep`, the library alone: its `pom.xml` inherits nothing, so it is complete as published, and its jar carries no demo class. `library/src/main/java/com/iyasec/wsfed` library (`ssf` is the poll receiver). `library/src/test/java` JUnit. `library/src/test-fixtures` holds `StubIdp` and its key files, which both modules' tests compile (build-helper) and no published jar carries. `demo/` is `com.iyasec:wsfed-caep-demo`, never published: `HttpDemoTest` and `TrustChainTest` (run from the repository root) are its tests, and its jar and `target/dependency` (the library among them) are what the image runs as `wsfed-caep.jar:dependency/*`. `com.iyasec.wsfed.demo.Demo` is the JDK HTTP server, started with `docker compose up --build`. `scripts/configure_iya_sts.py` registers the demo with iya-sts; the container `PORT` wins over the shell `PORT`. `Dockerfile` and comment-free `docker-compose.yml` use `network_mode: host`, `ENV PORT=3000`, and a health check of `http://127.0.0.1:${PORT}/healthz`.

## Demo

`PORT` defaults to 3000. Loopback realm and reply URLs follow the running port. Other hosts stay as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. `GET /healthz` returns `200` and `ok`. The page links to `/login`, which redirects with `wa=wsignin1.0`, `wtrealm`, `wreply`, and `wctx`. The reply URL handles the POST and sign-out cleanup. `POST /logout` signs out. `GET /live-status` reports `signedIn`, `subject`, the receiver state, and accepted events (`type` and `jti`). It does not include tokens. A session-revoked event whose subject matches no SessionIndex ends this demo's one session. Demo JSON uses `file:` placeholders. Do not commit `demo/generated`.

`idpCa` (`file:generated/idp-ca.pem`) is the iya-sts TLS listener CA trust chain. `scripts/configure_iya_sts.py` writes the whole chain there on every run through `scripts/trust_chain.py` (`GET /tls/server-certificate`, falling back to the handshake). `HttpClient` makes every block a PKIX trust anchor; the host name is still verified. The demo image bakes the file in (`COPY demo ./demo` after the compile; `.dockerignore` admits only that file of `demo/generated`, so keys and metadata never enter an image, and a build without it succeeds). Rebuild the image after re-running the install script against a different iya-sts. A generated test-user password goes to `demo/generated/<user>.password` (mode 0600), never to the output.
