<!--
SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
SPDX-License-Identifier: MIT
-->

# wsfed-caep

Server-side WS-Federation relying party for Java 17. It accepts SAML 2.0 bearer assertions, reads identity-provider federation metadata, writes relying-party metadata, verifies XML signatures, decrypts encrypted assertions, and remembers assertion ids so a bearer token cannot be replayed. A Shared Signals poll receiver for CAEP and RISC is included. The relying party does not start that receiver.

Group `com.iyasec`, artifact `wsfed-caep`, version 0.1.1. License: MIT. A pull request merged into `main` publishes the library (`library/` only; the demo never) to Maven Central after the test workflow succeeds on that commit. A direct push does not. `publish.yml` runs `mvn -Prelease -f library/pom.xml deploy` in the Maven container: the `release` profile adds the sources and javadoc jars, a GPG signature on every file, and the Central publishing plugin, which uploads, publishes and waits until the release is live. Maven Central has no trusted publishing, so the job uses four repository secrets: `CENTRAL_TOKEN_USERNAME` and `CENTRAL_TOKEN_PASSWORD` (a Central Portal user token) and `GPG_PRIVATE_KEY` and `GPG_PASSPHRASE` (the release signing key, whose public half is on a public key server). A release on Central is permanent: a version already there is skipped, and the next release is a new version in `VERSION` and the three poms. `-Dcentral.skipPublishing=true` builds and signs everything and uploads nothing. `develop` and `main` are the same commit when this tree is published; nothing here creates a remote.

## Usage

```java
RelyingParty rp = RelyingParty.fromFile("wsfed.json");
RelyingParty.LoginRequest request = rp.login(Map.of("relayState", "/"));
WsFedLogin who = rp.handleReply(Map.of("method", "POST", "url", "/wsfed", "body", body), request.id);
```

Methods are the TypeScript names: `fromFile`, `login`, `handleReply`, `resolveConfig`, `readConfigFile`. JSON keys match the Node configuration: `realm`, `replyUrl`, `idpMetadata`, `privateKey`, `certificate`, `idpCa`, `idpEntityId`, `clockSkewSeconds`, `wantAssertionsEncrypted`, `allowUnsolicited`, `requestTokenType`, `signals`, `ssf`. `file:` and `env:` prefixes are accepted. The default subject attribute is `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier`.

`signals` omitted or `true` is on. The resolved configuration leaves `signals` null in that case. `false` is kept as `Boolean.FALSE`, does not start a receiver, and does not require transmitter metadata. Sign-in is unchanged either way: WS-Federation does not send OAuth scopes. Any other value raises a config error whose message is `signals must be true or false`.

```sh
docker compose build
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/demo:/app/demo" \
  wsfed-caep-java-demo \
  java -cp 'wsfed-caep.jar:dependency/*' \
  com.iyasec.wsfed.Cli generate-keys --config demo/wsfed.json
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/demo:/app/demo" \
  wsfed-caep-java-demo \
  java -cp 'wsfed-caep.jar:dependency/*' \
  com.iyasec.wsfed.Cli metadata --config demo/wsfed.json
```

The generated certificate's common name defaults to `wsfed-caep-nodejs relying party` plus the realm, cut at 64 characters.

## Errors

A caught exception is written to `java.lang.System.Logger` with its stack. The JDK sends that logger to `java.util.logging` unless the application installs a `System.LoggerFinder`. Where this library already threw `WsFedError`, it still throws `WsFedError`, and the caught exception is the cause.

A catch that recovers does not throw. It is still logged. A poll is retried, the next signing key is tried, an HTTP error body is read, sign-out still finishes after a revoke fails, and a Shared Signals handler that throws does not stop acknowledgement of that event. Passing a `WsFedError` through is not logged again: the foreign exception was logged where it was caught.

**Plain http.** Federation metadata from a URL and every Shared Signals transmitter call (configuration, JWKS, stream, poll) use https. A plain `http://` URL is refused before any connection unless its host is loopback (`127.0.0.0/8`, `::1`, `localhost`), because metadata carries the signing keys and Shared Signals carry SETs and the bearer token. Redirects are not followed. A URL with userinfo is never loopback, and a URL holding whitespace or a control character is refused. The `WsFedError` keeps the fetch's code (`metadata`, `ssf`) and its message names the scheme and host only. There is no opt-out. The relying party's own realm and reply URL may stay http: they are never fetched.

## Tests

```sh
docker build --target test .
```

The suite runs in a container. It includes a stub identity provider. It does not need a live iya-sts. XML signatures use Santuario canonicalization and JDK RSA. The Shared Signals JWS uses Nimbus.

`python3 scripts/live_iya_sts.py` is the live half. It starts a fresh iya-sts when `IYA_STS_URL` is unset (or from `IYA_STS_IMAGE`), copies the checkout to a scratch build context without `demo/generated`, builds the demo image, generates the key pair inside it, runs the install script with host `python3` (which writes `idpCa`'s chain), builds the image again so it carries that chain, checks the image holds the chain and no key, and runs the demo with only the key pair and IdP metadata mounted. It then signs in, and requires a credential-change event and a session-revoked event on `GET /live-status`. The second event ends the local session. iya-sts main sets the WS-Federation assertion SessionIndex to the assertion id. The CAEP session-revoked subject names the sign-on session, so the index lookup finds nobody. This demo then ends its one session from the event handler. The script does not bind port 3000, 8081 or 18481-18495 (defaults: `LIVE_STS_PORT=18553`, `LIVE_DEMO_PORT=18653`), passes secrets to docker as `-e NAME` only, logs each sign-in request by a fixed label rather than its URL, and does not run Java or Maven on the host. Key generation runs inside the demo image. The nightly workflow, cron `51 6 * * *` plus a manual run, runs the unit suite and this script.

## Layout

- `library/` the library, `com.iyasec:wsfed-caep`, nothing else in its jar
- `library/src/main/java/com/iyasec/wsfed` library; `.../ssf` poll receiver
- `library/src/test/java` JUnit 5; `library/src/test-fixtures` the stub identity provider and its keys, shared with the demo's tests
- `demo/` the demo module, never published: `demo/src/main/java/com/iyasec/wsfed/demo/Demo.java` JDK HTTP demo
- `scripts/configure_iya_sts.py` registration plan for iya-sts; writes `idpCa`
- `scripts/trust_chain.py` fetches and saves the iya-sts listener CA trust chain
- `Dockerfile`, `docker-compose.yml` (`network_mode: host`, `PORT=3000`)

## Demo

`PORT` defaults to 3000. A loopback realm and reply URL follow that port. Any other host stays as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. The default `http://localhost:3000` is not an explicit public URL. `GET /healthz` returns `200` and the body `ok` even when generated keys are absent. `GET /login` redirects to the identity provider with `wa=wsignin1.0`, `wtrealm`, `wreply`, and `wctx`. The reply URL accepts the sign-in POST and `wsignoutcleanup1.0`. `POST /logout` signs out, including at the identity provider. `GET /live-status` is JSON: `signedIn`, `subject`, `receiver`, and `events` of `type` and `jti`. It records every accepted Shared Signals event and does not include tokens. A session-revoked event that names no indexed session ends this demo's one session, so `signedIn` is false.

Demo JSON uses `file:` paths under `demo/generated/`. Those keys are not in the tree. `"signals"` is omitted, so the receiver is on when a transmitter is configured.


## The iya-sts trust chain (`idpCa`)

`idpCa` (demo default `file:generated/idp-ca.pem`) is the iya-sts TLS listener CA trust chain. `scripts/configure_iya_sts.py` writes it on every run: the whole chain iya-sts publishes at `GET /tls/server-certificate` (leaf, TLS Issuing CA, Intermediate, Root), or the chain from the TLS handshake when that is missing (`scripts/trust_chain.py`). It prints the path, the anchor's subject and its SHA-256. The library makes every certificate in the file a PKIX trust anchor, so a reissued listener certificate from the same CA is trusted; a certificate that merely appears in the presented chain proves nothing, and the host name is checked against the leaf as usual.

The demo image build copies that file in (`COPY demo ./demo`; `.dockerignore` admits only `demo/generated/idp-ca.pem` from `demo/generated`), so a demo image built after the install script trusts that iya-sts with no mount and no fetch. Rebuild the image after running the install script against a different iya-sts. A build with no chain file (a fresh clone, CI) still succeeds. The relying party's key, certificate and the IdP metadata never enter the image: `docker-compose.yml` mounts `demo/generated` at run time.

```sh
PORT=40123 docker compose up --build
```
