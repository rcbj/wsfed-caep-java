<!--
SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
SPDX-License-Identifier: MIT
-->

# wsfed-caep

Server-side WS-Federation relying party for Java 17. It accepts SAML 2.0 bearer assertions, reads identity-provider federation metadata, writes relying-party metadata, verifies XML signatures, decrypts encrypted assertions, and remembers assertion ids so a bearer token cannot be replayed. A Shared Signals poll receiver for CAEP and RISC is included. The relying party does not start that receiver.

Group `com.iyasec`, artifact `wsfed-caep`, version 0.1.0. License: MIT. Publishing to Maven Central is not set up. `develop` and `main` are the same commit when this tree is published; nothing here creates a remote.

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

## Tests

```sh
docker build --target test .
```

The suite runs in a container. It includes a stub identity provider. It does not need a live iya-sts. XML signatures use Santuario canonicalization and JDK RSA. The Shared Signals JWS uses Nimbus.

`python3 scripts/live_iya_sts.py` is the live half. It builds this demo image, starts a fresh iya-sts when `IYA_STS_URL` is unset, registers the demo with host `python3`, signs in, and requires a credential-change event and a session-revoked event on `GET /live-status`. The second event ends the local session. iya-sts main sets the WS-Federation assertion SessionIndex to the assertion id. The CAEP session-revoked subject names the sign-on session, so the index lookup finds nobody. This demo then ends its one session from the event handler. The script does not bind port 3000 or 8081, and it does not run Java or Maven on the host. Key generation runs inside the demo image. The nightly workflow, cron `51 6 * * *` plus a manual run, runs the unit suite and this script.

## Layout

- `src/main/java/com/iyasec/wsfed` library
- `src/main/java/com/iyasec/wsfed/ssf` poll receiver
- `src/test/java` JUnit 5, fixtures, stub identity provider
- `src/main/java/com/iyasec/wsfed/demo/Demo.java` JDK HTTP demo
- `scripts/configure_iya_sts.py` registration plan for iya-sts
- `Dockerfile`, `docker-compose.yml` (`network_mode: host`, `PORT=3000`)

## Demo

`PORT` defaults to 3000. A loopback realm and reply URL follow that port. Any other host stays as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. The default `http://localhost:3000` is not an explicit public URL. `GET /healthz` returns `200` and the body `ok` even when generated keys are absent. `GET /login` redirects to the identity provider with `wa=wsignin1.0`, `wtrealm`, `wreply`, and `wctx`. The reply URL accepts the sign-in POST and `wsignoutcleanup1.0`. `POST /logout` signs out, including at the identity provider. `GET /live-status` is JSON: `signedIn`, `subject`, `receiver`, and `events` of `type` and `jti`. It records every accepted Shared Signals event and does not include tokens. A session-revoked event that names no indexed session ends this demo's one session, so `signedIn` is false.

Demo JSON uses `file:` paths under `demo/generated/`. Those keys are not in the tree. `"signals"` is omitted, so the receiver is on when a transmitter is configured.

```sh
PORT=40123 docker compose up --build
```
