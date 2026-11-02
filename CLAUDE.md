<!--
SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
SPDX-License-Identifier: MIT
-->

# wsfed-caep

Java 17 port of the server-side WS-Federation relying party. Group `com.iyasec`, artifact `wsfed-caep`, packages under `com.iyasec.wsfed`. Version 0.1.0. License MIT (`LICENSE`). Publishing to Maven Central is not set up. When this tree is published, `develop` and `main` are the same commit.

## Usage

`RelyingParty.fromFile("wsfed.json")`, then `login` and `handleReply`. JSON keys are the Node keys. Methods are the TypeScript camelCase names: `fromFile`, `login`, `handleReply`, `resolveConfig`, `readConfigFile`.

The party accepts SAML 2.0 assertions with bearer confirmation `urn:oasis:names:tc:SAML:2.0:cm:bearer`. It reads IdP metadata, writes RP metadata, verifies XML signatures (rsa-sha256 is `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`), decrypts encrypted elements, and caches assertion ids. Status success is `urn:oasis:names:tc:SAML:2.0:status:Success`. The default subject attribute is `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier`. `com.iyasec.wsfed.Cli` `generate-keys` writes a self-signed RSA key pair.

## signals

Omitted or `true` means on. The resolved configuration leaves `signals` null in that case. `false` is stored as `Boolean.FALSE`, does not start the receiver, and does not require transmitter metadata. The relying party never starts the receiver itself; `SignalsReceiver` is separate. Sign-in does not change when signals are off, because WS-Federation does not send OAuth scopes. A non-boolean raises a config error: `signals must be true or false`. The shipped demo omits the key.

## Errors

`Caught.error` records a caught exception through `java.lang.System.Logger`, including the stack, and the method then throws the `WsFedError` it already threw. The caught exception is the cause. `Caught.warn` is the same record when the method recovers and does not throw: a later signing key, a poll retry, a false verification, sign-out cleanup, or a handler that must still acknowledge the Security Event Token. A `catch (WsFedError)` that only throws that error again is not logged a second time.

## Tests

```sh
docker build --target test .
```

The `test` stage runs `mvn -B test` in `maven:3.9.9-eclipse-temurin-17`. GitHub Actions uses that command. Do not run Maven on the host. The demo stage packages with `-DskipTests` in its own Maven image.

JUnit 5 covers the stub IdP (a signed SAML assertion the library accepts), replay, metadata, the self-signed certificate, the SSF poll receiver, and the demo handler. The stub tests do not start iya-sts. `python3 scripts/live_iya_sts.py` does, unless `IYA_STS_URL` names one that is already running. It signs the demo in and checks two Shared Signals events on `GET /live-status`. iya-sts main sets the assertion SessionIndex to the assertion id, so a session-revoked subject that names the sign-on session matches nobody. The demo ends its one session from that handler. The nightly workflow, cron `51 6 * * *` plus workflow_dispatch, runs the unit image and that script. It never binds port 3000 or 8081. `scripts/configure_iya_sts.py` is the same registration script as the Python tree; its plan is exercised there. Configure is host Python and does not import this library.

## Layout

`src/main/java/com/iyasec/wsfed` library (`ssf` is the poll receiver). `src/test/java` JUnit. `com.iyasec.wsfed.demo.Demo` is the JDK HTTP server, started with `docker compose up --build`. `scripts/configure_iya_sts.py` registers the demo with iya-sts; the container `PORT` wins over the shell `PORT`. `Dockerfile` and comment-free `docker-compose.yml` use `network_mode: host`, `ENV PORT=3000`, and a health check of `http://127.0.0.1:${PORT}/healthz`.

## Demo

`PORT` defaults to 3000. Loopback realm and reply URLs follow the running port. Other hosts stay as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. `GET /healthz` returns `200` and `ok`. The page links to `/login`, which redirects with `wa=wsignin1.0`, `wtrealm`, `wreply`, and `wctx`. The reply URL handles the POST and sign-out cleanup. `POST /logout` signs out. `GET /live-status` reports `signedIn`, `subject`, the receiver state, and accepted events (`type` and `jti`). It does not include tokens. A session-revoked event whose subject matches no SessionIndex ends this demo's one session. Demo JSON uses `file:` placeholders. Do not commit `demo/generated`.
