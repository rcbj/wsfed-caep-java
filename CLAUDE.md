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

## Tests

```sh
mvn -B test
```

JUnit 5 covers the stub IdP (a signed SAML assertion the library accepts), replay, metadata, the self-signed certificate, the SSF poll receiver, and the demo handler. No live iya-sts. `scripts/configure_iya_sts.py` is the same registration script as the Python tree; its plan is exercised there.

## Layout

`src/main/java/com/iyasec/wsfed` library (`ssf` is the poll receiver). `src/test/java` JUnit. `com.iyasec.wsfed.demo.Demo` is the JDK HTTP server, started with `mvn exec:java`. `scripts/configure_iya_sts.py` registers the demo with iya-sts; the container `PORT` wins over the shell `PORT`. `Dockerfile` and comment-free `docker-compose.yml` use `network_mode: host`, `ENV PORT=3000`, and a health check of `http://127.0.0.1:${PORT}/healthz`.

## Demo

`PORT` defaults to 3000. Loopback realm and reply URLs follow the running port. Other hosts stay as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. `GET /healthz` returns `200` and `ok`. The page links to `/login`, which redirects with `wa=wsignin1.0`, `wtrealm`, `wreply`, and `wctx`. The reply URL handles the POST and sign-out cleanup. `POST /logout` signs out. Demo JSON uses `file:` placeholders. Do not commit `demo/generated`.
