<!--
SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
SPDX-License-Identifier: MIT
-->

# wsfed-caep

Server-side WS-Federation relying party for Java 17. It accepts SAML 2.0 bearer assertions, reads identity-provider federation metadata, writes relying-party metadata, verifies XML signatures, decrypts encrypted assertions, and remembers assertion ids so a bearer token cannot be replayed. A Shared Signals poll receiver for CAEP and RISC is included. The relying party does not start that receiver.

Group `com.iyasec`, artifact `wsfed-caep`. License: MIT. A pull request merged into `main` publishes the library (`library/` only; the demo never) to Maven Central after the test workflow succeeds on that commit. A direct push does not. `publish.yml` runs `mvn -Prelease -f library/pom.xml deploy` in the Maven container: the `release` profile adds the sources and javadoc jars, a GPG signature on every file, and the Central publishing plugin, which uploads, publishes and waits until the release is live. Maven Central has no trusted publishing, so the job uses four repository secrets: `CENTRAL_TOKEN_USERNAME` and `CENTRAL_TOKEN_PASSWORD` (a Central Portal user token) and `GPG_PRIVATE_KEY` and `GPG_PASSPHRASE` (the release signing key, whose public half is on a public key server). A release happens when the library's files changed since the last release's tag: `publish.yml` takes one patch above the highest published version, publishes it, and creates the matching tag and GitHub Release. A change to tests, the demo, or the docs releases nothing. To choose a version or start a new minor, raise `VERSION`; the version is stamped in CI and is not committed, so the manifests can trail what is published. `-Dcentral.skipPublishing=true` builds and signs everything and uploads nothing. The embedded PEP depends on `com.iyasec:iya-pep`, which is not on Maven Central yet. This work stays on `develop` until that artifact's first release, because a merge to `main` publishes this library.

## Usage

```java
RelyingParty rp = RelyingParty.fromFile("wsfed.json");
RelyingParty.LoginRequest request = rp.login(Map.of("relayState", "/"));
WsFedLogin who = rp.handleReply(Map.of("method", "POST", "url", "/wsfed", "body", body), request.id);
```

Methods are the TypeScript names: `fromFile`, `login`, `handleReply`, `resolveConfig`, `readConfigFile`. JSON keys match the Node configuration: `realm`, `replyUrl`, `idpMetadata`, `privateKey`, `certificate`, `idpCa`, `idpEntityId`, `clockSkewSeconds`, `wantAssertionsEncrypted`, `allowUnsolicited`, `requestTokenType`, `signals`, `ssf`, `pep`. `file:` and `env:` prefixes are accepted. The default subject attribute is `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier`.

`signals` omitted or `true` is on. The resolved configuration leaves `signals` null in that case. `false` is kept as `Boolean.FALSE`, does not start a receiver, and does not require transmitter metadata. Sign-in is unchanged either way: WS-Federation does not send OAuth scopes. Any other value raises a config error whose message is `signals must be true or false`.

**Subjects (SSF 1.0 §8.1.3.2–8.1.3.3).** A subscribing application should receive CAEP and RISC events only about people signed in to it. `SignalsReceiver.track` calls the transmitter's `add_subject_endpoint` with `{stream_id, subject, verified: true}`. `untrack`, and a session ended by a received event, call `remove_subject_endpoint` only when no other local session for that person remains. The subject is `iss_sub` (the transmitter's issuer and the session person, which is `nameidentifier`) when the person is known, else `email`. Each call is made once, inline, and never fails the sign-in. A 403 is logged at warn. `ssf.addSubjects` defaults to true; anything but a boolean leaves the demo's receiver off with `ssf.addSubjects must be true or false`. A receiver given an embedded PEP that wants events also adds the application, `{format: opaque, id: <application>}`, when it starts, and never removes it. Without that, the first sign-in would cut the PEP off from `pep-policies-changed`.

**The receiver's TLS client identity (`ssf.clientCertificate`, `ssf.clientKey`).** The receiver authenticates its stream calls by mutual TLS. Give both or neither: `"clientCertificate": "file:generated/ssf-client.crt"` (leaf first, then the chain) and `"clientKey": "file:generated/ssf-client.key"` (PKCS#8, PKCS#1 or SEC1 PEM; RSA or EC). A relative path is taken from the configuration's directory. A pair that is not a TLS client identity is refused when the configuration is read. Without them the receiver presents the relying party's own `certificate` and `privateKey` (`Resolved.ssfTlsClient()`). The install script has the realm issue the application that certificate, so the Shared Signals identity stays separate from the WS-Federation key pair.

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

## Embedded PEP

Ask iya-sts's authorization policy whether a signed-in person may act on a resource, through the embedded Remote PEP (the shared [`iya-pep`](https://github.com/rcbj/iya-pep-java) library; iya-sts [#1206](https://github.com/rcbj/iya-sts/issues/1206)). **[docs/remote-pep.md](docs/remote-pep.md) is the full guide**: setting up iya-sts, choosing `central` or `local`, every configuration member, obligations, policy-change events, operating it and troubleshooting.

The library always includes the PEP. There is no feature flag. `com.iyasec:iya-pep:0.1.0` is a dependency of `library/pom.xml`. Until that artifact is on Maven Central, the Docker `test` and `build` stages clone `iya-pep-java` branch `develop` and install it. This library stays on `develop` until then. Bytecode is 17. The runtime image is Temurin 25. The test image is `maven:3.9-eclipse-temurin-26`.

```json
"pep": { "name": "pep-orders", "mode": "local", "assertionKey": "pep-key.pem" }
```

```java
Decision decision = party.decideSession(receiver, sessionId, login, Access.of("read", "order", "42"));
int status = decision.httpStatus(); // 200 for a Permit, 403 for anything else
```

The section is off unless present. A section without `mode` is `local`. `pdpUrl` defaults to the identity provider's entityID (the realm issuer, `/realm/<id>` included). `application` defaults to `realm`. `signals` is the library's. `tlsCa` is `idpCa`. The PEP's key must be its own: `RelyingParty` refuses `pep.assertionKey` equal to `privateKey`, and `SignalsReceiver` refuses it equal to the receiver's TLS client key, both by JWK thumbprint. Only the claims the realm's AuthZEN catalogue declares are sent. The subject id is the `name` claim, else the NameID. `nameidentifier` is the opaque sub and is never the id. Every PEP failure (no policy yet, iya-sts unreachable, an engine fault) is Unavailable, and `httpStatus()` answers 403 like a Deny. `decide` does not throw. A `SignalsReceiver` given the PEP asks its stream for `pep-policies-changed`, adds the application as an opaque subject that is never removed, and tells the PEP whether the stream is `requested`, `excluded` or `down`. The demo protects `/orders/{id}` and `/attribute-protected` and answers each with the decision's `httpStatus()` after its own 401 for no sign-in.

## Errors

A caught exception is written to `java.lang.System.Logger` with its stack. The JDK sends that logger to `java.util.logging` unless the application installs a `System.LoggerFinder`. Where this library already threw `WsFedError`, it still throws `WsFedError`, and the caught exception is the cause.

A catch that recovers does not throw. It is still logged. A poll is retried, the next signing key is tried, an HTTP error body is read, sign-out still finishes after a revoke fails, and a Shared Signals handler that throws does not stop acknowledgement of that event. Passing a `WsFedError` through is not logged again: the foreign exception was logged where it was caught.

**Plain http.** Federation metadata from a URL and every Shared Signals transmitter call (configuration, JWKS, stream, poll) use https. A plain `http://` URL is refused before any connection unless its host is loopback (`127.0.0.0/8`, `::1`, `localhost`), because metadata carries the signing keys and Shared Signals carry SETs and the bearer token. Redirects are not followed. A URL with userinfo is never loopback, and a URL holding whitespace or a control character is refused. The `WsFedError` keeps the fetch's code (`metadata`, `ssf`) and its message names the scheme and host only. There is no opt-out. The relying party's own realm and reply URL may stay http: they are never fetched.

## Tests

```sh
docker build --target test .
```

The suite runs in a container. It includes a stub identity provider. It does not need a live iya-sts. XML signatures use Santuario canonicalization and JDK RSA. The Shared Signals JWS uses Nimbus.

`python3 scripts/live_iya_sts.py` is the live half. It starts a fresh iya-sts when `IYA_STS_URL` is unset (or from `IYA_STS_IMAGE`), copies the checkout to a scratch build context without `demo/generated`, builds the demo image, generates the key pair inside it, runs the install script with host `python3` (which writes `idpCa`'s chain), builds the image again so it carries that chain, checks the image's `demo/generated` holds only `idp-ca.pem`, and runs the demo with the key pair and IdP metadata mounted file by file, plus `ssf-client.key` and `ssf-client.crt` when the install script wrote them. `--pep` (or `LIVE_PEP=1`) also mounts `pep-key.pem`, runs central and then local (`WSFED_CONFIG=demo/wsfed.pep-local.json`), and puts `pep.central` and `pep.local` in the result. It needs an iya-sts image with #2026–#2028. The script then signs in, and requires a credential-change event and a session-revoked event on `GET /live-status`. The second event ends the local session. iya-sts main sets the WS-Federation assertion SessionIndex to the assertion id. The CAEP session-revoked subject names the sign-on session, so the index lookup finds nobody. This demo then ends its one session from the event handler. The script does not bind port 3000, 8081 or 18481-18495 (defaults: `LIVE_STS_PORT=18553`, `LIVE_DEMO_PORT=18653`), passes secrets to docker as `-e NAME` only, logs each sign-in request by a fixed label rather than its URL, and does not run Java or Maven on the host. Key generation runs inside the demo image. The nightly workflow, cron `51 6 * * *` plus a manual run, runs the unit suite and this script.

## Demo with its embedded PEP

**Shared Signals identity.** With an `ssf` block and signals on, the install script lets the application manage its own stream (`oauthAllowedScope` `ssf.manage`, a member of `SSF_MANAGE`). It then has the realm issue the application a TLS client certificate (`POST /admin-api/applications/issue-tls-client-certificate`, `keyAlg` `ec-p256`). The key goes to `demo/generated/ssf-client.key` (mode 0600, decrypted with the host's `openssl`, never printed). The leaf and chain go to `demo/generated/ssf-client.crt`, and the script names both in `ssf.clientKey` and `ssf.clientCertificate`. A re-run keeps a certificate the application still holds. Earlier versions pinned the relying party's self-signed certificate (`tls/trust/add` and `applications/add-certificate`). Once the new certificate is in place, the script removes both by that certificate's SHA-256. A missing anchor, or a 403, does not stop the run. `.dockerignore` keeps the key and certificate out of the image. Compose mounts `demo/generated` read-only.

One command registers the demo and sets up its PEP:

```sh
ADMIN_API_CLIENT_SECRET=... python3 scripts/configure_iya_sts.py --idp https://localhost:8443 --pep central
```

A bare `--pep` is `local`. It needs an iya-sts with embedded-PEP support (iya-sts #2026–#2028) and the host's `openssl`. Beside the registration it creates the PEP's service account (`pep-wsfed-demo`, or `--pep-name`) in `remote-peps`, makes its P-256 key in `demo/generated/pep-key.pem` (0600, never printed, never in the image), certifies it bound to the demo's application, adds the catalogue row `subject.acr` → `urn:example:acr`, gives the application its own enforced policy (read on an order needs an `acr`; read on `attribute-protected` needs the directory attribute `attr1=abc123`; anything else is denied; the realm root is never touched), and writes the `pep` section into `demo/wsfed.json` with `assertionKey` left as `file:generated/pep-key.pem`. Run it again with `--pep local` to switch modes: the account and key are kept, and so is the policy unless it is this script's own (`urn:example:wsfeddemo-orders`), which is brought up to date. The application display name stays `wsfed-caep-nodejs demo`. [docs/remote-pep.md](docs/remote-pep.md#the-demo) has the details.

**`GET /attribute-protected`** is decided on a directory attribute rather than a claim: the policy permits `read` on `attribute-protected` when the person's `attr1` is `abc123`, and the PEP asks iya-sts's PIP for it. Defining `attr1` uses a second token, `admin:read admin:security`, and only when `--pep` is set, so a nightly run against an older iya-sts does not call that path. The page is 401 when signed out, 200 with the heading Allowed on a Permit, 403 with Not allowed on a Deny, and 403 with No decision when the PEP could not decide. `GET /orders/{id}` is `read` (a Permit may say Order) and any other method is `write`.

## Credentials

Every credential the library, the demo and its scripts use: what it is, where it lives, and how it is replaced. Paths are relative to `demo/`. No script prints a key, a password or a secret: only paths.

### The application's own credentials

These are the relying party's own credentials, for its WS-Federation registration and sign-in and for its Shared Signals stream.

| Credential | What it is | Made or issued by | Where it lives | Used for | How iya-sts learns of it | Rotation |
|---|---|---|---|---|---|---|
| WS-Federation key pair | An RSA key and a self-signed certificate. The common name defaults to `wsfed-caep-nodejs relying party` plus the realm, cut at 64 characters. | `com.iyasec.wsfed.Cli generate-keys`, run inside the demo image. The install script tells you that command when neither file exists. It does not run Java on the host. | `privateKey` → `generated/rp.key` and `certificate` → `generated/rp.crt`. | Decrypting encrypted assertions. It is also the receiver's TLS client identity when the configuration names no `ssf.clientCertificate`. | The registration is the realm and the reply URL. The install script writes `generated/rp-metadata.xml` and does not upload it. Earlier versions pinned this certificate for Shared Signals; the current one removes that. | Run `generate-keys` again inside the image, then the install script, then restart the demo. |
| Shared Signals client certificate | An EC P-256 key and a TLS client certificate (`clientAuth`, subjectAltName `urn:sts:application:<realm>`), with its chain. | iya-sts's realm tls-client Issuing CA, through `POST /admin-api/applications/issue-tls-client-certificate` (`keyAlg` `ec-p256`), called by the install script whenever signals are on. The one-time encrypted key is decrypted with the host's `openssl`. The password is passed as `WSFED_SSF_CLIENT_KEY_PASSWORD` and is never printed. | `ssf.clientKey` → `generated/ssf-client.key` (0600) and `ssf.clientCertificate` → `generated/ssf-client.crt` (leaf, then chain). | Mutual TLS on every call the receiver makes to `/ssf/*`. | iya-sts issued it, and the application's record lists it. | Revoke it, or delete the two files, then run the install script again and restart the demo. A re-run keeps a certificate the application still holds. |
| Fallback: the WS-Federation key pair at `/ssf/*` | The row above's key pair, presented when `ssf.clientCertificate` and `ssf.clientKey` are absent. | (as above) | (as above) | Mutual TLS at `/ssf/*`. | Only if an administrator trusts that self-signed certificate. The install script no longer sets this up. | (as above) |
| Test user's password | The password of `wsfed-demo-user` (`--test-user`). | `WSFED_DEMO_USER_PASSWORD` when set; otherwise iya-sts generates one when the install script creates the user. | `generated/wsfed-demo-user.password` (0600), written only when iya-sts generated it. Only the path is printed. | Signing in at iya-sts's sign-in page. | It is iya-sts's directory entry. | Set `WSFED_DEMO_USER_PASSWORD` and run the install script again, or change it on the console. |
| Session cookie key | 32 random bytes per demo process, used for HMAC. | The demo. | Memory only. | Signing the `sid` and `wsfed_pending` cookies. | It doesn't. | Every restart. |

The live script makes its own users and passwords for each run and keeps them in memory. They reach containers as `-e NAME`.

### The embedded PEP's credentials

The PEP is a separate client of iya-sts with an identity of its own; [docs/remote-pep.md](docs/remote-pep.md#credentials) has the details.

| Credential | What it is | Made or issued by | Where it lives | Used for | Rotation |
|---|---|---|---|---|---|
| The PEP's service account | `pep-wsfed-demo` (`--pep-name`): a service account with no password (`credential: none`), owned by `admin-write`, and a member of `remote-peps`. | The install script (`--pep`), only when `GET /users?user=` says it doesn't exist. | iya-sts's directory; the `pep` section's `name`. | Being the PEP: the bound application, registration and audit name it. | Kept on every run. |
| The PEP's key | An EC P-256 key. | Made on the host with `openssl genpkey`. Only its certificate request (`CN=<name>`) is sent, to `POST /admin-api/xacml/issue-pep-credential` with `application` = the realm. | `pep.assertionKey` → `generated/pep-key.pem` (0600). It is never printed and never in the image. | Signing the PEP's assertion for its access tokens. | `--pep` keeps an existing key and only binds it again (`set-pep-application`). To replace it, delete the file and run `--pep` again. |

The library refuses a PEP key that is one of the application's own keys. `RelyingParty.create` refuses `pep.assertionKey` equal to `privateKey`, and `SignalsReceiver` refuses it equal to the receiver's TLS client key. Both compare JWK thumbprints.

### Install-time only

| Credential | What it is | Where it lives | Used for |
|---|---|---|---|
| The management client's secret | The secret of iya-sts's `sts-api-client`. | `ADMIN_API_CLIENT_SECRET` (or `STS_ADMIN_API_CLIENT_SECRET`) in the environment of `scripts/configure_iya_sts.py`. It is never written to a file or printed. | A `client_credentials` token with `admin:read admin:write` for every management call. A second token, `admin:read admin:security`, is minted only for the one `--pep` call that defines the realm's custom attribute `attr1`. |

Neither the demo nor the library ever sees this secret.

### Trust material

All of it is public; none of it is a secret.

| What | Where | What it verifies |
|---|---|---|
| iya-sts's listener CA chain | `idpCa` → `generated/idp-ca.pem`, written by the install script on every run through `scripts/trust_chain.py` and copied into the demo image. | iya-sts's TLS certificate, for the metadata fetch, every Shared Signals call, and the PEP's calls (`tlsCa` defaults to `idpCa`). |
| The identity provider's metadata | `idpMetadata` → `generated/idp-metadata.xml`. | The XML signature on every security token. |
| The transmitter's JWKS | Fetched at run time from the transmitter's `jwks_uri`. | The signature on every Security Event Token. |
| The relying party's metadata | `generated/rp-metadata.xml`, written by the install script. | Nothing here; it is for an identity provider that wants this relying party's encryption certificate. |

### Development and product iya-sts

- **Realm-issued certificates work in both modes.** A certificate iya-sts issues chains to its Service Root. The main port trusts that Root while issued client certificates are trusted, so nothing has to be pinned in its client-certificate truststore.
- **Why not pin the RP's certificate.** That truststore is process-wide. A self-signed certificate added there is trusted for every realm and ties the Shared Signals identity to the WS-Federation key pair. The install script has the realm issue a certificate and removes the anchor earlier versions added.
- **Development checks fewer passwords.** iya-sts's development sign-in page checks no password: the username is the identity. Product checks the test user's password.
- **The PEP's credential is the same in both modes:** its certified key and the `remote-peps` membership.

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
