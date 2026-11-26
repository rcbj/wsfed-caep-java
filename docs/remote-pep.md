<!--
SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
SPDX-License-Identifier: MIT
-->

# Using the iya-sts Remote PEP

This library can ask iya-sts's authorization policy whether a signed-in person (the `WsFedLogin` `handleReply` returned) may do something to a resource in your application, through an embedded **Remote PEP** (Policy Enforcement Point). The PEP itself is the shared [`iya-pep`](https://github.com/rcbj/iya-pep-java) library (`com.iyasec:iya-pep`); this library builds it from your configuration, turns its WS-Federation sign-in into the PEP's subject, and hands it policy-change events from its Shared Signals stream. The design is [iya-sts #1206](https://github.com/rcbj/iya-sts/issues/1206).

The PEP never permits by default. A decision is a Permit, a Deny or Unavailable, and Unavailable (no policy held yet, iya-sts unreachable or answering badly, or an engine fault) must be treated as a refusal. Every PEP failure is a 403: `Decision.httpStatus()` is 200 for a Permit and 403 for a Deny and an Unavailable alike. `decide` and `decideSession` do not throw.

## Choosing a mode

| | `central` | `local` |
|---|---|---|
| Who decides | iya-sts, per request (`POST /access/v1/evaluation`) | this process, with the PEP's own XACML engine |
| How this library includes it | always; there is no feature flag | the same dependency |
| Latency | one HTTPS round trip per decision | none after the first pull |
| When iya-sts is down | every decision is Unavailable, and a Permit cache is emptied | decisions continue with the policies held |
| Policy changes | at once | on the `pep-policies-changed` event, or the next poll |
| Decision records | written by iya-sts | sent by the PEP to iya-sts's audit log |

Pick `central` when decisions are infrequent or must reflect a change immediately, and `local` when decisions are on a hot path or must survive a short outage. Both modes give the same answer for the same request: `local` maps the request through the realm's catalogue exactly as iya-sts does.

## Before you start: set up iya-sts

You need an iya-sts release with embedded-PEP support (iya-sts #2026, #2027 and #2028). The steps below use the management API; `$API` is `https://<host>/realm/<realm>/admin-api` (or `https://<host>/admin-api` for the default realm) and `$TOKEN` a token for it with write access. Every step has a console equivalent, named after it.

```bash
api() { curl -s -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d "$2" "$API/$1"; }
```

### 1. Register the application

Register the WS-Federation relying party in iya-sts as usual; `scripts/configure_iya_sts.py` does it for the demo. Note its identifier: it is the `application` the PEP is bound to (`realm`, the wtrealm, by default).

**For the demo, one command does steps 1 to 6**: `python3 scripts/configure_iya_sts.py --pep central` (or `local`); see *The demo* below.

### 2. Create the PEP's service account

The PEP signs in as a service account of its own, never as a person or as the application:

```bash
api users/create '{"username":"pep-orders","invent":false,
  "credential":"none","serviceAccount":true,"owners":["admin-write"],
  "attributes":{"cn":"pep-orders","displayName":"pep-orders"}}'
api groups/add-member '{"group":"remote-peps","member":"pep-orders"}'
```

Console: **Users → New user** (tick **Service account**), then the `remote-peps` group's **Add member**.

### 3. Make the PEP's key, certify it and bind the PEP

Generate the key where the application runs. Only the certificate request leaves the machine:

```bash
openssl ecparam -name prime256v1 -genkey -noout | \
  openssl pkcs8 -topk8 -nocrypt -out pep-key.pem
openssl req -new -key pep-key.pem -subj /CN=pep-orders -out pep-key.csr
api xacml/issue-pep-credential "$(jq -n --rawfile csr pep-key.csr \
  '{name: "pep-orders", csr: $csr, application: "<application id>"}')"
```

`application` binds the PEP to the application in the same call (`POST /admin-api/xacml/set-pep-application` does it on its own). An EC P-256 key is preferred; RSA of 2048 bits or more is accepted. **The key must be the PEP's own**: this library refuses a configuration where it is `privateKey` (the relying party's signing and decryption key) and where it is the receiver's TLS client key. Both comparisons are JWK thumbprints.

Console: **Protocols → XACML → Remote PEPs**, **Certify the key**, then the PEP's Overview, **Embedded in an application**.

### 4. Declare the claims your policy reads

The PEP sends a subject's claims only through the realm's AuthZEN attribute catalogue: a claim with no catalogue row is not sent (iya-sts would refuse the whole request). Add one row per claim your policy uses, on **Protocols → XACML → AuthZEN** or with `POST /admin-api/xacml/authzen/set-attribute`. For example, to make `acr` available as `urn:example:acr`:

```bash
api xacml/authzen/set-attribute '{"object":"subject","property":"acr","attributeId":"urn:example:acr"}'
```

which is the row

| `object` | `property` | `attributeId` |
|---|---|---|
| `subject` | `acr` | `urn:example:acr` |

The same applies to resource properties, action properties and context members you put on an `Access`. iya-sts's [AuthZEN page](https://rcbj.github.io/iya-sts/v1.2.0/authzen.html), *The realm's conversion rules*, describes the rows.

### 5. Write the policy

The policy that decides is the application's own fine-grained authorization policy when the application enforces fine-grained authorization, and otherwise the realm's root policy. A `local` PEP is sent that policy and everything it references, and nothing else. The subject's id arrives as XACML's `subject-id`, the action's name as `action-id` and the resource's id as `resource-id`; anything else comes through the catalogue rows of step 4, or from iya-sts's PIP for attributes on the person's directory entry. The resource's type arrives as `urn:sts:xacml:authzen:resource-type`.

For an application that enforces no fine-grained authorization, a root that permits `read` on an `order` when the person's `acr` arrived, and denies everything else, can be written in ALFA (the console's **Policies** tab does the same):

```bash
api xacml/import-alfa "$(jq -n --arg alfa '
namespace orders {
    attribute act { category = actionCat
        id = "urn:oasis:names:tc:xacml:1.0:action:action-id" type = string }
    attribute rtype { category = resourceCat
        id = "urn:sts:xacml:authzen:resource-type" type = string }
    attribute acr { category = subjectCat id = "urn:example:acr" type = string }
    policy ordersRoot {
        id = "urn:example:orders"
        apply firstApplicable
        rule readOrder {
            permit
            target clause act == "read"
            target clause rtype == "order"
            condition integerGreaterThan(stringBagSize(acr), 0)
        }
        rule otherwise { deny }
    }
}' '{name: "orders", alfa: $alfa}')"
api xacml/set-root '{"name":"orders"}'
```

Every change to that policy, or to which policy is the root, is sent to a `local` PEP as `pep-policies-changed` (step 6).

### 6. (`local` with signals) let the event through

If the application's entry restricts its Shared Signals streams with `ssfAllowedEvents`, add `urn:iya:sts:secevent:event-type:pep-policies-changed` to it. Otherwise the PEP doesn't hear of a change until its fallback poll, and the application's page in the console warns about it.

## Dependency

```xml
<dependency>
  <groupId>com.iyasec</groupId>
  <artifactId>iya-pep</artifactId>
  <version>0.1.0</version>
</dependency>
```

`library/pom.xml` already declares that dependency. The library always includes the PEP: a missing `pep` section means the PEP is off, and a present section is used. There is no build flag that refuses the section.

`iya-pep` is not on Maven Central yet. The Dockerfile `test` stage (`maven:3.9-eclipse-temurin-26`) and the `build` stage clone `https://github.com/rcbj/iya-pep-java.git` branch `develop` and install it with `mvn -B -DskipTests install` before this library's `mvn -B test` and before the demo is packaged. The clone is one attempt. This library stays on `develop` until `iya-pep` is published, because a merge to `main` publishes `wsfed-caep`. The bytecode this library compiles is 17. The image that runs the demo is `eclipse-temurin:25-jre`.

## Configure

Add a `pep` section to `wsfed.json`. The PEP is off unless it is present.

```json
"pep": {
  "name": "pep-orders",
  "mode": "local",
  "assertionKey": "pep-key.pem"
}
```

| Member | Default here | What it is |
|---|---|---|
| `name` | required | The PEP's service account (step 2). |
| `mode` | `local` | `local` (the PEP pulls its application's policies, caches them in memory and decides in process) or `central` (it asks iya-sts for every decision). |
| `assertionKey` | required | The PEP's private key in PEM: a path (a `file:` prefix is allowed); a relative one is read from the configuration file's directory, like `privateKey`. The configuration stores the path. The PEM is not copied into the section. |
| `pdpUrl` | the identity provider's metadata entityID. iya-sts publishes its realm's issuer there, which is the service's base with the `/realm/<id>` prefix | iya-sts, with `/realm/<id>` for a realm. |
| `application` | `realm` (the wtrealm) | The application the PEP is bound to (step 3). |
| `clientId` | `sts-remote-pep` | The client the PEP's assertion is presented through. |
| `signals` | the library's `signals` | Whether a signal stream hands over policy-change events. With it on, the PEP starts as `down` until the receiver reports the stream. `null` or `true` is on. |
| `pollIntervalMs` | 15000 | `local`: the poll period while the stream does not carry the event (no stream, `down` or `excluded`). |
| `fallbackPollMs` | 300000 | `local`: the poll period while the stream carries the event (`requested`), in case one is lost. |
| `heartbeatIntervalMs` | 30000 | How often the PEP reports to iya-sts. |
| `permitCacheMs` | 0 (off) | `central` only: reuse a Permit for this long, at most 60000. The policy-change event clears it, and so does a failed evaluation or heartbeat. |
| `supportedObligations` | `[]` | The obligation types your application discharges (see *Obligations*). |
| `decisionRecords` | `true` | `local`: send each decision to iya-sts's audit log. |
| `tlsCa` | `idpCa` | PEM trust anchors for iya-sts's TLS. Inserted when `idpCa` contains a certificate and the section does not name its own. |
| `timeoutMs` | 10000 | Per request to iya-sts. |

An unknown member is refused, so a misspelt one doesn't quietly fall back to a default. `RelyingParty.fromFile` and `RelyingParty.create` start the PEP after the identity provider's metadata is read. An unreachable service is retried on the PEP's own thread; `start` returns.

## Decide

```java
Decision decision = party.decideSession(receiver, sessionId, login, Access.of("read", "order", orderId));
int status = decision.httpStatus(); // 200 for a Permit, 403 for anything else
if (decision.isPermit()) {
    // discharge decision.obligations(), then serve
} else {
    // 403. decision.kind() is DENY or UNAVAILABLE; decision.why() says which
}
// Without a receiver: party.decide(login, access)
```

Answer the request with `decision.httpStatus()` rather than your own mapping, so a failure can never become anything but a 403. Whether the person is signed in at all (a 401) is your question, asked before the PEP's.

`Access.of(action, resourceType, resourceId)` carries the AuthZEN action and resource. The PEP always sets the application context to the bound application.

**The subject** comes from the sign-in, never from a request header:

- **id:** the `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name` claim, else the NameID. A blank name is skipped. iya-sts puts the directory username in both. The `nameidentifier` claim is the opaque `sub` and is never the id. (The Shared Signals session index still keys a person by `nameidentifier`. That is a different subject.)
- **properties:** each attribute keyed by its FriendlyName, else the last segment of its Name (`emailaddress`, `role`), when that name matches `[A-Za-z0-9_$@:-]` and is 1 to 64 characters. A dot is not in that set, so an OID with no usable segment is left out. Then `acr` (AuthnContextClassRef), `amr` (the `authenticationmethod` claim, always an array) and `auth_time` (AuthnInstant, epoch seconds). Empty values are skipped. The first claim URI in sorted order wins a duplicate property key; `acr`, `amr` and `auth_time` overwrite.

Only the properties the catalogue declares are sent.

**Ended sessions.** `party.decideSession(receiver, sessionId, login, access)` is a Deny without asking when the assertion's `SessionNotOnOrAfter` is now or in the past (`the identity provider's session has ended`), or when the receiver no longer tracks the session (`no signed-in session`): untracked, past the index expiry, or ended by a Shared Signals event such as CAEP `session-revoked`.

**Without a `pep` section**, every decision is Unavailable (`no pep section is configured`), a 403.

### Obligations

A Permit can carry obligations, which your application must carry out before it grants the access (for example a `step-up` to a stronger `acr`). The PEP only hands you obligations of types you list in `supportedObligations`. A Permit carrying any other obligation is turned into a Deny, so an obligation is never silently dropped. Advice can be ignored.

```json
"pep": { "name": "pep-orders", "assertionKey": "pep-key.pem", "supportedObligations": ["step-up"] }
```

## Receive policy-change events

In `local` mode, and in `central` mode with a Permit cache (`permitCacheMs` greater than 0), the PEP wants to hear when the policies change. Give the receiver the PEP on `SignalsReceiver.Options.pep` (the demo sets it from `RelyingParty.pep()`). The receiver also refuses a PEP key that is its own TLS client key.

The receiver then asks its stream for `urn:iya:sts:secevent:event-type:pep-policies-changed` (`Pep.POLICIES_CHANGED_EVENT`), verifies each SET like every other one, and hands the event body to `pep.onPolicyEvent`. A stream that already exists is updated with `PATCH` to ask for the event too; if the transmitter refuses, the receiver still starts, the refusal goes to the receiver's log at error, and the PEP's heartbeat reports the event as `excluded`. The event is only a hint: the PEP pulls with its own credential and never trusts the event's contents. An event naming another PEP is ignored.

The same receiver tells the transmitter which people it cares about. When a local session starts it calls Add Subject, and when a person's last local session ends (sign-out, or a session an event ended) it calls Remove Subject. The calls follow SSF 1.0 §8.1.3.2–8.1.3.3 and are made only when the transmitter publishes those endpoints. The person subject is `iss_sub` (issuer plus `nameidentifier`) else `email`. A refusal is logged and never fails the sign-in. `ssf.addSubjects` (default true) turns this off; anything but `true` or `false` refuses to start the demo's receiver. Because iya-sts narrows a stream that names subjects to those subjects, and `pep-policies-changed` is about the application, a receiver given a PEP that wants events also adds the application (`{format: opaque, id: <application>}`) when it starts. It never removes that subject. Otherwise the first sign-in would stop the policy events.

The receiver keeps the PEP's view of the stream current: `requested` (or `excluded`) when it starts and after each poll that succeeds, `down` after a poll that fails and once `stop()` is called. A `local` PEP polls at `pollIntervalMs` while the stream is not `requested`, so a change still arrives while the stream cannot carry it. `status().eventStream` is that state (`none`, `requested`, `excluded` or `down`).

## Operate it

- **Health.** `pep.status()` reports whether the PEP is registered and running, whether it holds a policy (and which sync token), its decision counters and its current problems. It holds no secret, so it's safe on a health page. The demo's `GET /live-status` includes that map under `pep`, and `GET /pep-status` returns it alone.
- **In the console.** The PEP appears under **Protocols → XACML → Remote PEPs** with its kind (`embedded`), application, mode, protocol version and whether its stream carries policy-change events. The application's page lists the PEPs bound to it.
- **Rotating the key.** Generate a new key, certify it with `issue-pep-credential` (add `revokePrevious: true` to retire the old one), and replace the file. The tokens bound to the old key are dropped once the PEP reads the new file.
- **Audit.** In `local` mode each decision becomes an audit row in iya-sts (`authzen.remote.decision`). In `central` mode iya-sts records its own.

## Credentials

The PEP's half of the README's [Credentials](../README.md#credentials) section, in more detail. The headings match the README's.

### The application's own credentials

The relying party's WS-Federation key pair (`privateKey`, `certificate`) and its Shared Signals client certificate (`ssf.clientCertificate`, `ssf.clientKey`, issued by the realm) belong to the application, not the PEP. The README's table lists them. The PEP uses neither, and the library makes sure it can't (below).

### The embedded PEP's credentials

**The service account.** The PEP signs in as a service account of its own (step 2): `pep-wsfed-demo` in the demo (`--pep-name`), with no password (`credential: none`), owned by `admin-write`, and a member of `remote-peps`. The install script creates it only when `GET /admin-api/users?user=` says it doesn't exist.

**The key.** `pep.assertionKey`, an EC P-256 private key in PEM (RSA of 2048 bits or more is accepted). In the demo it is `generated/pep-key.pem`, made on the host with `openssl genpkey` and created 0600. It is never printed and never in the image. Only its certificate request (`CN=<name>`) leaves the machine, to `POST /admin-api/xacml/issue-pep-credential` with `application` equal to the realm. That certifies the key for the account and binds the PEP to the application in one call; `set-pep-application` binds it again on its own.

**What the key authenticates.** iya-pep signs an RFC 7523 self-assertion with it, through the client `sts-remote-pep` (`clientId`), at iya-sts's token endpoint. It receives DPoP-bound access tokens and signs every DPoP proof with the same key. There is one token per audience:

| Scope | Resource | Calls |
|---|---|---|
| `xacml:pep` | `<pdpUrl>/xacml/pep` | registration, heartbeat, the catalogue, the policy pull (`local`), and the PIP (`local`) |
| `xacml:pep-audit` | `<pdpUrl>/admin-api` | decision records (`local`) |
| `authzen:evaluate` | `<pdpUrl>/access/v1` | the evaluation (`central`) |

iya-pep logs and returns no token, key or proof.

**Separate from the application's keys.** `RelyingParty.create` refuses a `pep.assertionKey` that is `privateKey`, and `SignalsReceiver` refuses one that is the receiver's TLS client key (the realm-issued `ssf.clientKey`, or `privateKey` when that is absent). Both compare JWK thumbprints (`SigningKey.jwkThumbprint` for the relying party's RSA key, `SigningKey.pemThumbprint` for the TLS key). A null or empty thumbprint is not treated as a match. The PEP's tokens are bound to its key, so a shared key would let whoever holds the application's key obtain the PEP's tokens and act as the PEP.

**Rotation.** The install script's `--pep` keeps an existing account and key and only binds them again. To replace the key, delete `generated/pep-key.pem` and run `--pep <mode>` again, then revoke the old certificate on **Protocols → XACML → Remote PEPs**.

### Install-time only

The install script's management token comes from `sts-api-client`'s secret (`ADMIN_API_CLIENT_SECRET` or `STS_ADMIN_API_CLIENT_SECRET`, from the environment only, never stored or printed), with `admin:read admin:write`. Defining `attr1` alone uses a second token with `admin:read admin:security`, and only on a `--pep` run. The PEP never sees either.

### Trust material

`tlsCa` defaults to `idpCa`, the iya-sts listener CA chain the install script saves. The PEP verifies iya-sts's TLS with it on every call. A `local` PEP's policies, catalogue and PIP answers come over that verified connection with its own token. A `pep-policies-changed` event is only a hint, verified as a SET by the receiver, and the PEP pulls with its own credential.

### Development and product iya-sts

The PEP's credential is the same in both modes: the certified key and the `remote-peps` membership. Its TLS trust is the listener chain in `tlsCa`, whatever the mode.

## Troubleshooting

| What you see | Likely cause |
|---|---|
| Every decision Unavailable, `status().registered` false, a problem mentioning 403 | The PEP's entry has no binding, or is bound to another application (iya-sts `STS-XACML-0338`, `0339`). Repeat step 3 with the right `application`. |
| Unavailable and a problem naming the token endpoint (`invalid_grant`) | The key isn't certified for this account, or the account isn't in `remote-peps` (steps 2 and 3). |
| Unavailable with "no policy is held yet" (`local`) | The first pull hasn't succeeded. Check `status().lastError`: a 403 on the policy pull (`STS-XACML-0343`) means the PEP isn't registered as an embedded `local` PEP bound to that application. |
| A registration refused with 400 (`STS-XACML-0340`) | The iya-sts release doesn't support this PEP's protocol version. Upgrade iya-sts or this library. |
| Deny saying the evaluation was refused | A resource, action or context property you sent has no catalogue row (step 4). Subject claims without a row are dropped, not refused. |
| Deny although the policy should permit | The policy reads a claim that has no catalogue row, so it never arrives (step 4). Or a Permit carried an obligation type missing from `supportedObligations`. |
| Policy changes take minutes to apply (`local`) | The stream is `requested` but the event never arrives, so only the `fallbackPollMs` poll brings the change. Check `ssfAllowedEvents` (step 6) and the receiver's log for a refused stream update. |
| The configuration is refused for the assertion key | It is `privateKey`, or it is the receiver's TLS client key. The message is `pep.assertionKey is the relying party's privateKey (its signing and decryption key); the PEP needs a key of its own`, or `the receiver's TLS client key is pep.assertionKey; the PEP needs a key of its own`. |
| `pep must be an object` | The `pep` value is present and is not a JSON object. |

## The demo

The demo protects `/orders/{id}` and `/attribute-protected` when `demo/wsfed.json` has a `pep` section. No sign-in is 401, with the heading Sign in, and the PEP is not asked. Otherwise the response status is `decision.httpStatus()`: 200 on a Permit, and 403 on a Deny and on Unavailable. A GET of an order is `read` and any other method is `write`. A Permit on an order uses the heading Order; a Permit on `/attribute-protected` uses Allowed. A Deny uses Not allowed. Unavailable uses No decision and the words "could not decide". `GET /attribute-protected` is always `Access.of("read", "attribute-protected", "attr1")`: the demo application's policy permits it when the person's directory attribute `attr1` is `abc123`, which the PEP asks iya-sts's PIP for (it is not in the assertion). With a receiver running, both pages use `decideSession`, so a session an event ended is a Deny.

The signed-in home page links Home, Order 42 and Attribute-protected. `GET /live-status` carries `pep.status()` under `pep` (`mode` as `local` or `central`). `GET /pep-status` is that status as JSON and holds no secret.

The install script sets the demo up with its PEP in one command, after registering the relying party:

```bash
ADMIN_API_CLIENT_SECRET=... python3 scripts/configure_iya_sts.py --idp https://localhost:8443 --pep central
```

It does steps 2 to 6 above through the management API (a bare `--pep` is `local`): the service account `pep-wsfed-demo` (`--pep-name` to choose another) in `remote-peps`; a P-256 key made with your `openssl` in `demo/generated/pep-key.pem` (0600, never printed, kept out of the image by `.dockerignore`), certified with `issue-pep-credential` and bound to the demo's application; the catalogue row `subject.acr` → `urn:example:acr`; the application's **own** policy, enforced, which permits `read` on an `order` when the sign-in carried an `acr`, and `read` on `attribute-protected` when the person's directory attribute `attr1` is `abc123`, and denies everything else; `pep-policies-changed` in `ssfAllowedEvents` if the application restricts its events. It never touches the realm root. The application's display name stays `wsfed-caep-nodejs demo`. Finally it writes the `pep` section (`name`, `mode`, `assertionKey: file:generated/pep-key.pem`) into `demo/wsfed.json`, keeping everything else. `--dry-run` lists the calls and prints no key.

With `--pep` and a test user (the default, `wsfed-demo-user`), the script also gives that user `attr1=abc123`. Defining the realm's custom attribute `attr1` uses a second token carrying `admin:security`. A run without `--pep` does not call that path. If the definition is refused and the value cannot be set, the script says what to add on the console and carries on.

Run it again, for example with `--pep local` to switch modes: the account and the key are kept and the binding is set again. The application's policy is rewritten while its PolicyId is `urn:example:wsfeddemo-orders`; a policy under any other PolicyId is left as it is.

`python3 scripts/live_iya_sts.py --pep` (or `LIVE_PEP=1`) runs that install with `--pep central`, writes `demo/wsfed.pep-local.json` with `mode` `local`, creates `wsfed-demo-user-denied` with `attr1=not-abc123`, and checks both modes: `GET /attribute-protected` 200 with the heading Allowed for the test user, 403 with Not allowed (and not "could not decide") for the denied user, who still gets 200 on `GET /orders/42`; `GET /orders/42` 200 and `POST /orders/42` 403. It then rewrites the application's own policy to deny read and requires the GET to turn 403 within 30 seconds because `pep-policies-changed` was received (`via` `event`; the fallback poll stays at 300 seconds). The result JSON has `pep.central` and `pep.local`. It needs `IYA_STS_IMAGE` with iya-sts #2026–#2028. Ports default to 18553 and 18653 and are never 3000, 8081, or 18481–18495. The containers are `iya-sts-live-wsfed-caep-java` and `wsfed-caep-java-live-demo`. The image is checked to hold only `idp-ca.pem` under `demo/generated`. The key pair, IdP metadata, the Shared Signals client certificate when present, and `pep-key.pem` are mounted file by file. Passwords stay in memory or in a mode-0600 file whose path is the only thing printed.

On every signals-on run, not only `--pep`, the install script also issues the receiver's TLS client certificate and retires a previously pinned relying-party certificate. See the README's *Demo with its embedded PEP*.

## See also

- [`iya-pep`'s README](https://github.com/rcbj/iya-pep-java): the library's own API (`Pep`, `PepConfig`, `Decision`, `Subject`, `Access`, `SigningKey`).
- iya-sts's [Remote PEP page](https://rcbj.github.io/iya-sts/v1.2.0/remote-pep.html), *An embedded PEP's application*: the service's side of the binding, registration and the scoped pull.
- iya-sts's [CAEP events page](https://rcbj.github.io/iya-sts/v1.2.0/caep-events.html): the `pep-policies-changed` event.
