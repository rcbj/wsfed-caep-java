// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.wsfed;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.w3c.dom.Element;

class RpTest {
    private static Map<String, Object> config() {
        return config(Map.of(), null);
    }

    private static Map<String, Object> config(Map<String, Object> extra, String metadata) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("realm", StubIdp.REALM);
        body.put("replyUrl", StubIdp.REPLY);
        body.put("privateKey", StubIdp.RP_KEY);
        body.put("certificate", StubIdp.RP_CERT);
        body.put("idpMetadata", metadata == null ? StubIdp.idpMetadata() : metadata);
        body.putAll(extra);
        return body;
    }

    private static WsFedLogin post(RelyingParty rp, String result, Object requestId, String wctx) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("wa", "wsignin1.0");
        body.put("wresult", result);
        if (wctx != null) body.put("wctx", wctx);
        return rp.handleReply(Map.of("method", "POST", "url", "/wsfed", "body", body), requestId);
    }

    private static WsFedLogin post(RelyingParty rp, String result, Object requestId) {
        String wctx = requestId instanceof String text ? "id=" + text : null;
        return post(rp, result, requestId, wctx);
    }

    private static void rejects(Executable call, String code, String pattern) {
        WsFedError err = assertThrows(WsFedError.class, call);
        assertEquals(code, err.code, err.getMessage());
        if (pattern != null) assertTrue(Pattern.compile(pattern).matcher(err.getMessage()).find(), err.getMessage());
    }

    private static Map<String, String> qparams(String url) {
        String query = URI.create(url).getRawQuery();
        Map<String, String> out = new LinkedHashMap<>();
        for (String part : query.split("&")) {
            int eq = part.indexOf('=');
            out.put(URLDecoder.decode(part.substring(0, eq), StandardCharsets.UTF_8), URLDecoder.decode(part.substring(eq + 1), StandardCharsets.UTF_8));
        }
        return out;
    }

    @Test
    void configurationRequiresRealmReplyAndAMatchingKey() {
        Map<String, Object> emptyRealm = config();
        emptyRealm.put("realm", "");
        rejects(() -> RelyingParty.create(emptyRealm), "config", "realm");
        Map<String, Object> relative = config();
        relative.put("replyUrl", "/wsfed");
        rejects(() -> RelyingParty.create(relative), "config", "absolute");
        rejects(() -> RelyingParty.create(config(Map.of("certificate", StubIdp.IDP_CERT), null)), "config", "not for the private key");
        Map<String, Object> onlyKey = new LinkedHashMap<>();
        onlyKey.put("realm", StubIdp.REALM);
        onlyKey.put("replyUrl", StubIdp.REPLY);
        onlyKey.put("idpMetadata", StubIdp.idpMetadata());
        onlyKey.put("privateKey", StubIdp.RP_KEY);
        rejects(() -> RelyingParty.create(onlyKey), "config", "together");
        Map<String, Object> want = new LinkedHashMap<>();
        want.put("realm", StubIdp.REALM);
        want.put("replyUrl", StubIdp.REPLY);
        want.put("idpMetadata", StubIdp.idpMetadata());
        want.put("wantAssertionsEncrypted", Boolean.TRUE);
        rejects(() -> RelyingParty.create(want), "config", "needs privateKey");
        Map<String, Object> keyless = new LinkedHashMap<>();
        keyless.put("realm", StubIdp.REALM);
        keyless.put("replyUrl", StubIdp.REPLY);
        keyless.put("idpMetadata", StubIdp.idpMetadata());
        assertFalse(RelyingParty.create(keyless).metadata().contains("KeyDescriptor"));
    }

    @Test
    void signalsOmittedOrTrueIsLeftOffTheResolvedConfig() {
        Map<String, Object> base = new LinkedHashMap<>();
        base.put("realm", StubIdp.REALM);
        base.put("replyUrl", StubIdp.REPLY);
        base.put("idpMetadata", "https://idp.example/FederationMetadata/2007-06/FederationMetadata.xml");
        Resolved omitted = RelyingParty.resolveConfig(base);
        assertNull(omitted.signals);
        assertEquals(StubIdp.REALM, omitted.realm);
        assertEquals(StubIdp.REPLY, omitted.replyUrl);
        assertTrue(omitted.requestTokenType);
        Map<String, Object> onMap = new LinkedHashMap<>(base);
        onMap.put("signals", Boolean.TRUE);
        Resolved on = RelyingParty.resolveConfig(onMap);
        assertNull(on.signals);
        assertEquals(omitted.realm, on.realm);
        assertEquals(omitted.replyUrl, on.replyUrl);
        assertEquals(omitted.idpMetadata, on.idpMetadata);
        assertEquals(omitted.clockSkewMs, on.clockSkewMs);
        assertEquals(omitted.requestTokenType, on.requestTokenType);
    }

    @Test
    void signalsFalseIsRecordedAndSignInStillWorks() {
        Map<String, Object> base = new LinkedHashMap<>();
        base.put("realm", StubIdp.REALM);
        base.put("replyUrl", StubIdp.REPLY);
        base.put("idpMetadata", "https://idp.example/FederationMetadata/2007-06/FederationMetadata.xml");
        Map<String, Object> offMap = new LinkedHashMap<>(base);
        offMap.put("signals", Boolean.FALSE);
        Resolved off = RelyingParty.resolveConfig(offMap);
        assertEquals(Boolean.FALSE, off.signals);
        assertEquals(StubIdp.REALM, off.realm);
        assertEquals(StubIdp.REPLY, off.replyUrl);
        assertEquals(base.get("idpMetadata"), off.idpMetadata);
        Map<String, Object> party = config(Map.of("signals", Boolean.FALSE), null);
        RelyingParty rp = RelyingParty.create(party);
        assertEquals("alice-1234", post(rp, StubIdp.wresult(), "_r").nameId);
    }

    @Test
    void signalsMustBeTrueOrFalse() {
        Map<String, Object> base = new LinkedHashMap<>();
        base.put("realm", StubIdp.REALM);
        base.put("replyUrl", StubIdp.REPLY);
        base.put("idpMetadata", "https://idp.example/metadata");
        base.put("signals", "no");
        WsFedError err = assertThrows(WsFedError.class, () -> RelyingParty.resolveConfig(base));
        assertEquals("config", err.code);
        assertEquals("signals must be true or false", err.getMessage());
    }

    @Test
    void readsTheSecurityTokenServiceRole() {
        RelyingParty rp = RelyingParty.create(config());
        assertEquals(StubIdp.IDP_ENTITY, rp.getIdp().entityId);
        assertEquals(StubIdp.PASSIVE, rp.getIdp().passiveRequestorEndpoint);
        assertTrue(rp.getIdp().tokenTypesOffered.contains("urn:oasis:names:tc:SAML:2.0:assertion"));
        assertEquals(1, rp.getIdp().signingCertificates.size());
    }

    @Test
    void xsiTypeIsResolvedByNamespaceAndTheIdpRoleKeyIsAFallback() {
        assertEquals(StubIdp.PASSIVE, RelyingParty.create(config(Map.of(), StubIdp.idpMetadata("sts", null, "wsfed", false))).getIdp().passiveRequestorEndpoint);
        assertEquals(1, RelyingParty.create(config(Map.of(), StubIdp.idpMetadata("idpsso", null, "fed", false))).getIdp().signingCertificates.size());
    }

    @Test
    void refusesMetadataWithoutAnStsOrSaml2() {
        rejects(() -> RelyingParty.create(config(Map.of(), StubIdp.idpMetadata("sts", null, "fed", true))), "metadata", "SecurityTokenServiceType");
        rejects(() -> RelyingParty.create(config(Map.of(), StubIdp.idpMetadata("sts", new String[] {"urn:oasis:names:tc:SAML:1.0:assertion"}, "fed", false))), "metadata", "no SAML 2.0");
    }

    @Test
    void writesApplicationServiceMetadata() {
        String xml = RelyingParty.create(config()).metadata();
        Element root = Xmls.parse(xml, "metadata").getDocumentElement();
        assertEquals(StubIdp.REALM, root.getAttribute("entityID"));
        Element role = Xmls.child(root, Xmls.MD, "RoleDescriptor");
        assertEquals("fed:ApplicationServiceType", role.getAttributeNS(Xmls.XSI, "type"));
        assertTrue(xml.contains("<fed:PassiveRequestorEndpoint><wsa:EndpointReference><wsa:Address>" + StubIdp.REPLY + "</wsa:Address>"));
        assertTrue(xml.contains("<fed:TargetScopes><wsa:EndpointReference><wsa:Address>" + StubIdp.REALM + "</wsa:Address>"));
        assertTrue(Pattern.compile("<md:KeyDescriptor use=\"encryption\">[\\s\\S]*xmlenc11#aes256-gcm[\\s\\S]*</md:KeyDescriptor>").matcher(xml).find());
    }

    @Test
    void signinNamesRealmReplyWctxAndSaml2() {
        RelyingParty rp = RelyingParty.create(config());
        RelyingParty.LoginRequest req = rp.login(Map.of("relayState", "/home é"));
        URI uri = URI.create(req.url);
        assertEquals(StubIdp.PASSIVE, uri.getScheme() + "://" + uri.getRawAuthority() + uri.getRawPath());
        Map<String, String> params = qparams(req.url);
        assertEquals("wsignin1.0", params.get("wa"));
        assertEquals(StubIdp.REALM, params.get("wtrealm"));
        assertEquals(StubIdp.REPLY, params.get("wreply"));
        Map<String, String> wctx = qparams("http://x/?" + params.get("wctx"));
        assertEquals(req.id, wctx.get("id"));
        assertEquals("/home é", wctx.get("ru"));
        assertTrue(params.get("wreq").contains("<wst:TokenType>urn:oasis:names:tc:SAML:2.0:assertion</wst:TokenType>"));
        assertTrue(params.get("wct").matches("\\d{4}-\\d\\d-\\d\\dT\\d\\d:\\d\\d:\\d\\dZ"));
        assertFalse(params.containsKey("wfresh"));
    }

    @Test
    void forceAuthnAndProtocolParams() {
        RelyingParty rp = RelyingParty.create(config(Map.of("requestTokenType", Boolean.FALSE), null));
        Map<String, Object> options = new LinkedHashMap<>();
        options.put("forceAuthn", Boolean.TRUE);
        options.put("authenticationMethod", "http://schemas.microsoft.com/claims/multipleauthn");
        options.put("homeRealm", "urn:partner");
        options.put("params", Map.of("login_hint", "alice"));
        Map<String, String> params = qparams(rp.login(options).url);
        assertEquals("0", params.get("wfresh"));
        assertEquals("http://schemas.microsoft.com/claims/multipleauthn", params.get("wauth"));
        assertEquals("urn:partner", params.get("whr"));
        assertEquals("alice", params.get("login_hint"));
        assertFalse(params.containsKey("wreq"));
        WsFedError own = assertThrows(WsFedError.class, () -> rp.login(Map.of("params", Map.of("wtrealm", "urn:evil"))));
        assertTrue(own.getMessage().contains("protocol's own"));
        WsFedError longRelay = assertThrows(WsFedError.class, () -> rp.login(Map.of("relayState", "x".repeat(1025))));
        assertTrue(longRelay.getMessage().contains("1024 bytes"));
    }

    @Test
    void signoutRequest() {
        Map<String, String> params = qparams(RelyingParty.create(config()).logout("https://rp.test/"));
        assertEquals("wsignout1.0", params.get("wa"));
        assertEquals(StubIdp.REALM, params.get("wtrealm"));
        assertEquals("https://rp.test/", params.get("wreply"));
    }

    @Test
    void signedAssertionInA2005Response() {
        RelyingParty rp = RelyingParty.create(config());
        RelyingParty.LoginRequest req = rp.login(Map.of("relayState", "/home"));
        WsFedLogin who = post(rp, StubIdp.wresult(), req.id, req.wctx);
        assertEquals("alice-1234", who.nameId);
        assertEquals("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", who.nameIdFormat);
        assertEquals("_session1", who.sessionIndex);
        assertEquals("/home", who.relayState);
        assertEquals(req.id, who.requestId);
        assertEquals("2005/02", who.trustVersion);
        assertEquals(StubIdp.REALM, who.realm);
        assertFalse(who.encrypted);
        assertEquals(List.of("staff", "admins"), who.attributes.get("http://schemas.microsoft.com/ws/2008/06/identity/claims/role"));
        assertEquals("mail", who.attributeFriendlyNames.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"));
        assertEquals("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport", who.authnContextClassRef);
    }

    @Test
    void trust13AndARawFormBody() {
        RelyingParty rp = RelyingParty.create(config());
        assertEquals("1.3", post(rp, StubIdp.wresult(null, "1.3", null, null, 3_600_000), "_r").trustVersion);
        String raw = form(Map.of("wa", "wsignin1.0", "wresult", StubIdp.wresult(), "wctx", "id=_s"));
        WsFedLogin who = rp.handleReply(Map.of("method", "POST", "url", "/wsfed", "body", raw), List.of("_x", "_s"));
        assertEquals("alice-1234", who.nameId);
    }

    @Test
    void recipientOptionalAndChecked() {
        RelyingParty rp = RelyingParty.create(config());
        StubIdp.Options none = new StubIdp.Options();
        none.recipient = null;
        assertEquals("alice-1234", post(rp, StubIdp.wresult(StubIdp.signedAssertion(none).xml, "2005", null, null, 3_600_000), "_r").nameId);
        StubIdp.Options other = new StubIdp.Options();
        other.recipient = "https://other.test/wsfed";
        rejects(() -> post(rp, StubIdp.wresult(StubIdp.signedAssertion(other).xml, "2005", null, null, 3_600_000), "_r"), "validation", "Recipient");
    }

    @Test
    void bareBearerConfirmation() {
        RelyingParty rp = RelyingParty.create(config());
        StubIdp.Options bare = new StubIdp.Options();
        bare.bareConfirmation = true;
        WsFedLogin who = post(rp, StubIdp.wresult(StubIdp.signedAssertion(bare).xml, "2005", null, null, 3_600_000), "_r");
        assertEquals("alice-1234", who.nameId);
        assertTrue(who.notOnOrAfter.isAfter(Instant.now()));
        StubIdp.Options expired = new StubIdp.Options();
        expired.bareConfirmation = true;
        expired.notOnOrAfterMs = -120_000;
        rejects(() -> post(rp, StubIdp.wresult(StubIdp.signedAssertion(expired).xml, "2005", null, null, 3_600_000), "_r"), "validation", "expired");
        StubIdp.Options unbounded = new StubIdp.Options();
        unbounded.bareConfirmation = true;
        unbounded.noConditionsExpiry = true;
        rejects(() -> post(rp, StubIdp.wresult(StubIdp.signedAssertion(unbounded).xml, "2005", null, null, 3_600_000), "_r"), "validation", "nothing|no Conditions NotOnOrAfter");
    }

    @Test
    void unsignedAssertionIsRefused() {
        RelyingParty rp = RelyingParty.create(config());
        rejects(() -> post(rp, StubIdp.wresult(StubIdp.assertionXml(null).xml, "2005", null, null, 3_600_000), "_r"), "validation", "not signed");
    }

    @Test
    void alteredOrWrongKeyIsRefused() {
        RelyingParty rp = RelyingParty.create(config());
        rejects(() -> post(rp, StubIdp.wresult(StubIdp.signedAssertion(null).xml.replace("alice-1234", "mallory"), "2005", null, null, 3_600_000), "_r"), "signature", null);
        StubIdp.Made made = StubIdp.assertionXml(null);
        rejects(() -> post(rp, StubIdp.wresult(StubIdp.signXml(made.xml, made.id, StubIdp.RP_KEY, StubIdp.RP_CERT), "2005", null, null, 3_600_000), "_r"), "signature", "does not verify");
    }

    @Test
    void signatureWrapping() {
        RelyingParty rp = RelyingParty.create(config());
        StubIdp.Made signed = StubIdp.signedAssertion(null);
        StubIdp.Options forgedOptions = new StubIdp.Options();
        forgedOptions.nameId = "mallory";
        String forged = StubIdp.assertionXml(forgedOptions).xml;
        rejects(() -> post(rp, StubIdp.wresult(forged + signed.xml, "2005", null, null, 3_600_000), "_r"), "message", "exactly one");
        String hidden = forged.replaceFirst("ID=\"[^\"]+\"", "ID=\"" + signed.id + "\"").replace("</saml:Assertion>", "<saml:Advice>" + signed.xml + "</saml:Advice></saml:Assertion>");
        rejects(() -> post(rp, StubIdp.wresult(hidden, "2005", null, null, 3_600_000), "_r"), "signature", "two elements");
        String decoy = StubIdp.wresult(signed.xml, "2005", null, null, 3_600_000).replace("<t:Lifetime>",
                "<t:Lifetime xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" wsu:Id=\"" + signed.id + "\">");
        rejects(() -> post(rp, decoy, "_r"), "signature", "two elements");
        var matcher = Pattern.compile("<ds:Signature[\\s\\S]*</ds:Signature>").matcher(signed.xml);
        assertTrue(matcher.find());
        String moved = forged.replaceFirst("(</saml:Issuer>)", "$1" + matcher.group());
        rejects(() -> post(rp, StubIdp.wresult(moved, "2005", null, null, 3_600_000), "_r"), "signature", "refers to");
    }

    @Test
    void wrongRealmIssuerOrExpiry() {
        RelyingParty rp = RelyingParty.create(config());
        StubIdp.Options audience = new StubIdp.Options();
        audience.audience = "https://other.test/";
        rejects(() -> post(rp, StubIdp.wresult(StubIdp.signedAssertion(audience).xml, "2005", null, null, 3_600_000), "_r"), "validation", "not for");
        StubIdp.Options issuer = new StubIdp.Options();
        issuer.issuer = "https://evil.test";
        rejects(() -> post(rp, StubIdp.wresult(StubIdp.signedAssertion(issuer).xml, "2005", null, null, 3_600_000), "_r"), "validation", "issued by");
        StubIdp.Options expired = new StubIdp.Options();
        expired.notOnOrAfterMs = -120_000;
        rejects(() -> post(rp, StubIdp.wresult(StubIdp.signedAssertion(expired).xml, "2005", null, null, 3_600_000), "_r"), "validation", "expired");
        rejects(() -> post(rp, StubIdp.wresult(null, "2005", "https://other.test/", null, 3_600_000), "_r"), "validation", "applies to");
        rejects(() -> post(rp, StubIdp.wresult(null, "2005", null, null, -120_000), "_r"), "validation", "response expired");
    }

    @Test
    void inResponseToIsRefused() {
        RelyingParty rp = RelyingParty.create(config());
        StubIdp.Options options = new StubIdp.Options();
        options.inResponseTo = "_samlreq";
        rejects(() -> post(rp, StubIdp.wresult(StubIdp.signedAssertion(options).xml, "2005", null, null, 3_600_000), "_r"), "validation", "InResponseTo");
    }

    @Test
    void saml11AndNonTrustAreRefused() {
        RelyingParty rp = RelyingParty.create(config());
        rejects(() -> post(rp, StubIdp.wresult(StubIdp.saml11(), "2005", null, "urn:oasis:names:tc:SAML:2.0:assertion", 3_600_000), "_r"), "message", "SAML 1\\.1");
        rejects(() -> post(rp, StubIdp.wresult(null, "2005", null, "urn:oasis:names:tc:SAML:1.0:assertion", 3_600_000), "_r"), "message", "SAML 2.0 assertions only");
        rejects(() -> post(rp, StubIdp.signedAssertion(null).xml, "_r"), "message", "not a WS-Trust");
        rejects(() -> post(rp, "<!DOCTYPE x [<!ENTITY e \"x\">]>" + StubIdp.wresult(), "_r"), "xml", "DOCTYPE");
    }

    @Test
    void unsolicitedAndUnknownRequests() {
        RelyingParty rp = RelyingParty.create(config());
        rejects(() -> post(rp, StubIdp.wresult(), "_other", "id=_r"), "validation", "not a sign-in this browser");
        rejects(() -> post(rp, StubIdp.wresult(), null, "id=_r"), "validation", "not a sign-in this browser");
        rejects(() -> post(rp, StubIdp.wresult(), null, null), "validation", "unsolicited");
        RelyingParty open = RelyingParty.create(config(Map.of("allowUnsolicited", Boolean.TRUE), null));
        WsFedLogin who = post(open, StubIdp.wresult(), null, "ru=%2Fthere");
        assertNull(who.requestId);
        assertEquals("/there", who.relayState);
    }

    @Test
    void replay() {
        RelyingParty rp = RelyingParty.create(config());
        String result = StubIdp.wresult();
        post(rp, result, "_r");
        rejects(() -> post(rp, result, "_r"), "replay", null);
    }

    @Test
    void decryptsEncryptedAssertions() {
        RelyingParty rp = RelyingParty.create(config());
        for (String cipher : List.of("aes-256-gcm", "aes-128-cbc")) {
            WsFedLogin who = post(rp, StubIdp.wresult(StubIdp.encrypt(StubIdp.signedAssertion(null).xml, cipher, "mgf1p", "EncryptedAssertion"), "2005", null, null, 3_600_000), "_r");
            assertEquals("alice-1234", who.nameId);
            assertTrue(who.encrypted);
        }
        WsFedLogin who = post(rp, StubIdp.wresult(StubIdp.encrypt(StubIdp.signedAssertion(null).xml, "aes-256-gcm", "oaep256", null), "2005", null, null, 3_600_000), "_r");
        assertTrue(who.encrypted);
    }

    @Test
    void wantAssertionsEncryptedAndTamperedCiphertext() {
        RelyingParty rp = RelyingParty.create(config(Map.of("wantAssertionsEncrypted", Boolean.TRUE), null));
        rejects(() -> post(rp, StubIdp.wresult(), "_r"), "validation", "not encrypted");
        rejects(() -> post(rp, StubIdp.wresult(StubIdp.encrypt(StubIdp.assertionXml(null).xml), "2005", null, null, 3_600_000), "_r"), "validation", "not signed");
        String enc = StubIdp.encrypt(StubIdp.signedAssertion(null).xml);
        var matcher = Pattern.compile("<xenc:CipherValue>([^<]+)</xenc:CipherValue>").matcher(enc);
        String last = null;
        while (matcher.find()) last = matcher.group(1);
        byte[] raw = Base64.getDecoder().decode(last);
        raw[20] ^= 1;
        String replaced = enc.replace(last, Base64.getEncoder().encodeToString(raw));
        rejects(() -> post(rp, StubIdp.wresult(replaced, "2005", null, null, 3_600_000), "_r"), "decryption", null);
    }

    @Test
    void encryptedAttributeAndMissingKey() {
        Map<String, Object> keyless = new LinkedHashMap<>();
        keyless.put("realm", StubIdp.REALM);
        keyless.put("replyUrl", StubIdp.REPLY);
        keyless.put("idpMetadata", StubIdp.idpMetadata());
        rejects(() -> post(RelyingParty.create(keyless), StubIdp.wresult(StubIdp.encrypt(StubIdp.signedAssertion(null).xml), "2005", null, null, 3_600_000), "_r"), "decryption", "no privateKey");
        RelyingParty rp = RelyingParty.create(config());
        String secret = StubIdp.encrypt("<saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"employeeNumber\"><saml:AttributeValue>E-42</saml:AttributeValue></saml:Attribute>", "aes-256-gcm", "oaep256", "EncryptedAttribute");
        StubIdp.Options options = new StubIdp.Options();
        options.extraAttributes = secret;
        StubIdp.Made made = StubIdp.assertionXml(options);
        WsFedLogin who = post(rp, StubIdp.wresult(StubIdp.signXml(made.xml, made.id, StubIdp.IDP_KEY, StubIdp.IDP_CERT), "2005", null, null, 3_600_000), "_r");
        assertEquals(List.of("E-42"), who.attributes.get("employeeNumber"));
    }

    @Test
    void replyUrlRefusesGetWrongWaAndWresultptr() {
        RelyingParty rp = RelyingParty.create(config());
        String quoted = URLEncoder.encode(StubIdp.wresult(), StandardCharsets.UTF_8);
        rejects(() -> rp.handleReply(Map.of("method", "GET", "url", "/wsfed?wa=wsignin1.0&wresult=" + quoted), null), "message", "POSTed");
        rejects(() -> rp.handleReply(Map.of("method", "POST", "url", "/wsfed", "body", Map.of("wa", "wattr1.0", "wresult", StubIdp.wresult())), null), "message", "not wsignin1.0");
        rejects(() -> rp.handleReply(Map.of("method", "POST", "url", "/wsfed", "body", Map.of("wa", "wsignin1.0", "wresultptr", "https://evil.test/")), null), "message", "wresultptr");
        rejects(() -> rp.handleReply(Map.of("method", "POST", "url", "/wsfed", "body", Map.of("wa", "wsignin1.0")), null), "message", "no wresult");
    }

    @Test
    void signOutCleanup() {
        RelyingParty rp = RelyingParty.create(config());
        assertTrue(rp.isSignOutCleanup(Map.of("method", "GET", "url", "/wsfed?wa=wsignoutcleanup1.0")));
        assertTrue(rp.isSignOutCleanup(Map.of("method", "POST", "url", "/wsfed", "body", "wa=wsignout1.0")));
        assertFalse(rp.isSignOutCleanup(Map.of("method", "POST", "url", "/wsfed", "body", Map.of("wa", "wsignin1.0"))));
        rejects(() -> rp.handleReply(Map.of("method", "GET", "url", "/wsfed?wa=wsignoutcleanup1.0"), null), "message", "sign-out");
    }

    private static String form(Map<String, String> fields) {
        StringBuilder out = new StringBuilder();
        for (Map.Entry<String, String> entry : fields.entrySet()) {
            if (out.length() > 0) out.append('&');
            out.append(URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8)).append('=').append(URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8));
        }
        return out.toString();
    }
}
