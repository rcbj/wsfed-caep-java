// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.wsfed;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import org.w3c.dom.Element;

/** Read a wresult and validate the SAML 2.0 assertion it carries. */
public final class TokenValidator {
    private static final Pattern UTC = Pattern.compile("^\\d{4}-\\d\\d-\\d\\dT\\d\\d:\\d\\d:\\d\\d(\\.\\d+)?Z$");

    public static final class Context {
        public String realm;
        public String replyUrl;
        public String idpEntityId;
        public List<X509Certificate> idpCertificates;
        public PrivateKey decryptionKey;
        public long clockSkewMs = 60_000;
        public boolean wantAssertionsEncrypted;
        public MemoryReplayCache replayCache;
        public Instant now;
    }

    private TokenValidator() {}

    public static WsFedLogin validate(String wresult, Context ctx) {
        Instant now = ctx.now == null ? Instant.now() : ctx.now;
        long skew = ctx.clockSkewMs;
        Element root = Xmls.parse(wresult, "wresult").getDocumentElement();
        Xmls.assertUniqueIds(root);
        Response response = responseOf(root);
        String tokenType = Xmls.text(Xmls.child(response.element, response.trust, "TokenType"));
        if (!tokenType.isEmpty() && !Xmls.isSaml2Token(tokenType)) {
            malformed("the response carries a token of type " + tokenType + "; this relying party accepts SAML 2.0 assertions only");
        }
        List<Element> applies = new ArrayList<>();
        applies.addAll(Xmls.children(response.element, Xmls.WSP, "AppliesTo"));
        applies.addAll(Xmls.children(response.element, Xmls.WSP15, "AppliesTo"));
        if (applies.size() > 1) malformed("the response has more than one AppliesTo");
        if (!applies.isEmpty()) {
            List<String> scopes = Xmls.wsaAddresses(applies.get(0));
            if (!scopes.isEmpty() && !scopes.contains(ctx.realm)) {
                invalid("the response applies to " + String.join(", ", scopes) + ", not to " + ctx.realm);
            }
        }
        Element lifetime = Xmls.child(response.element, response.trust, "Lifetime");
        Instant expires = null;
        if (lifetime != null) {
            String raw = Xmls.text(Xmls.child(lifetime, Xmls.WSU, "Expires"));
            expires = raw.isEmpty() ? null : instant(raw, "the response's Lifetime Expires");
        }
        if (expires != null && expires.toEpochMilli() <= now.toEpochMilli() - skew) {
            invalid("the response expired at " + iso(expires));
        }
        List<Element> requested = Xmls.children(response.element, response.trust, "RequestedSecurityToken");
        if (requested.size() != 1) {
            malformed("the response holds " + requested.size() + " RequestedSecurityToken elements; exactly one is accepted");
        }
        List<Element> tokens = Xmls.elementChildren(requested.get(0));
        if (tokens.size() != 1) malformed("the RequestedSecurityToken holds " + tokens.size() + " tokens; exactly one is accepted");
        Element token = tokens.get(0);
        boolean encrypted = false;
        Element assertion;
        if (Xmls.is(token, Xmls.SAML, "Assertion")) {
            if (ctx.wantAssertionsEncrypted) invalid("the assertion is not encrypted, and wantAssertionsEncrypted is on");
            assertion = token;
        } else if (Xmls.is(token, Xmls.SAML, "EncryptedAssertion") || Xmls.is(token, Xmls.XENC, "EncryptedData")) {
            if (ctx.decryptionKey == null) {
                throw new WsFedError("decryption", "the assertion is encrypted, and this relying party has no privateKey to decrypt it with");
            }
            encrypted = true;
            String assertionXml = XmlEncryption.decryptElement(token, ctx.decryptionKey);
            Element decrypted = Xmls.parse(assertionXml, "the decrypted assertion").getDocumentElement();
            Xmls.assertUniqueIds(decrypted);
            if (Xmls.is(decrypted, Xmls.SAML1, "Assertion")) {
                malformed("the encrypted token is a SAML 1.1 assertion; this relying party accepts SAML 2.0 assertions only");
            }
            if (!Xmls.is(decrypted, Xmls.SAML, "Assertion")) invalid("the encrypted token does not hold a SAML 2.0 Assertion");
            assertion = decrypted;
        } else if (Xmls.is(token, Xmls.SAML1, "Assertion")) {
            malformed("the token is a SAML 1.1 assertion; this relying party accepts SAML 2.0 assertions only. Ask for SAML 2.0 (requestTokenType, the default), or configure the identity provider to issue it to this realm");
            throw new AssertionError("unreachable");
        } else {
            malformed("the RequestedSecurityToken holds a <" + token.getLocalName() + ">, not a SAML 2.0 assertion");
            throw new AssertionError("unreachable");
        }
        String signed = XmlSignature.verify(assertion, ctx.idpCertificates, "the assertion");
        if (signed == null) invalid("the assertion is not signed; in WS-Federation its signature is the only one, so it is required");
        assertion = Xmls.parse(signed, "the signed assertion").getDocumentElement();
        if (!"2.0".equals(Xmls.attr(assertion, "Version"))) invalid("the assertion is not version 2.0");
        String assertionId = Xmls.attr(assertion, "ID");
        if (assertionId == null || assertionId.isEmpty()) invalid("the assertion has no ID");
        Element issuer = Xmls.child(assertion, Xmls.SAML, "Issuer");
        if (issuer == null) invalid("the assertion has no Issuer");
        String issuerFormat = Xmls.attr(issuer, "Format");
        if (issuerFormat != null && !issuerFormat.equals("urn:oasis:names:tc:SAML:2.0:nameid-format:entity")) {
            invalid("the assertion's Issuer has the Format " + issuerFormat);
        }
        if (!Xmls.text(issuer).equals(ctx.idpEntityId)) {
            invalid("the assertion was issued by " + Xmls.text(issuer) + ", not by " + ctx.idpEntityId);
        }
        Element subject = Xmls.child(assertion, Xmls.SAML, "Subject");
        if (subject == null) invalid("the assertion has no Subject");
        Element nameId = Xmls.child(subject, Xmls.SAML, "NameID");
        Element encryptedId = Xmls.child(subject, Xmls.SAML, "EncryptedID");
        if (nameId == null && encryptedId != null) {
            if (ctx.decryptionKey == null) {
                throw new WsFedError("decryption", "the NameID is encrypted, and this relying party has no privateKey to decrypt it with");
            }
            nameId = Xmls.parse(XmlEncryption.decryptElement(encryptedId, ctx.decryptionKey), "the decrypted NameID").getDocumentElement();
            if (!Xmls.is(nameId, Xmls.SAML, "NameID")) invalid("the EncryptedID does not hold a NameID");
        }
        if (nameId == null || Xmls.text(nameId).isEmpty()) invalid("the assertion's Subject has no NameID");
        Element conditions = Xmls.child(assertion, Xmls.SAML, "Conditions");
        if (conditions == null) invalid("the assertion has no Conditions, so it names no audience");
        Instant notBefore = instant(Xmls.attr(conditions, "NotBefore"), "Conditions NotBefore");
        Instant notOnOrAfter = instant(Xmls.attr(conditions, "NotOnOrAfter"), "Conditions NotOnOrAfter");
        List<String> reasons = new ArrayList<>();
        Instant confirmedUntil = null;
        for (Element confirmation : Xmls.children(subject, Xmls.SAML, "SubjectConfirmation")) {
            if (!Xmls.CM_BEARER.equals(Xmls.attr(confirmation, "Method"))) {
                reasons.add("method " + Xmls.attr(confirmation, "Method"));
                continue;
            }
            Element data = Xmls.child(confirmation, Xmls.SAML, "SubjectConfirmationData");
            if (data == null) {
                if (notOnOrAfter == null) {
                    reasons.add("no SubjectConfirmationData, and no Conditions NotOnOrAfter to bound it");
                    continue;
                }
                confirmedUntil = notOnOrAfter;
                break;
            }
            String recipient = Xmls.attr(data, "Recipient");
            Instant until = instant(Xmls.attr(data, "NotOnOrAfter"), "SubjectConfirmationData NotOnOrAfter");
            if (until == null) until = notOnOrAfter;
            if (recipient != null && !recipient.equals(ctx.replyUrl)) reasons.add("Recipient " + recipient);
            else if (until == null) reasons.add("no NotOnOrAfter, on the confirmation or the Conditions");
            else if (until.toEpochMilli() <= now.toEpochMilli() - skew) reasons.add("expired at " + iso(until));
            else if (Xmls.attr(data, "NotBefore") != null) reasons.add("a NotBefore, which a bearer confirmation must not have");
            else if (Xmls.attr(data, "InResponseTo") != null) {
                reasons.add("InResponseTo " + Xmls.attr(data, "InResponseTo") + ", which answers a SAML request, not a WS-Federation sign-in");
            } else {
                confirmedUntil = until;
                break;
            }
        }
        if (confirmedUntil == null) {
            invalid("no bearer SubjectConfirmation of the assertion fits: " + (reasons.isEmpty() ? "there is none" : String.join("; ", reasons)));
        }
        if (notBefore != null && notBefore.toEpochMilli() > now.toEpochMilli() + skew) invalid("the assertion is not valid before " + iso(notBefore));
        if (notOnOrAfter != null && notOnOrAfter.toEpochMilli() <= now.toEpochMilli() - skew) invalid("the assertion expired at " + iso(notOnOrAfter));
        List<Element> restrictions = Xmls.children(conditions, Xmls.SAML, "AudienceRestriction");
        if (restrictions.isEmpty()) invalid("the assertion has no AudienceRestriction");
        for (Element restriction : restrictions) {
            boolean ok = false;
            for (Element audience : Xmls.children(restriction, Xmls.SAML, "Audience")) {
                if (ctx.realm.equals(Xmls.text(audience))) ok = true;
            }
            if (!ok) invalid("the assertion is not for " + ctx.realm);
        }
        List<Element> authnAll = Xmls.children(assertion, Xmls.SAML, "AuthnStatement");
        if (authnAll.isEmpty()) invalid("the assertion has no AuthnStatement");
        Element authn = authnAll.get(0);
        Instant authnInstant = instant(Xmls.attr(authn, "AuthnInstant"), "AuthnInstant");
        if (authnInstant == null) invalid("the AuthnStatement has no AuthnInstant");
        Instant sessionNot = instant(Xmls.attr(authn, "SessionNotOnOrAfter"), "SessionNotOnOrAfter");
        if (sessionNot != null && sessionNot.toEpochMilli() <= now.toEpochMilli() - skew) invalid("the identity provider's session has already ended");
        Element contextEl = Xmls.child(authn, Xmls.SAML, "AuthnContext");
        String classRef = contextEl == null ? "" : Xmls.text(Xmls.child(contextEl, Xmls.SAML, "AuthnContextClassRef"));
        Map<String, List<String>> attributes = new LinkedHashMap<>();
        Map<String, String> friendly = new LinkedHashMap<>();
        for (Element statement : Xmls.children(assertion, Xmls.SAML, "AttributeStatement")) {
            List<Element> decrypted = new ArrayList<>();
            for (Element encryptedAttr : Xmls.children(statement, Xmls.SAML, "EncryptedAttribute")) {
                if (ctx.decryptionKey == null) {
                    throw new WsFedError("decryption", "an attribute is encrypted, and this relying party has no privateKey to decrypt it with");
                }
                Element element = Xmls.parse(XmlEncryption.decryptElement(encryptedAttr, ctx.decryptionKey), "the decrypted attribute").getDocumentElement();
                if (!Xmls.is(element, Xmls.SAML, "Attribute")) invalid("an EncryptedAttribute does not hold an Attribute");
                decrypted.add(element);
            }
            List<Element> all = new ArrayList<>(Xmls.children(statement, Xmls.SAML, "Attribute"));
            all.addAll(decrypted);
            for (Element attribute : all) {
                String name = Xmls.attr(attribute, "Name");
                if (name == null || name.isEmpty()) continue;
                List<String> values = attributes.computeIfAbsent(name, key -> new ArrayList<>());
                for (Element value : Xmls.children(attribute, Xmls.SAML, "AttributeValue")) values.add(Xmls.text(value));
                String friendlyName = Xmls.attr(attribute, "FriendlyName");
                if (friendlyName != null) friendly.put(name, friendlyName);
            }
        }
        long keepMs = Math.max(confirmedUntil.toEpochMilli(), notOnOrAfter == null ? 0 : notOnOrAfter.toEpochMilli()) + skew;
        boolean recorded = ctx.replayCache.checkAndRecord(ctx.idpEntityId + " " + assertionId, Instant.ofEpochMilli(keepMs));
        if (recorded) throw new WsFedError("replay", "the assertion " + assertionId + " has been accepted before");
        WsFedLogin login = new WsFedLogin();
        login.nameId = Xmls.text(nameId);
        login.authnInstant = authnInstant;
        login.attributes = attributes;
        login.attributeFriendlyNames = friendly;
        login.issuer = ctx.idpEntityId;
        login.realm = ctx.realm;
        login.trustVersion = response.version;
        login.encrypted = encrypted;
        login.assertionId = assertionId;
        login.notOnOrAfter = confirmedUntil;
        login.nameIdFormat = Xmls.attr(nameId, "Format");
        login.nameQualifier = Xmls.attr(nameId, "NameQualifier");
        login.spNameQualifier = Xmls.attr(nameId, "SPNameQualifier");
        login.sessionIndex = Xmls.attr(authn, "SessionIndex");
        login.sessionNotOnOrAfter = sessionNot;
        login.authnContextClassRef = classRef.isEmpty() ? null : classRef;
        return login;
    }

    private static Instant instant(String value, String what) {
        if (value == null || value.isEmpty()) return null;
        if (!UTC.matcher(value).matches()) invalid(what + " is not a UTC dateTime: " + value);
        try {
            return OffsetDateTime.parse(value.replace("Z", "+00:00")).toInstant();
        } catch (Exception err) {
            Caught.error(err);
            invalid(what + " is not a dateTime: " + value);
            return null;
        }
    }

    private static String iso(Instant moment) {
        return DateTimeFormatter.ISO_INSTANT.format(moment.truncatedTo(ChronoUnit.MILLIS));
    }

    private static void invalid(String message) { throw new WsFedError("validation", message); }
    private static void malformed(String message) { throw new WsFedError("message", message); }

    private record Response(Element element, String trust, String version) {}

    private static Response responseOf(Element root) {
        if (Xmls.is(root, Xmls.TRUST13, "RequestSecurityTokenResponseCollection")) {
            List<Element> all = Xmls.children(root, Xmls.TRUST13, "RequestSecurityTokenResponse");
            if (all.size() != 1) malformed("the RequestSecurityTokenResponseCollection holds " + all.size() + " responses; exactly one is accepted");
            return new Response(all.get(0), Xmls.TRUST13, "1.3");
        }
        if (Xmls.is(root, Xmls.TRUST2005, "RequestSecurityTokenResponse")) return new Response(root, Xmls.TRUST2005, "2005/02");
        if (Xmls.is(root, Xmls.TRUST13, "RequestSecurityTokenResponse")) return new Response(root, Xmls.TRUST13, "1.3");
        String ns = root.getNamespaceURI() == null ? "no namespace" : root.getNamespaceURI();
        malformed("wresult is a <" + root.getLocalName() + "> in " + ns + ", not a WS-Trust RequestSecurityTokenResponse");
        throw new AssertionError("unreachable");
    }
}
