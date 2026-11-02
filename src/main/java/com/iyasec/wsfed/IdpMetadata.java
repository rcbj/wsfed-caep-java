// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.wsfed;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import org.w3c.dom.Element;

/** The identity provider's federation metadata, and this relying party's. */
public final class IdpMetadata {
    public final String entityId;
    public final String passiveRequestorEndpoint;
    public final List<String> tokenTypesOffered;
    public final List<X509Certificate> signingCertificates;

    public IdpMetadata(String entityId, String passiveRequestorEndpoint, List<String> tokenTypesOffered, List<X509Certificate> signingCertificates) {
        this.entityId = entityId;
        this.passiveRequestorEndpoint = passiveRequestorEndpoint;
        this.tokenTypesOffered = List.copyOf(tokenTypesOffered);
        this.signingCertificates = List.copyOf(signingCertificates);
    }

    public static IdpMetadata read(String xml, String entityId) {
        Element root = Xmls.parse(xml, "the identity provider metadata").getDocumentElement();
        Element entity = null;
        if (Xmls.is(root, Xmls.MD, "EntityDescriptor")) {
            entity = root;
        } else if (Xmls.is(root, Xmls.MD, "EntitiesDescriptor")) {
            List<Element> all = new ArrayList<>();
            for (Element item : Xmls.descendants(root, Xmls.MD, "EntityDescriptor")) {
                if (hasSts(item)) all.add(item);
            }
            if (entityId != null) {
                for (Element item : all) {
                    if (entityId.equals(Xmls.attr(item, "entityID"))) entity = item;
                }
            } else if (all.size() == 1) {
                entity = all.get(0);
            }
            if (entity == null) {
                if (entityId != null) throw new WsFedError("metadata", "the metadata aggregate has no WS-Federation identity provider " + entityId);
                throw new WsFedError("metadata", "the metadata aggregate holds " + all.size() + " WS-Federation identity providers; name one with idpEntityId");
            }
        } else {
            throw new WsFedError("metadata", "the identity provider metadata is not an EntityDescriptor");
        }
        String identifier = Xmls.attr(entity, "entityID");
        if (identifier == null || identifier.isEmpty()) throw new WsFedError("metadata", "the identity provider metadata has no entityID");
        if (entityId != null && !identifier.equals(entityId)) throw new WsFedError("metadata", "the metadata describes " + identifier + ", not " + entityId);
        Element role = null;
        for (Element item : Xmls.children(entity, Xmls.MD, "RoleDescriptor")) {
            if (isSts(item)) role = item;
        }
        if (role == null) {
            throw new WsFedError("metadata", identifier + "'s metadata has no fed:SecurityTokenServiceType RoleDescriptor, so it is not a WS-Federation identity provider");
        }
        List<String> passive = addresses(role, "PassiveRequestorEndpoint");
        if (passive.isEmpty()) throw new WsFedError("metadata", identifier + "'s metadata names no PassiveRequestorEndpoint");
        String endpoint = passive.get(0);
        String scheme = URI.create(endpoint).getScheme();
        if (!"https".equals(scheme) && !"http".equals(scheme)) {
            throw new WsFedError("metadata", identifier + "'s PassiveRequestorEndpoint " + endpoint + " is not an http(s) URL");
        }
        List<String> offered = new ArrayList<>();
        for (Element types : Xmls.children(role, Xmls.FED, "TokenTypesOffered")) {
            for (Element token : Xmls.children(types, Xmls.FED, "TokenType")) {
                String uri = Xmls.attr(token, "Uri");
                if (uri != null && !uri.isEmpty()) offered.add(uri);
            }
        }
        if (!offered.isEmpty() && offered.stream().noneMatch(Xmls::isSaml2Token)) {
            throw new WsFedError("metadata", identifier + " offers no SAML 2.0 token (it offers " + String.join(", ", offered) + ")");
        }
        List<X509Certificate> signing = certificates(role, "signing");
        if (signing.isEmpty()) {
            List<Element> idp = Xmls.children(entity, Xmls.MD, "IDPSSODescriptor");
            if (!idp.isEmpty()) signing = certificates(idp.get(0), "signing");
        }
        if (signing.isEmpty()) throw new WsFedError("metadata", identifier + "'s metadata names no signing certificate");
        return new IdpMetadata(identifier, endpoint, offered, signing);
    }

    public static String writeRp(String realm, String replyUrl, X509Certificate certificate) {
        String key = "";
        if (certificate != null) {
            String body = Xmls.pemBody(new String(java.util.Base64.getMimeEncoder(64, "\n".getBytes()).encode(certificate.getPublicKey() == null ? new byte[0] : encoded(certificate)), StandardCharsets.US_ASCII));
            try {
                body = Xmls.pemBody(new String(certificate.getEncoded() == null ? new byte[0] : pemOf(certificate).getBytes(StandardCharsets.US_ASCII), StandardCharsets.US_ASCII));
            } catch (Exception ignored) {
                body = "";
            }
            String pem = pemOf(certificate);
            body = Xmls.pemBody(pem);
            String methods = ""
                    + "\n      <md:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes256-gcm\"/>"
                    + "\n      <md:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes128-gcm\"/>"
                    + "\n      <md:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#rsa-oaep\"/>"
                    + "\n      <md:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\"/>";
            key = "    <md:KeyDescriptor use=\"encryption\">\n      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>"
                    + body + "</ds:X509Certificate></ds:X509Data></ds:KeyInfo>" + methods + "\n    </md:KeyDescriptor>\n";
        }
        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                + "<md:EntityDescriptor xmlns:md=\"" + Xmls.MD + "\" xmlns:ds=\"" + Xmls.DS + "\" xmlns:fed=\"" + Xmls.FED + "\" xmlns:wsa=\"" + Xmls.WSA + "\" xmlns:xsi=\"" + Xmls.XSI + "\" entityID=\"" + Xmls.escape(realm) + "\">\n"
                + "  <md:RoleDescriptor xsi:type=\"fed:ApplicationServiceType\" protocolSupportEnumeration=\"" + Xmls.FED + "\">\n"
                + key
                + "    <fed:TokenTypesOffered><fed:TokenType Uri=\"" + Xmls.SAML2_TOKEN + "\"/></fed:TokenTypesOffered>\n"
                + "    <fed:TargetScopes><wsa:EndpointReference><wsa:Address>" + Xmls.escape(realm) + "</wsa:Address></wsa:EndpointReference></fed:TargetScopes>\n"
                + endpoint("ApplicationServiceEndpoint", replyUrl) + "\n"
                + endpoint("SingleSignOutNotificationEndpoint", replyUrl) + "\n"
                + endpoint("PassiveRequestorEndpoint", replyUrl) + "\n"
                + "  </md:RoleDescriptor>\n</md:EntityDescriptor>\n";
    }

    private static String pemOf(X509Certificate certificate) {
        try {
            String body = java.util.Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(certificate.getEncoded());
            return "-----BEGIN CERTIFICATE-----\n" + body + "\n-----END CERTIFICATE-----\n";
        } catch (Exception err) {
            throw new WsFedError("metadata", "the relying party certificate cannot be encoded", err);
        }
    }

    private static byte[] encoded(X509Certificate certificate) {
        try { return certificate.getEncoded(); } catch (Exception err) { return new byte[0]; }
    }

    private static String endpoint(String local, String address) {
        return "    <fed:" + local + "><wsa:EndpointReference><wsa:Address>" + Xmls.escape(address) + "</wsa:Address></wsa:EndpointReference></fed:" + local + ">";
    }

    private static boolean hasSts(Element entity) {
        for (Element role : Xmls.children(entity, Xmls.MD, "RoleDescriptor")) if (isSts(role)) return true;
        return false;
    }

    private static boolean isSts(Element el) {
        String[] type = Xmls.xsiType(el);
        return type != null && Xmls.FED.equals(type[0]) && "SecurityTokenServiceType".equals(type[1]);
    }

    private static List<String> addresses(Element role, String local) {
        List<String> out = new ArrayList<>();
        for (Element endpoint : Xmls.children(role, Xmls.FED, local)) out.addAll(Xmls.wsaAddresses(endpoint));
        return out;
    }

    private static List<X509Certificate> certificates(Element role, String use) {
        List<X509Certificate> out = new ArrayList<>();
        for (Element descriptor : Xmls.children(role, Xmls.MD, "KeyDescriptor")) {
            String declared = Xmls.attr(descriptor, "use");
            if (declared != null && !declared.equals(use)) continue;
            for (Element data : Xmls.descendants(descriptor, Xmls.DS, "X509Data")) {
                List<Element> first = Xmls.children(data, Xmls.DS, "X509Certificate");
                if (first.isEmpty()) continue;
                try {
                    String pem = Xmls.toPem(Xmls.text(first.get(0)));
                    out.add((X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII))));
                } catch (Exception err) {
                    throw new WsFedError("metadata", "a " + use + " certificate in the identity provider's metadata cannot be read", err);
                }
            }
        }
        return out;
    }
}
