// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.wsfed;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/** XML read by this library. A DOCTYPE is refused before the parser sees it. */
public final class Xmls {
    public static final String SAML = "urn:oasis:names:tc:SAML:2.0:assertion";
    public static final String SAML1 = "urn:oasis:names:tc:SAML:1.0:assertion";
    public static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    public static final String DS = "http://www.w3.org/2000/09/xmldsig#";
    public static final String XENC = "http://www.w3.org/2001/04/xmlenc#";
    public static final String XENC11 = "http://www.w3.org/2009/xmlenc11#";
    public static final String XSI = "http://www.w3.org/2001/XMLSchema-instance";
    public static final String FED = "http://docs.oasis-open.org/wsfed/federation/200706";
    public static final String TRUST2005 = "http://schemas.xmlsoap.org/ws/2005/02/trust";
    public static final String TRUST13 = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
    public static final String WSA = "http://www.w3.org/2005/08/addressing";
    public static final String WSA2004 = "http://schemas.xmlsoap.org/ws/2004/08/addressing";
    public static final String WSP = "http://schemas.xmlsoap.org/ws/2004/09/policy";
    public static final String WSP15 = "http://www.w3.org/ns/ws-policy";
    public static final String WSU = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
    public static final String SAML2_TOKEN = "urn:oasis:names:tc:SAML:2.0:assertion";
    public static final String SAML2_TOKEN_WSS = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";
    public static final String CM_BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
    public static final String STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";

    private static final Pattern DOCTYPE = Pattern.compile("<!DOCTYPE|<!ENTITY", Pattern.CASE_INSENSITIVE);
    private static final Set<String> ID_NAMES = Set.of("ID", "Id", "id");

    private Xmls() {}

    public static boolean isSaml2Token(String value) {
        return SAML2_TOKEN.equals(value) || SAML2_TOKEN_WSS.equals(value);
    }

    public static Document parse(String text, String what) {
        if (text != null && DOCTYPE.matcher(text).find()) {
            throw new WsFedError("xml", what + " carries a DOCTYPE or an entity declaration, which WS-Federation never needs");
        }
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            factory.setExpandEntityReferences(false);
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            Document doc = factory.newDocumentBuilder().parse(new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8)));
            doc.getDocumentElement().normalize();
            return doc;
        } catch (WsFedError err) {
            throw err;
        } catch (Exception err) {
            Caught.error(err);
            throw new WsFedError("xml", what + " is not well-formed XML: " + err.getMessage(), err);
        }
    }

    public static boolean is(Element el, String ns, String local) {
        return el != null && ns.equals(el.getNamespaceURI()) && local.equals(el.getLocalName());
    }

    public static List<Element> children(Element el, String ns, String local) {
        List<Element> out = new ArrayList<>();
        if (el == null) return out;
        NodeList list = el.getChildNodes();
        for (int i = 0; i < list.getLength(); i++) {
            Node node = list.item(i);
            if (node instanceof Element child && ns.equals(child.getNamespaceURI()) && local.equals(child.getLocalName())) {
                out.add(child);
            }
        }
        return out;
    }

    public static Element child(Element el, String ns, String local) {
        List<Element> all = children(el, ns, local);
        return all.isEmpty() ? null : all.get(0);
    }

    public static List<Element> elementChildren(Element el) {
        List<Element> out = new ArrayList<>();
        NodeList list = el.getChildNodes();
        for (int i = 0; i < list.getLength(); i++) {
            if (list.item(i) instanceof Element child) out.add(child);
        }
        return out;
    }

    public static List<Element> descendants(Element el, String ns, String local) {
        List<Element> out = new ArrayList<>();
        NodeList list = el.getElementsByTagNameNS(ns, local);
        for (int i = 0; i < list.getLength(); i++) out.add((Element) list.item(i));
        return out;
    }

    public static String text(Element el) {
        if (el == null) return "";
        return el.getTextContent() == null ? "" : el.getTextContent().strip();
    }

    public static String attr(Element el, String name) {
        if (el == null || !el.hasAttribute(name)) return null;
        return el.getAttribute(name);
    }

    public static List<String> wsaAddresses(Element el) {
        List<String> out = new ArrayList<>();
        for (Element address : descendants(el, WSA, "Address")) {
            String value = text(address);
            if (!value.isEmpty()) out.add(value);
        }
        for (Element address : descendants(el, WSA2004, "Address")) {
            String value = text(address);
            if (!value.isEmpty()) out.add(value);
        }
        return out;
    }

    public static void assertUniqueIds(Element root) {
        Set<String> seen = new HashSet<>();
        walk(root, seen);
    }

    private static void walk(Element el, Set<String> seen) {
        var attrs = el.getAttributes();
        for (int i = 0; i < attrs.getLength(); i++) {
            Node attr = attrs.item(i);
            String local = attr.getLocalName() != null ? attr.getLocalName() : attr.getNodeName();
            if (!ID_NAMES.contains(local) || attr.getNodeValue() == null || attr.getNodeValue().isEmpty()) continue;
            if (!seen.add(attr.getNodeValue())) {
                throw new WsFedError("signature", "two elements carry the ID " + attr.getNodeValue());
            }
        }
        NodeList list = el.getChildNodes();
        for (int i = 0; i < list.getLength(); i++) {
            if (list.item(i) instanceof Element child) walk(child, seen);
        }
    }

    public static String escape(String value) {
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&apos;");
    }

    public static String pemBody(String pem) {
        return pem.replaceAll("-----(BEGIN|END) CERTIFICATE-----", "").replaceAll("\\s+", "");
    }

    public static String toPem(String b64) {
        String body = b64.replaceAll("\\s+", "");
        StringBuilder out = new StringBuilder("-----BEGIN CERTIFICATE-----\n");
        for (int i = 0; i < body.length(); i += 64) {
            out.append(body, i, Math.min(i + 64, body.length())).append('\n');
        }
        out.append("-----END CERTIFICATE-----\n");
        return out.toString();
    }

    /** xsi:type resolved by the prefix's namespace, not by the prefix text. */
    public static String[] xsiType(Element el) {
        String value = el.getAttributeNS(XSI, "type");
        if (value == null || value.isEmpty()) return null;
        String prefix = null;
        String local = value;
        int colon = value.indexOf(':');
        if (colon >= 0) {
            prefix = value.substring(0, colon).strip();
            local = value.substring(colon + 1).strip();
        }
        return new String[] {el.lookupNamespaceURI(prefix), local};
    }
}
