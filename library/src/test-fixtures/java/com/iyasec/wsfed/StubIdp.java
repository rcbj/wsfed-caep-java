// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.wsfed;

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/** A stub WS-Federation identity provider. It signs with the fixture key and the library's canonicalization. */
public final class StubIdp {
    public static final String IDP_ENTITY = "https://idp.test";
    public static final String PASSIVE = "https://idp.test/wsfed";
    public static final String REALM = "https://rp.test/";
    public static final String REPLY = "https://rp.test/wsfed";
    public static final String IDP_KEY = resource("idp.key");
    public static final String IDP_CERT = resource("idp.crt");
    public static final String RP_KEY = resource("rp.key");
    public static final String RP_CERT = resource("rp.crt");

    private static final String DS = Xmls.DS;
    private static final String XENC = Xmls.XENC;
    private static final String XENC11 = Xmls.XENC11;
    private static final String SAML = Xmls.SAML;
    private static final String CLAIMS = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims";
    private static final DateTimeFormatter ISO = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC);

    public static final class Made {
        public final String xml;
        public final String id;

        public Made(String xml, String id) {
            this.xml = xml;
            this.id = id;
        }
    }

    private StubIdp() {}

    public static String idpMetadata() {
        return idpMetadata("sts", null, "fed", false);
    }

    public static String idpMetadata(String keyIn, String[] tokenTypes, String fedPrefix, boolean noSts) {
        String fed = fedPrefix;
        String key = "<md:KeyDescriptor use=\"signing\"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>"
                + pemBody(IDP_CERT) + "</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>";
        String[] types = tokenTypes == null ? new String[] {"urn:oasis:names:tc:SAML:1.0:assertion", "urn:oasis:names:tc:SAML:2.0:assertion"} : tokenTypes;
        StringBuilder offered = new StringBuilder();
        for (String token : types) offered.append('<').append(fed).append(":TokenType Uri=\"").append(token).append("\"/>");
        String sts = noSts ? "" : "\n  <md:RoleDescriptor xsi:type=\"" + fed + ":SecurityTokenServiceType\" protocolSupportEnumeration=\"http://docs.oasis-open.org/wsfed/federation/200706\">"
                + ("idpsso".equals(keyIn) ? "" : key)
                + "<" + fed + ":TokenTypesOffered>" + offered + "</" + fed + ":TokenTypesOffered>"
                + "<" + fed + ":SecurityTokenServiceEndpoint><wsa:EndpointReference><wsa:Address>https://idp.test/sts</wsa:Address></wsa:EndpointReference></" + fed + ":SecurityTokenServiceEndpoint>"
                + "<" + fed + ":PassiveRequestorEndpoint><wsa:EndpointReference><wsa:Address>" + PASSIVE + "</wsa:Address></wsa:EndpointReference></" + fed + ":PassiveRequestorEndpoint>"
                + "</md:RoleDescriptor>";
        return "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"" + DS + "\" xmlns:" + fed
                + "=\"http://docs.oasis-open.org/wsfed/federation/200706\" xmlns:wsa=\"http://www.w3.org/2005/08/addressing\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" entityID=\""
                + IDP_ENTITY + "\">" + sts + "\n  <md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n    " + key
                + "\n    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://idp.test/saml2/sso\"/>\n  </md:IDPSSODescriptor>\n</md:EntityDescriptor>";
    }

    public static Made assertionXml(Options options) {
        Options o = options == null ? new Options() : options;
        String aid = "_" + hex(16);
        String recipientAttr = !o.recipientSet ? "" : (o.recipient == null ? "" : " Recipient=\"" + o.recipient + "\"");
        String irt = o.inResponseTo == null ? "" : " InResponseTo=\"" + o.inResponseTo + "\"";
        String confirmation = o.bareConfirmation
                ? "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"/>"
                : "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml:SubjectConfirmationData" + recipientAttr
                + " NotOnOrAfter=\"" + iso(o.notOnOrAfterMs) + "\"" + irt + "/></saml:SubjectConfirmation>";
        String expiry = o.noConditionsExpiry ? "" : " NotOnOrAfter=\"" + iso(o.notOnOrAfterMs) + "\"";
        String xml = "<saml:Assertion xmlns:saml=\"" + SAML + "\" ID=\"" + aid + "\" Version=\"2.0\" IssueInstant=\"" + iso(0) + "\">"
                + "<saml:Issuer>" + (o.issuer == null ? IDP_ENTITY : o.issuer) + "</saml:Issuer>"
                + "<saml:Subject><saml:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\">" + (o.nameId == null ? "alice-1234" : o.nameId) + "</saml:NameID>"
                + confirmation + "</saml:Subject>"
                + "<saml:Conditions NotBefore=\"" + iso(-5000) + "\"" + expiry + "><saml:AudienceRestriction><saml:Audience>"
                + (o.audience == null ? REALM : o.audience) + "</saml:Audience></saml:AudienceRestriction></saml:Conditions>"
                + "<saml:AttributeStatement><saml:Attribute Name=\"" + CLAIMS + "/nameidentifier\"><saml:AttributeValue>urn:uuid:alice</saml:AttributeValue></saml:Attribute>"
                + "<saml:Attribute Name=\"" + CLAIMS + "/emailaddress\" FriendlyName=\"mail\"><saml:AttributeValue>alice@example.com</saml:AttributeValue></saml:Attribute>"
                + "<saml:Attribute Name=\"http://schemas.microsoft.com/ws/2008/06/identity/claims/role\"><saml:AttributeValue>staff</saml:AttributeValue><saml:AttributeValue>admins</saml:AttributeValue></saml:Attribute>"
                + (o.extraAttributes == null ? "" : o.extraAttributes) + "</saml:AttributeStatement>"
                + "<saml:AuthnStatement AuthnInstant=\"" + iso(-1000) + "\" SessionIndex=\"" + (o.sessionIndex == null ? "_session1" : o.sessionIndex) + "\">"
                + "<saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>"
                + "</saml:Assertion>";
        return new Made(xml, aid);
    }

    public static Made signedAssertion(Options options) {
        Made made = assertionXml(options);
        return new Made(signXml(made.xml, made.id, IDP_KEY, IDP_CERT), made.id);
    }

    public static String signXml(String xml, String elementId, String keyPem, String certPem) {
        String current = xml;
        for (int pass = 0; pass < 2; pass++) {
            Document doc = Xmls.parse(current, "assertion");
            Element target = findId(doc.getDocumentElement(), elementId);
            if (target == null) throw new IllegalStateException("no element ID " + elementId);
            Element old = Xmls.child(target, DS, "Signature");
            if (old != null) old.getParentNode().removeChild(old);
            Element signature = signatureElement(doc, elementId, certPem);
            Element issuer = Xmls.child(target, SAML, "Issuer");
            if (issuer == null || issuer.getNextSibling() == null) target.appendChild(signature);
            else target.insertBefore(signature, issuer.getNextSibling());
            Element digest = first(signature, DS, "DigestValue");
            digest.setTextContent(Base64.getEncoder().encodeToString(sha256(referenceBytes(target, signature))));
            Element signedInfo = Xmls.child(signature, DS, "SignedInfo");
            byte[] info = XmlSignature.canonicalize(signedInfo, XmlSignature.EXC_C14N, null);
            try {
                Signature signer = Signature.getInstance("SHA256withRSA");
                signer.initSign(privateKey(keyPem));
                signer.update(info);
                first(signature, DS, "SignatureValue").setTextContent(Base64.getEncoder().encodeToString(signer.sign()));
            } catch (Exception err) {
                throw new IllegalStateException(err);
            }
            current = serialize(doc);
        }
        return current;
    }

    public static String encrypt(String plain) {
        return encrypt(plain, "aes-256-gcm", "mgf1p", "EncryptedAssertion");
    }

    public static String encrypt(String plain, String cipherName, String transport, String wrapper) {
        byte[] value;
        String alg;
        byte[] key;
        try {
            if ("aes-256-gcm".equals(cipherName)) {
                key = random(32);
                byte[] iv = random(12);
                Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
                aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
                value = concat(iv, aes.doFinal(plain.getBytes(StandardCharsets.UTF_8)));
                alg = "http://www.w3.org/2009/xmlenc11#aes256-gcm";
            } else if ("aes-128-cbc".equals(cipherName)) {
                key = random(16);
                byte[] iv = random(16);
                byte[] raw = plain.getBytes(StandardCharsets.UTF_8);
                int pad = 16 - (raw.length % 16);
                byte[] padded = new byte[raw.length + pad];
                System.arraycopy(raw, 0, padded, 0, raw.length);
                for (int i = raw.length; i < padded.length; i++) padded[i] = (byte) pad;
                Cipher aes = Cipher.getInstance("AES/CBC/NoPadding");
                aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
                value = concat(iv, aes.doFinal(padded));
                alg = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
            } else {
                throw new IllegalArgumentException(cipherName);
            }
            X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(RP_CERT.getBytes(StandardCharsets.US_ASCII)));
            String keyMethod;
            byte[] wrapped;
            Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
            if ("mgf1p".equals(transport)) {
                rsa.init(Cipher.ENCRYPT_MODE, certificate.getPublicKey(), new OAEPParameterSpec("SHA-1", "MGF1", java.security.spec.MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT));
                keyMethod = "<xenc:EncryptionMethod Algorithm=\"" + XENC + "rsa-oaep-mgf1p\"/>";
            } else if ("oaep256".equals(transport)) {
                rsa.init(Cipher.ENCRYPT_MODE, certificate.getPublicKey(), new OAEPParameterSpec("SHA-256", "MGF1", java.security.spec.MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
                keyMethod = "<xenc:EncryptionMethod Algorithm=\"" + XENC11 + "rsa-oaep\"><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>"
                        + "<xenc11:MGF xmlns:xenc11=\"" + XENC11 + "\" Algorithm=\"" + XENC11 + "mgf1sha256\"/></xenc:EncryptionMethod>";
            } else {
                throw new IllegalArgumentException(transport);
            }
            wrapped = rsa.doFinal(key);
            String data = "<xenc:EncryptedData xmlns:xenc=\"" + XENC + "\" Type=\"" + XENC + "Element\"><xenc:EncryptionMethod Algorithm=\"" + alg + "\"/>"
                    + "<ds:KeyInfo xmlns:ds=\"" + DS + "\"><xenc:EncryptedKey>" + keyMethod
                    + "<xenc:CipherData><xenc:CipherValue>" + Base64.getEncoder().encodeToString(wrapped) + "</xenc:CipherValue></xenc:CipherData>"
                    + "</xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>" + Base64.getEncoder().encodeToString(value)
                    + "</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>";
            if (wrapper == null) return data;
            return "<saml:" + wrapper + " xmlns:saml=\"" + SAML + "\">" + data + "</saml:" + wrapper + ">";
        } catch (RuntimeException err) {
            throw err;
        } catch (Exception err) {
            throw new IllegalStateException(err);
        }
    }

    public static String wresult() {
        return wresult(null, "2005", null, null, 3_600_000);
    }

    public static String wresult(String token, String trust, String appliesTo, String tokenType, int expiresMs) {
        String ns = "1.3".equals(trust) ? Xmls.TRUST13 : Xmls.TRUST2005;
        String body = token == null ? signedAssertion(null).xml : token;
        String wsu = Xmls.WSU;
        String rstr = "<t:RequestSecurityTokenResponse xmlns:t=\"" + ns + "\"><t:Lifetime><wsu:Created xmlns:wsu=\"" + wsu + "\">" + iso(0)
                + "</wsu:Created><wsu:Expires xmlns:wsu=\"" + wsu + "\">" + iso(expiresMs) + "</wsu:Expires></t:Lifetime>"
                + "<wsp:AppliesTo xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\"><wsa:EndpointReference xmlns:wsa=\"http://www.w3.org/2005/08/addressing\"><wsa:Address>"
                + (appliesTo == null ? REALM : appliesTo) + "</wsa:Address></wsa:EndpointReference></wsp:AppliesTo><t:RequestedSecurityToken>" + body
                + "</t:RequestedSecurityToken><t:TokenType>" + (tokenType == null ? "urn:oasis:names:tc:SAML:2.0:assertion" : tokenType) + "</t:TokenType>"
                + "<t:RequestType>" + ns + "/Issue</t:RequestType><t:KeyType>" + ns + "/Bearer</t:KeyType></t:RequestSecurityTokenResponse>";
        if ("1.3".equals(trust)) return "<t:RequestSecurityTokenResponseCollection xmlns:t=\"" + ns + "\">" + rstr + "</t:RequestSecurityTokenResponseCollection>";
        return rstr;
    }

    public static String saml11() {
        return "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:1.0:assertion\" MajorVersion=\"1\" MinorVersion=\"1\" AssertionID=\"" + "_" + hex(16)
                + "\" Issuer=\"" + IDP_ENTITY + "\" IssueInstant=\"" + iso(0) + "\"><saml:AttributeStatement><saml:Subject><saml:NameIdentifier>alice</saml:NameIdentifier></saml:Subject></saml:AttributeStatement></saml:Assertion>";
    }

    public static final class Options {
        public String audience;
        public String recipient = REPLY;
        public boolean recipientSet = true;
        public String inResponseTo;
        public int notOnOrAfterMs = 300_000;
        public String issuer;
        public String nameId;
        public String sessionIndex;
        public String extraAttributes = "";
        public boolean bareConfirmation;
        public boolean noConditionsExpiry;
    }

    private static Element signatureElement(Document doc, String elementId, String cert) {
        Element signature = doc.createElementNS(DS, "ds:Signature");
        Element signedInfo = child(doc, signature, "SignedInfo");
        child(doc, signedInfo, "CanonicalizationMethod").setAttribute("Algorithm", XmlSignature.EXC_C14N);
        child(doc, signedInfo, "SignatureMethod").setAttribute("Algorithm", XmlSignature.RSA_SHA256);
        Element reference = child(doc, signedInfo, "Reference");
        reference.setAttribute("URI", "#" + elementId);
        Element transforms = child(doc, reference, "Transforms");
        child(doc, transforms, "Transform").setAttribute("Algorithm", XmlSignature.ENVELOPED);
        child(doc, transforms, "Transform").setAttribute("Algorithm", XmlSignature.EXC_C14N);
        child(doc, reference, "DigestMethod").setAttribute("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256");
        child(doc, reference, "DigestValue");
        Element data = child(doc, child(doc, child(doc, signature, "KeyInfo"), "X509Data"), "X509Certificate");
        data.setTextContent(pemBody(cert));
        child(doc, signature, "SignatureValue");
        return signature;
    }

    private static Element child(Document doc, Element parent, String local) {
        Element element = doc.createElementNS(DS, "ds:" + local);
        parent.appendChild(element);
        return element;
    }

    private static byte[] referenceBytes(Element target, Element signature) {
        Node parent = signature.getParentNode();
        Node next = signature.getNextSibling();
        parent.removeChild(signature);
        try {
            return XmlSignature.canonicalize(target, XmlSignature.EXC_C14N, null);
        } finally {
            if (next != null) parent.insertBefore(signature, next);
            else parent.appendChild(signature);
        }
    }

    private static Element findId(Element el, String id) {
        if (id.equals(el.getAttribute("ID"))) return el;
        NodeList list = el.getChildNodes();
        for (int i = 0; i < list.getLength(); i++) {
            if (list.item(i) instanceof Element child) {
                Element found = findId(child, id);
                if (found != null) return found;
            }
        }
        return null;
    }

    private static Element first(Element root, String ns, String local) {
        return Xmls.descendants(root, ns, local).get(0);
    }

    private static String serialize(Document doc) {
        try {
            var transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
            StringWriter writer = new StringWriter();
            transformer.transform(new DOMSource(doc.getDocumentElement()), new StreamResult(writer));
            return writer.toString();
        } catch (Exception err) {
            throw new IllegalStateException(err);
        }
    }

    private static String iso(int offsetMs) {
        return ISO.format(Instant.now().plusMillis(offsetMs));
    }

    private static String pemBody(String pem) {
        return pem.replaceAll("-----(BEGIN|END) CERTIFICATE-----", "").replaceAll("\\s+", "");
    }

    private static PrivateKey privateKey(String pem) {
        try {
            return Config.privateKey(pem);
        } catch (Exception err) {
            throw new IllegalStateException(err);
        }
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception err) {
            throw new IllegalStateException(err);
        }
    }

    private static byte[] random(int n) {
        byte[] raw = new byte[n];
        new SecureRandom().nextBytes(raw);
        return raw;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static String hex(int bytes) {
        byte[] raw = random(bytes);
        StringBuilder out = new StringBuilder();
        for (byte b : raw) out.append(String.format("%02x", b));
        return out.toString();
    }

    private static String resource(String name) {
        try (var in = StubIdp.class.getClassLoader().getResourceAsStream(name)) {
            if (in == null) throw new IllegalStateException("missing fixture " + name);
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (RuntimeException err) {
            throw err;
        } catch (Exception err) {
            throw new IllegalStateException(err);
        }
    }
}
