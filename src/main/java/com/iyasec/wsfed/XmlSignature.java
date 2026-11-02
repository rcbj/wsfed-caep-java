// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.wsfed;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.xml.security.c14n.Canonicalizer;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/** Enveloped XML Signature. The signed bytes are what is read afterwards. KeyInfo is not trusted. */
public final class XmlSignature {
    public static final String EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#";
    public static final String EXC_C14N_COMMENTS = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
    public static final String C14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    public static final String C14N_COMMENTS = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
    public static final String ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
    public static final String RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

    private static final Map<String, String> SIGNATURES = Map.of(
            RSA_SHA256, "SHA256withRSA",
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", "SHA384withRSA",
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", "SHA512withRSA");
    private static final Map<String, String> DIGESTS = Map.of(
            "http://www.w3.org/2001/04/xmlenc#sha256", "SHA-256",
            "http://www.w3.org/2001/04/xmldsig-more#sha384", "SHA-384",
            "http://www.w3.org/2001/04/xmlenc#sha512", "SHA-512");
    private static final Set<String> TRANSFORMS = Set.of(ENVELOPED, EXC_C14N, EXC_C14N_COMMENTS, C14N, C14N_COMMENTS);
    private static final Set<String> CANONICALIZATIONS = Set.of(EXC_C14N, EXC_C14N_COMMENTS, C14N, C14N_COMMENTS);

    static {
        org.apache.xml.security.Init.init();
    }

    private XmlSignature() {}

    public static byte[] canonicalize(Node node, String algorithm, String inclusivePrefixes) {
        try {
            Canonicalizer canonicalizer = Canonicalizer.getInstance(algorithm);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            if (algorithm.startsWith(EXC_C14N)) {
                canonicalizer.canonicalizeSubtree(node, inclusivePrefixes == null ? "" : inclusivePrefixes, out);
            } else {
                canonicalizer.canonicalizeSubtree(node, out);
            }
            return out.toByteArray();
        } catch (Exception err) {
            throw new WsFedError("signature", "canonicalization failed: " + err.getMessage(), err);
        }
    }

    /** @return the canonical XML that was signed, or null when the element is unsigned */
    public static String verify(Element element, List<X509Certificate> certs, String what) {
        Element signature = Xmls.child(element, Xmls.DS, "Signature");
        if (signature == null) return null;
        String elementId = Xmls.attr(element, "ID");
        if (elementId == null || elementId.isEmpty()) {
            throw new WsFedError("signature", what + " is signed but has no ID for the signature to refer to");
        }
        Element signedInfo = Xmls.child(signature, Xmls.DS, "SignedInfo");
        if (signedInfo == null) throw new WsFedError("signature", what + "'s signature has no SignedInfo");
        String c14nAlg = algorithmOf(signedInfo, "CanonicalizationMethod");
        if (!CANONICALIZATIONS.contains(c14nAlg)) {
            throw new WsFedError("signature", what + "'s signature uses the canonicalization " + (c14nAlg.isEmpty() ? "(none)" : c14nAlg) + ", which is refused");
        }
        String sigAlg = algorithmOf(signedInfo, "SignatureMethod");
        String jca = SIGNATURES.get(sigAlg);
        if (jca == null) {
            throw new WsFedError("signature", what + "'s signature uses " + (sigAlg.isEmpty() ? "(none)" : sigAlg) + ", which is refused (SHA-1 and non-RSA algorithms are not accepted)");
        }
        List<Element> refs = Xmls.children(signedInfo, Xmls.DS, "Reference");
        if (refs.size() != 1) {
            throw new WsFedError("signature", what + "'s signature has " + refs.size() + " references; exactly one is accepted");
        }
        Element ref = refs.get(0);
        if (!("#" + elementId).equals(Xmls.attr(ref, "URI"))) {
            throw new WsFedError("signature", what + "'s signature refers to " + (Xmls.attr(ref, "URI") == null ? "(nothing)" : Xmls.attr(ref, "URI")) + ", not to " + what + " itself (#" + elementId + ")");
        }
        String digestAlg = algorithmOf(ref, "DigestMethod");
        if (!DIGESTS.containsKey(digestAlg)) {
            throw new WsFedError("signature", what + "'s signature digests with " + (digestAlg.isEmpty() ? "(none)" : digestAlg) + ", which is refused");
        }
        Element transforms = Xmls.child(ref, Xmls.DS, "Transforms");
        List<Element> transformEls = transforms == null ? List.of() : Xmls.children(transforms, Xmls.DS, "Transform");
        String refAlgorithm = EXC_C14N;
        String prefixes = null;
        boolean enveloped = false;
        for (Element transform : transformEls) {
            String alg = Xmls.attr(transform, "Algorithm");
            if (alg == null || !TRANSFORMS.contains(alg)) {
                throw new WsFedError("signature", what + "'s signature uses the transform " + (alg == null || alg.isEmpty() ? "(none)" : alg) + ", which is refused");
            }
            if (ENVELOPED.equals(alg)) enveloped = true;
            else if (CANONICALIZATIONS.contains(alg)) {
                refAlgorithm = alg;
                prefixes = prefixesOf(transform);
            }
        }
        if (certs == null || certs.isEmpty()) {
            throw new WsFedError("signature", "no signing certificate is known for the identity provider, so " + what + " cannot be verified");
        }
        byte[] refC14n = referenceC14n(element, signature, enveloped, refAlgorithm, prefixes);
        byte[] got;
        try {
            got = MessageDigest.getInstance(DIGESTS.get(digestAlg)).digest(refC14n);
        } catch (Exception err) {
            throw new WsFedError("signature", what + "'s digest could not be computed", err);
        }
        if (!java.util.Arrays.equals(got, b64(Xmls.child(ref, Xmls.DS, "DigestValue")))) {
            throw new WsFedError("signature", what + "'s signature does not verify against the identity provider's certificate: the signature does not verify");
        }
        byte[] info = canonicalize(signedInfo, c14nAlg, prefixesOf(Xmls.child(signedInfo, Xmls.DS, "CanonicalizationMethod")));
        byte[] signatureBytes = b64(Xmls.child(signature, Xmls.DS, "SignatureValue"));
        String reason = "the signature does not verify";
        for (X509Certificate cert : certs) {
            try {
                Signature verifier = Signature.getInstance(jca);
                verifier.initVerify(cert.getPublicKey());
                verifier.update(info);
                if (verifier.verify(signatureBytes)) return new String(refC14n, StandardCharsets.UTF_8);
            } catch (Exception err) {
                reason = err.getMessage();
            }
        }
        throw new WsFedError("signature", what + "'s signature does not verify against the identity provider's certificate: " + reason);
    }

    private static byte[] referenceC14n(Element element, Element signature, boolean enveloped, String algorithm, String prefixes) {
        Node parent = signature.getParentNode();
        Node next = signature.getNextSibling();
        if (enveloped && parent != null) parent.removeChild(signature);
        try {
            return canonicalize(element, algorithm, prefixes);
        } finally {
            if (enveloped && parent != null && signature.getParentNode() == null) {
                if (next != null) parent.insertBefore(signature, next);
                else parent.appendChild(signature);
            }
        }
    }

    private static String algorithmOf(Element parent, String local) {
        Element element = Xmls.child(parent, Xmls.DS, local);
        String value = element == null ? null : Xmls.attr(element, "Algorithm");
        return value == null ? "" : value;
    }

    private static String prefixesOf(Element method) {
        if (method == null) return null;
        Node node = method.getFirstChild();
        while (node != null) {
            if (node instanceof Element el && "InclusiveNamespaces".equals(el.getLocalName())) {
                return el.getAttribute("PrefixList");
            }
            node = node.getNextSibling();
        }
        return null;
    }

    private static byte[] b64(Element element) {
        String raw = element == null || element.getTextContent() == null ? "" : element.getTextContent().replaceAll("\\s+", "");
        return Base64.getMimeDecoder().decode(raw);
    }
}
