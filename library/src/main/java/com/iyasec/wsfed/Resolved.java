// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.wsfed;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Map;

/**
 * Configuration after file: and env: are read. signals is null when the receiver is on
 * (the key was omitted or true) and Boolean.FALSE when it is off.
 */
public final class Resolved {
    public String realm;
    public String replyUrl;
    public String idpMetadata;
    public long clockSkewMs = 60_000;
    public boolean wantAssertionsEncrypted;
    public boolean allowUnsolicited;
    public boolean requestTokenType = true;
    public Boolean signals;
    public PrivateKey privateKey;
    public X509Certificate certificate;
    public String idpCa;
    public String idpEntityId;
    /**
     * The {@code pep} section, with a relative {@code assertionKey} made absolute
     * against the configuration's directory. Null when the configuration has none.
     */
    public Map<String, Object> pep;
    /**
     * The Shared Signals receiver's own TLS client identity
     * ({@code ssf.clientCertificate}, a PEM chain with the leaf first, and
     * {@code ssf.clientKey}). Null when the configuration names none.
     */
    public String ssfClientCertificate;
    public String ssfClientKey;

    /**
     * The certificate chain and private key (PEM) the Shared Signals receiver
     * authenticates with: {@code ssf.clientCertificate} and {@code ssf.clientKey}
     * when set, else the relying party's own pair. Null when there is neither.
     */
    public String[] ssfTlsClient() {
        if (ssfClientCertificate != null && !ssfClientCertificate.isEmpty()
                && ssfClientKey != null && !ssfClientKey.isEmpty()) {
            return new String[] {ssfClientCertificate, ssfClientKey};
        }
        if (certificate == null || privateKey == null) return null;
        try {
            return new String[] {
                    Keys.pem("CERTIFICATE", certificate.getEncoded()),
                    Keys.pem("PRIVATE KEY", privateKey.getEncoded())
            };
        } catch (Exception err) {
            Caught.error(err);
            throw new WsFedError("config", "the relying party's key pair cannot be encoded", err);
        }
    }
}
