// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.wsfed;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

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
}
