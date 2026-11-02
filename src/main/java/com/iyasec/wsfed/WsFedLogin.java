// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.wsfed;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Who signed in. Optional fields stay null when the assertion did not carry them. */
public final class WsFedLogin {
    public String nameId;
    public String nameIdFormat;
    public String nameQualifier;
    public String spNameQualifier;
    public Instant authnInstant;
    public String sessionIndex;
    public Instant sessionNotOnOrAfter;
    public String authnContextClassRef;
    public Map<String, List<String>> attributes = new LinkedHashMap<>();
    public Map<String, String> attributeFriendlyNames = new LinkedHashMap<>();
    public String issuer;
    public String realm;
    public String trustVersion;
    public boolean encrypted;
    public String assertionId;
    public Instant notOnOrAfter;
    public String requestId;
    public String relayState;
}
