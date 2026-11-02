// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.wsfed.ssf;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** CAEP, RISC, and SSF event types, and what an event subject names. */
public final class Events {
    public static final String CAEP = "https://schemas.openid.net/secevent/caep/event-type/";
    public static final String RISC = "https://schemas.openid.net/secevent/risc/event-type/";
    public static final String SSF = "https://schemas.openid.net/secevent/ssf/event-type/";

    public static final Map<String, String> EVENT = new LinkedHashMap<>();
    public static final List<String> CAEP_EVENTS = new ArrayList<>();
    public static final List<String> RISC_EVENTS = new ArrayList<>();
    public static final List<String> DEFAULT_EVENTS_REQUESTED = new ArrayList<>();
    public static final List<String> DEFAULT_ENDING_EVENTS = new ArrayList<>();

    static {
        put("session_revoked", CAEP + "session-revoked");
        put("token_claims_change", CAEP + "token-claims-change");
        put("credential_change", CAEP + "credential-change");
        put("assurance_level_change", CAEP + "assurance-level-change");
        put("device_compliance_change", CAEP + "device-compliance-change");
        put("session_established", CAEP + "session-established");
        put("session_presented", CAEP + "session-presented");
        put("risk_level_change", CAEP + "risk-level-change");
        put("account_credential_change_required", RISC + "account-credential-change-required");
        put("account_purged", RISC + "account-purged");
        put("account_disabled", RISC + "account-disabled");
        put("account_enabled", RISC + "account-enabled");
        put("identifier_changed", RISC + "identifier-changed");
        put("identifier_recycled", RISC + "identifier-recycled");
        put("credential_compromise", RISC + "credential-compromise");
        put("opt_in", RISC + "opt-in");
        put("opt_out_initiated", RISC + "opt-out-initiated");
        put("opt_out_cancelled", RISC + "opt-out-cancelled");
        put("opt_out_effective", RISC + "opt-out-effective");
        put("recovery_activated", RISC + "recovery-activated");
        put("recovery_information_changed", RISC + "recovery-information-changed");
        put("sessions_revoked", RISC + "sessions-revoked");
        put("verification", SSF + "verification");
        put("stream_updated", SSF + "stream-updated");
        for (String value : EVENT.values()) {
            if (value.startsWith(CAEP)) CAEP_EVENTS.add(value);
            if (value.startsWith(RISC)) RISC_EVENTS.add(value);
        }
        for (String name : List.of("session_revoked", "credential_change", "assurance_level_change", "token_claims_change",
                "account_disabled", "account_enabled", "account_purged", "credential_compromise", "sessions_revoked",
                "account_credential_change_required")) {
            DEFAULT_EVENTS_REQUESTED.add(EVENT.get(name));
        }
        for (String name : List.of("session_revoked", "account_disabled", "account_purged", "credential_compromise", "sessions_revoked")) {
            DEFAULT_ENDING_EVENTS.add(EVENT.get(name));
        }
    }

    private Events() {}

    private static void put(String name, String value) {
        EVENT.put(name, value);
    }

    @SuppressWarnings("unchecked")
    public static Map<String, String> subjectOf(Object subId, String issuer) {
        if (!(subId instanceof Map<?, ?> raw)) return Map.of();
        Map<String, Object> subject = (Map<String, Object>) raw;
        String format = formatOf(subject);
        Map<String, String> out = new LinkedHashMap<>();
        if ("complex".equals(format) || (format.isEmpty() && (subject.get("user") != null || subject.get("session") != null))) {
            Map<String, String> user = simple(subject.get("user"), issuer);
            Map<String, String> session = simple(subject.get("session"), issuer);
            if (user.get("sub") != null) out.put("person", user.get("sub"));
            if (user.get("email") != null) out.put("email", user.get("email"));
            String sessionId = session.get("opaque") != null ? session.get("opaque") : session.get("sub");
            if (sessionId != null) out.put("idp_session", sessionId);
            return out;
        }
        Map<String, String> one = simple(subject, issuer);
        if (one.get("sub") != null) out.put("person", one.get("sub"));
        if (one.get("email") != null) out.put("email", one.get("email"));
        return out;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, String> simple(Object identifier, String issuer) {
        if (!(identifier instanceof Map<?, ?> raw)) return Map.of();
        Map<String, Object> item = (Map<String, Object>) raw;
        String format = formatOf(item);
        if ("iss_sub".equals(format) && item.get("sub") instanceof String sub && (item.get("iss") == null || issuer.equals(item.get("iss")))) {
            return Map.of("sub", sub);
        }
        if ("email".equals(format) && item.get("email") instanceof String email) return Map.of("email", email);
        if ("opaque".equals(format) && item.get("id") instanceof String id) return Map.of("opaque", id);
        if ("aliases".equals(format) && item.get("identifiers") instanceof List<?> list) {
            Map<String, String> merged = new LinkedHashMap<>();
            for (Object child : list) merged.putAll(simple(child, issuer));
            return merged;
        }
        return Map.of();
    }

    private static String formatOf(Map<String, Object> item) {
        Object format = item.get("format") != null ? item.get("format") : item.get("subject_type");
        return format == null ? "" : String.valueOf(format);
    }
}
