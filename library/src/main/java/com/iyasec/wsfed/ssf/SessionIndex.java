// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.wsfed.ssf;

import com.iyasec.wsfed.WsFedLogin;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

/** Which local sessions belong to which person and which identity-provider session. */
public final class SessionIndex {
    public static final String DEFAULT_SUBJECT_ATTRIBUTE = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier";
    public static final List<String> MAIL_ATTRIBUTES = List.of(
            "urn:oid:0.9.2342.19200300.100.1.3",
            "mail",
            "email",
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress");

    public static final class Session {
        public String localId;
        public String person;
        public String email;
        public String idpSession;
        public Instant expiresAt;
    }

    private final int max;
    private final Map<String, Session> sessions = new LinkedHashMap<>();

    public SessionIndex() {
        this(100_000);
    }

    public SessionIndex(int max) {
        this.max = max;
    }

    public void add(Session session) {
        if (sessions.size() >= max && !sessions.containsKey(session.localId)) {
            Instant now = Instant.now();
            Iterator<Map.Entry<String, Session>> it = sessions.entrySet().iterator();
            while (it.hasNext()) {
                Instant expires = it.next().getValue().expiresAt;
                if (expires != null && !expires.isAfter(now)) it.remove();
            }
            while (sessions.size() >= max) sessions.remove(sessions.keySet().iterator().next());
        }
        Session stored = session;
        if (stored.email != null) stored.email = stored.email.toLowerCase();
        sessions.put(session.localId, stored);
    }

    public void remove(String localId) {
        sessions.remove(localId);
    }

    public List<String> byPerson(String person) {
        return find(session -> person.equals(session.person));
    }

    public List<String> byEmail(String email) {
        String wanted = email.toLowerCase();
        return find(session -> wanted.equals(session.email));
    }

    public List<String> byIdpSession(String idpSession) {
        return find(session -> idpSession.equals(session.idpSession));
    }

    private List<String> find(Predicate<Session> match) {
        Instant now = Instant.now();
        List<String> out = new ArrayList<>();
        Iterator<Map.Entry<String, Session>> it = sessions.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, Session> entry = it.next();
            if (entry.getValue().expiresAt != null && !entry.getValue().expiresAt.isAfter(now)) {
                it.remove();
                continue;
            }
            if (match.test(entry.getValue())) out.add(entry.getKey());
        }
        return out;
    }

    public static Session trackedFrom(String localId, WsFedLogin login, String subjectAttribute, Instant expiresAt) {
        String attribute = subjectAttribute == null || subjectAttribute.isEmpty() ? DEFAULT_SUBJECT_ATTRIBUTE : subjectAttribute;
        Session session = new Session();
        session.localId = localId;
        List<String> people = login.attributes.get(attribute);
        session.person = people == null || people.isEmpty() ? null : people.get(0);
        String email = null;
        for (String name : MAIL_ATTRIBUTES) {
            List<String> values = login.attributes.get(name);
            if (values != null && !values.isEmpty() && values.get(0) != null && !values.get(0).isEmpty()) {
                email = values.get(0);
                break;
            }
        }
        if (email == null && "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".equals(login.nameIdFormat)) email = login.nameId;
        session.email = email;
        session.idpSession = login.sessionIndex;
        session.expiresAt = expiresAt != null ? expiresAt : login.sessionNotOnOrAfter;
        return session;
    }
}
