// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.wsfed;

import java.time.Instant;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

/** One process's memory of accepted assertion ids. */
public final class MemoryReplayCache {
    private final int max;
    private final Map<String, Long> entries = new LinkedHashMap<>();

    public MemoryReplayCache() {
        this(10_000);
    }

    public MemoryReplayCache(int max) {
        this.max = max;
    }

    /** @return true when this id is already live */
    public boolean checkAndRecord(String assertionId, Instant expiresAt) {
        long now = Instant.now().toEpochMilli();
        Long until = entries.get(assertionId);
        if (until != null && until > now) return true;
        if (entries.size() >= max) {
            Iterator<Map.Entry<String, Long>> it = entries.entrySet().iterator();
            while (it.hasNext()) {
                if (it.next().getValue() <= now) it.remove();
            }
            if (entries.size() >= max) {
                throw new RuntimeException("the replay cache holds " + max + " live assertions and cannot record another");
            }
        }
        entries.put(assertionId, expiresAt.toEpochMilli());
        return false;
    }
}
