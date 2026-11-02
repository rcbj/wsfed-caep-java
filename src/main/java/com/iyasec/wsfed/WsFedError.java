// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.wsfed;

/** A config, metadata, message, xml, signature, validation, replay, decryption, or ssf failure. */
public class WsFedError extends RuntimeException {
    public final String code;

    public WsFedError(String code, String message) {
        super(message);
        this.code = code;
    }

    public WsFedError(String code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }
}
