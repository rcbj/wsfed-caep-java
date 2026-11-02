// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.wsfed;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** A small JSON reader and writer. Configuration and Security Event Tokens use it. */
public final class Json {
    private Json() {}

    public static final class Num extends Number {
        private final String raw;

        public Num(String raw) {
            this.raw = raw;
        }

        public boolean integral() {
            return raw.indexOf('.') < 0 && raw.indexOf('e') < 0 && raw.indexOf('E') < 0;
        }

        @Override public int intValue() { return (int) longValue(); }
        @Override public long longValue() { return integral() ? Long.parseLong(raw) : (long) doubleValue(); }
        @Override public float floatValue() { return (float) doubleValue(); }
        @Override public double doubleValue() { return Double.parseDouble(raw); }
        @Override public String toString() { return raw; }
    }

    public static Object parse(String text) {
        Parser parser = new Parser(text);
        Object value = parser.value();
        parser.skip();
        if (parser.i != parser.s.length()) throw new WsFedError("config", "JSON has trailing text");
        return value;
    }

    public static String stringify(Object value) {
        StringBuilder out = new StringBuilder();
        write(out, value);
        return out.toString();
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> object(Object value) {
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) out.put(String.valueOf(entry.getKey()), entry.getValue());
            return out;
        }
        return null;
    }

    private static void write(StringBuilder out, Object value) {
        if (value == null) {
            out.append("null");
        } else if (value instanceof String text) {
            out.append('"');
            for (int i = 0; i < text.length(); i++) {
                char c = text.charAt(i);
                switch (c) {
                    case '"' -> out.append("\\\"");
                    case '\\' -> out.append("\\\\");
                    case '\b' -> out.append("\\b");
                    case '\f' -> out.append("\\f");
                    case '\n' -> out.append("\\n");
                    case '\r' -> out.append("\\r");
                    case '\t' -> out.append("\\t");
                    default -> {
                        if (c < 0x20) out.append(String.format("\\u%04x", (int) c));
                        else out.append(c);
                    }
                }
            }
            out.append('"');
        } else if (value instanceof Boolean || value instanceof Num) {
            out.append(value);
        } else if (value instanceof Number number) {
            out.append(number);
        } else if (value instanceof Map<?, ?> map) {
            out.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (!first) out.append(',');
                first = false;
                write(out, String.valueOf(entry.getKey()));
                out.append(':');
                write(out, entry.getValue());
            }
            out.append('}');
        } else if (value instanceof Iterable<?> list) {
            out.append('[');
            boolean first = true;
            for (Object item : list) {
                if (!first) out.append(',');
                first = false;
                write(out, item);
            }
            out.append(']');
        } else {
            write(out, String.valueOf(value));
        }
    }

    private static final class Parser {
        private final String s;
        private int i;

        private Parser(String s) {
            this.s = s == null ? "" : s;
        }

        private Object value() {
            skip();
            if (i >= s.length()) throw new WsFedError("config", "JSON ended early");
            char c = s.charAt(i);
            if (c == '{') return object();
            if (c == '[') return array();
            if (c == '"') return string();
            if (c == 't' || c == 'f') return bool();
            if (c == 'n') return nul();
            if (c == '-' || (c >= '0' && c <= '9')) return number();
            throw new WsFedError("config", "JSON has an unexpected character");
        }

        private Map<String, Object> object() {
            i++;
            Map<String, Object> out = new LinkedHashMap<>();
            skip();
            if (peek('}')) { i++; return out; }
            while (true) {
                skip();
                if (i >= s.length() || s.charAt(i) != '"') throw new WsFedError("config", "JSON object key is not a string");
                String key = string();
                skip();
                if (!peek(':')) throw new WsFedError("config", "JSON object is missing a colon");
                i++;
                out.put(key, value());
                skip();
                if (peek('}')) { i++; return out; }
                if (!peek(',')) throw new WsFedError("config", "JSON object is missing a comma");
                i++;
            }
        }

        private List<Object> array() {
            i++;
            List<Object> out = new ArrayList<>();
            skip();
            if (peek(']')) { i++; return out; }
            while (true) {
                out.add(value());
                skip();
                if (peek(']')) { i++; return out; }
                if (!peek(',')) throw new WsFedError("config", "JSON array is missing a comma");
                i++;
            }
        }

        private String string() {
            i++;
            StringBuilder out = new StringBuilder();
            while (i < s.length()) {
                char c = s.charAt(i++);
                if (c == '"') return out.toString();
                if (c == '\\') {
                    if (i >= s.length()) throw new WsFedError("config", "JSON string ended in an escape");
                    char e = s.charAt(i++);
                    switch (e) {
                        case '"', '\\', '/' -> out.append(e);
                        case 'b' -> out.append('\b');
                        case 'f' -> out.append('\f');
                        case 'n' -> out.append('\n');
                        case 'r' -> out.append('\r');
                        case 't' -> out.append('\t');
                        case 'u' -> {
                            if (i + 4 > s.length()) throw new WsFedError("config", "JSON unicode escape is short");
                            out.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                            i += 4;
                        }
                        default -> throw new WsFedError("config", "JSON string has an unknown escape");
                    }
                } else {
                    out.append(c);
                }
            }
            throw new WsFedError("config", "JSON string is not closed");
        }

        private Boolean bool() {
            if (s.startsWith("true", i)) { i += 4; return Boolean.TRUE; }
            if (s.startsWith("false", i)) { i += 5; return Boolean.FALSE; }
            throw new WsFedError("config", "JSON boolean is not true or false");
        }

        private Object nul() {
            if (s.startsWith("null", i)) { i += 4; return null; }
            throw new WsFedError("config", "JSON null is incomplete");
        }

        private Num number() {
            int start = i;
            if (peek('-')) i++;
            if (i >= s.length() || s.charAt(i) < '0' || s.charAt(i) > '9') throw new WsFedError("config", "JSON number is incomplete");
            if (s.charAt(i) == '0') i++;
            else while (i < s.length() && s.charAt(i) >= '0' && s.charAt(i) <= '9') i++;
            if (i < s.length() && s.charAt(i) == '.') {
                i++;
                while (i < s.length() && s.charAt(i) >= '0' && s.charAt(i) <= '9') i++;
            }
            if (i < s.length() && (s.charAt(i) == 'e' || s.charAt(i) == 'E')) {
                i++;
                if (i < s.length() && (s.charAt(i) == '+' || s.charAt(i) == '-')) i++;
                while (i < s.length() && s.charAt(i) >= '0' && s.charAt(i) <= '9') i++;
            }
            return new Num(s.substring(start, i));
        }

        private void skip() {
            while (i < s.length()) {
                char c = s.charAt(i);
                if (c != ' ' && c != '\n' && c != '\r' && c != '\t') return;
                i++;
            }
        }

        private boolean peek(char c) {
            return i < s.length() && s.charAt(i) == c;
        }
    }
}
