/* SPDX-License-Identifier: MIT */
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>

static void oom(void) { fputs("[forge] out of memory\n", stderr); exit(1); }

void buf_init(Buf *b) { b->p = NULL; b->len = 0; b->cap = 0; }
void buf_free(Buf *b) { free(b->p); b->p = NULL; b->len = b->cap = 0; }
void buf_reset(Buf *b) { b->len = 0; if (b->p) b->p[0] = '\0'; }

static void buf_term(Buf *b) { if (b->p && b->len < b->cap) b->p[b->len] = '\0'; }

void buf_reserve(Buf *b, size_t extra) {
    if (b->len + extra + 1 <= b->cap) return;   /* keep room for a terminating NUL */
    size_t cap = b->cap ? b->cap : 256;
    while (cap < b->len + extra + 1) cap = cap + (cap >> 1) + 64;
    char *np = (char *)realloc(b->p, cap);
    if (!np) oom();
    b->p = np; b->cap = cap;
}

void buf_add(Buf *b, const void *data, size_t len) {
    if (!len) { buf_reserve(b, 0); buf_term(b); return; }
    buf_reserve(b, len);
    memcpy(b->p + b->len, data, len);
    b->len += len;
    buf_term(b);
}

void buf_addc(Buf *b, char c) { buf_reserve(b, 1); b->p[b->len++] = c; buf_term(b); }
void buf_adds(Buf *b, const char *s) { buf_add(b, s, strlen(s)); }
void buf_addn(Buf *b, const char *s, size_t n) { buf_add(b, s, n); }

void buf_addf(Buf *b, const char *fmt, ...) {
    char tmp[512];
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof tmp, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if ((size_t)n < sizeof tmp) { buf_add(b, tmp, (size_t)n); return; }
    char *big = (char *)malloc((size_t)n + 1);
    if (!big) oom();
    va_start(ap, fmt);
    vsnprintf(big, (size_t)n + 1, fmt, ap);
    va_end(ap);
    buf_add(b, big, (size_t)n);
    free(big);
}

void buf_json_strn(Buf *b, const char *s, size_t n) {
    buf_addc(b, '"');
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
            case '"':  buf_adds(b, "\\\""); break;
            case '\\': buf_adds(b, "\\\\"); break;
            case '\n': buf_adds(b, "\\n"); break;
            case '\r': buf_adds(b, "\\r"); break;
            case '\t': buf_adds(b, "\\t"); break;
            case '\b': buf_adds(b, "\\b"); break;
            case '\f': buf_adds(b, "\\f"); break;
            default:
                if (c < 0x20) buf_addf(b, "\\u%04x", c);
                else buf_addc(b, (char)c);
        }
    }
    buf_addc(b, '"');
}
void buf_json_str(Buf *b, const char *s) { buf_json_strn(b, s, strlen(s)); }

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
size_t b64_encoded_len(size_t n) { return ((n + 2) / 3) * 4; }

void b64_encode(Buf *out, const unsigned char *in, size_t n) {
    buf_reserve(out, b64_encoded_len(n));
    size_t i = 0;
    while (i + 3 <= n) {
        uint32_t v = (uint32_t)in[i] << 16 | (uint32_t)in[i + 1] << 8 | in[i + 2];
        buf_addc(out, B64[(v >> 18) & 63]);
        buf_addc(out, B64[(v >> 12) & 63]);
        buf_addc(out, B64[(v >> 6) & 63]);
        buf_addc(out, B64[v & 63]);
        i += 3;
    }
    if (n - i == 1) {
        uint32_t v = (uint32_t)in[i] << 16;
        buf_addc(out, B64[(v >> 18) & 63]);
        buf_addc(out, B64[(v >> 12) & 63]);
        buf_addc(out, '='); buf_addc(out, '=');
    } else if (n - i == 2) {
        uint32_t v = (uint32_t)in[i] << 16 | (uint32_t)in[i + 1] << 8;
        buf_addc(out, B64[(v >> 18) & 63]);
        buf_addc(out, B64[(v >> 12) & 63]);
        buf_addc(out, B64[(v >> 6) & 63]);
        buf_addc(out, '=');
    }
}

static int b64val(int c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

int b64_is_valid(const char *in, size_t n) {
    if (n % 4 != 0) return 0;
    for (size_t i = 0; i < n; i++) {
        char c = in[i];
        if (c == '=' ) continue;
        if (c == '\n' || c == '\r' || c == ' ') continue;
        if (b64val((unsigned char)c) < 0) return 0;
    }
    return 1;
}

/* Tolerant base64: skips whitespace, accepts missing padding. */
int b64_decode(Buf *out, const char *in, size_t n) {
    int quad[4]; int qn = 0;
    for (size_t i = 0; i < n; i++) {
        char c = in[i];
        if (c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
        if (c == '=') {
            /* flush with whatever we have */
            if (qn == 2) { uint32_t v = (uint32_t)quad[0] << 6 | quad[1]; buf_addc(out, (char)((v >> 4) & 0xff)); }
            else if (qn == 3) { uint32_t v = (uint32_t)quad[0] << 12 | quad[1] << 6 | quad[2]; buf_addc(out, (char)((v >> 10) & 0xff)); buf_addc(out, (char)((v >> 2) & 0xff)); }
            qn = 0;
            continue;
        }
        int v = b64val((unsigned char)c);
        if (v < 0) return -1;
        quad[qn++] = v;
        if (qn == 4) {
            uint32_t x = (uint32_t)quad[0] << 18 | (uint32_t)quad[1] << 12 | (uint32_t)quad[2] << 6 | quad[3];
            buf_addc(out, (char)((x >> 16) & 0xff));
            buf_addc(out, (char)((x >> 8) & 0xff));
            buf_addc(out, (char)(x & 0xff));
            qn = 0;
        }
    }
    if (qn == 2) { uint32_t v = (uint32_t)quad[0] << 6 | quad[1]; buf_addc(out, (char)((v >> 4) & 0xff)); }
    else if (qn == 3) { uint32_t v = (uint32_t)quad[0] << 12 | quad[1] << 6 | quad[2]; buf_addc(out, (char)((v >> 10) & 0xff)); buf_addc(out, (char)((v >> 2) & 0xff)); }
    return 0;
}

static const char *skip_ws(const char *s, const char *end) {
    while (s < end && (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r')) s++;
    return s;
}

int json_is_object(const char *body, size_t len) {
    const char *s = skip_ws(body, body + len);
    return s < body + len && *s == '{';
}

/* Find a top-level key in a JSON object and return the raw value span (without trailing ws).
   Handles nested strings/objects/arrays. Returns 1 on success. */
int json_find(const char *body, size_t len, const char *key, const char **val, size_t *vlen) {
    const char *s = body, *end = body + len;
    s = skip_ws(s, end);
    if (s >= end || *s != '{') return 0;
    s++;
    size_t klen = strlen(key);
    while (s < end) {
        s = skip_ws(s, end);
        if (s >= end) return 0;
        if (*s == '}') return 0;
        if (*s == ',') { s++; continue; }
        if (*s != '"') return 0;
        s++;
        const char *kstart = s;
        while (s < end && *s != '"') { if (*s == '\\') s++; s++; }
        size_t this_klen = (size_t)(s - kstart);
        if (s < end) s++; /* closing quote */
        s = skip_ws(s, end);
        if (s >= end || *s != ':') return 0;
        s++;
        s = skip_ws(s, end);
        const char *vstart = s;
        /* scan value */
        if (s < end && *s == '"') {
            s++;
            while (s < end && *s != '"') { if (*s == '\\') s++; s++; }
            if (s < end) s++;
        } else if (s < end && (*s == '{' || *s == '[')) {
            char open = *s, close = open == '{' ? '}' : ']';
            int depth = 0;
            while (s < end) {
                if (*s == '"') { s++; while (s < end && *s != '"') { if (*s == '\\') s++; s++; } if (s < end) s++; continue; }
                if (*s == open) depth++;
                else if (*s == close) { depth--; if (depth == 0) { s++; break; } }
                s++;
            }
        } else {
            while (s < end && *s != ',' && *s != '}') s++;
        }
        const char *vend = s;
        while (vend > vstart && (vend[-1] == ' ' || vend[-1] == '\t' || vend[-1] == '\n' || vend[-1] == '\r')) vend--;
        if (this_klen == klen && memcmp(kstart, key, klen) == 0) {
            *val = vstart; *vlen = (size_t)(vend - vstart);
            return 1;
        }
    }
    return 0;
}

int json_unescape(const char *s, size_t n, Buf *out) {
    if (n < 2 || s[0] != '"' || s[n - 1] != '"') return -1;
    s++; n -= 2;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (c != '\\') { buf_addc(out, c); continue; }
        if (++i >= n) return -1;
        char e = s[i];
        switch (e) {
            case '"': buf_addc(out, '"'); break;
            case '\\': buf_addc(out, '\\'); break;
            case '/': buf_addc(out, '/'); break;
            case 'n': buf_addc(out, '\n'); break;
            case 't': buf_addc(out, '\t'); break;
            case 'r': buf_addc(out, '\r'); break;
            case 'b': buf_addc(out, '\b'); break;
            case 'f': buf_addc(out, '\f'); break;
            case 'u': {
                if (i + 4 >= n) return -1;
                unsigned cp = 0;
                for (int k = 1; k <= 4; k++) {
                    int hv; char h = s[i + k];
                    if (h >= '0' && h <= '9') hv = h - '0';
                    else if (h >= 'a' && h <= 'f') hv = h - 'a' + 10;
                    else if (h >= 'A' && h <= 'F') hv = h - 'A' + 10;
                    else return -1;
                    cp = cp * 16 + (unsigned)hv;
                }
                i += 4;
                if (cp < 0x80) buf_addc(out, (char)cp);
                else if (cp < 0x800) {
                    buf_addc(out, (char)(0xC0 | (cp >> 6)));
                    buf_addc(out, (char)(0x80 | (cp & 0x3F)));
                } else {
                    buf_addc(out, (char)(0xE0 | (cp >> 12)));
                    buf_addc(out, (char)(0x80 | ((cp >> 6) & 0x3F)));
                    buf_addc(out, (char)(0x80 | (cp & 0x3F)));
                }
                break;
            }
            default: return -1;
        }
    }
    return 0;
}

int ci_eq(const char *a, const char *b) {
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return 0;
        a++; b++;
    }
    return *a == '\0' && *b == '\0';
}

int ci_prefix(const char *a, const char *pfx) {
    while (*pfx) {
        if (!*a) return 0;
        if (tolower((unsigned char)*a) != tolower((unsigned char)*pfx)) return 0;
        a++; pfx++;
    }
    return 1;
}

char *xstrdup(const char *s) { size_t n = strlen(s); char *p = (char *)malloc(n + 1); if (!p) oom(); memcpy(p, s, n + 1); return p; }
char *xstrndup(const char *s, size_t n) { char *p = (char *)malloc(n + 1); if (!p) oom(); memcpy(p, s, n); p[n] = '\0'; return p; }
