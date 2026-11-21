/* SPDX-License-Identifier: MIT */
#include "sha1.h"
#include <string.h>

static inline uint32_t rotl(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

static void sha1_block(uint32_t h[5], const unsigned char *p) {
    uint32_t w[80];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) |
               ((uint32_t)p[i * 4 + 2] << 8) | (uint32_t)p[i * 4 + 3];
    for (int i = 16; i < 80; i++)
        w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20)      { f = (b & c) | (~b & d);          k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d;                   k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
        else             { f = b ^ c ^ d;                   k = 0xCA62C1D6; }
        uint32_t tmp = rotl(a, 5) + f + e + k + w[i];
        e = d; d = c; c = rotl(b, 30); b = a; a = tmp;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}

void sha1_init(Sha1 *s) {
    s->h[0] = 0x67452301; s->h[1] = 0xEFCDAB89; s->h[2] = 0x98BADCFE;
    s->h[3] = 0x10325476; s->h[4] = 0xC3D2E1F0;
    s->nbytes = 0; s->fill = 0;
}

void sha1_update(Sha1 *s, const void *data, size_t len) {
    const unsigned char *p = (const unsigned char *)data;
    s->nbytes += len;
    if (s->fill) {
        size_t need = 64 - s->fill;
        size_t take = len < need ? len : need;
        memcpy(s->block + s->fill, p, take);
        s->fill += take; p += take; len -= take;
        if (s->fill == 64) { sha1_block(s->h, s->block); s->fill = 0; }
    }
    while (len >= 64) { sha1_block(s->h, p); p += 64; len -= 64; }
    if (len) { memcpy(s->block, p, len); s->fill = len; }
}

void sha1_final(Sha1 *s, unsigned char out[20]) {
    uint64_t bits = s->nbytes * 8;
    unsigned char pad = 0x80;
    sha1_update(s, &pad, 1);
    unsigned char z = 0;
    while (s->fill != 56) sha1_update(s, &z, 1);
    unsigned char lenb[8];
    for (int i = 0; i < 8; i++) lenb[i] = (unsigned char)(bits >> (56 - i * 8));
    sha1_update(s, lenb, 8);
    for (int i = 0; i < 5; i++) {
        out[i * 4]     = (unsigned char)(s->h[i] >> 24);
        out[i * 4 + 1] = (unsigned char)(s->h[i] >> 16);
        out[i * 4 + 2] = (unsigned char)(s->h[i] >> 8);
        out[i * 4 + 3] = (unsigned char)(s->h[i]);
    }
}

void sha1_buf(const void *data, size_t len, unsigned char out[20]) {
    Sha1 s; sha1_init(&s); sha1_update(&s, data, len); sha1_final(&s, out);
}

void sha1_hex(const unsigned char in[20], char out[41]) {
    static const char *d = "0123456789abcdef";
    for (int i = 0; i < 20; i++) { out[i * 2] = d[in[i] >> 4]; out[i * 2 + 1] = d[in[i] & 15]; }
    out[40] = '\0';
}

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int sha1_hex_decode(const char *hex, size_t len, unsigned char out[20]) {
    if (len != 40) return -1;
    for (int i = 0; i < 20; i++) {
        int a = hexval(hex[i * 2]), b = hexval(hex[i * 2 + 1]);
        if (a < 0 || b < 0) return -1;
        out[i] = (unsigned char)((a << 4) | b);
    }
    return 0;
}
