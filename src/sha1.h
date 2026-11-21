/* SPDX-License-Identifier: MIT */
#ifndef FORGE_SHA1_H
#define FORGE_SHA1_H
#include <stddef.h>
#include <stdint.h>

/* Streaming SHA-1, used for git object ids and the pack trailer. */
typedef struct {
    uint32_t h[5];
    uint64_t nbytes;
    unsigned char block[64];
    size_t fill;
} Sha1;

void sha1_init(Sha1 *s);
void sha1_update(Sha1 *s, const void *data, size_t len);
void sha1_final(Sha1 *s, unsigned char out[20]);
void sha1_buf(const void *data, size_t len, unsigned char out[20]);
void sha1_hex(const unsigned char in[20], char out[41]);
int  sha1_hex_decode(const char *hex, size_t len, unsigned char out[20]);

#endif
