/* SPDX-License-Identifier: MIT */
#ifndef FORGE_UTIL_H
#define FORGE_UTIL_H
#include <stddef.h>
#include <stdint.h>

/* A growable byte buffer. Never returns NULL for allocation failure semantics we care
   about: an OOM here aborts the process, which is an entry failure the harness sees. */
typedef struct { char *p; size_t len, cap; } Buf;

void  buf_init(Buf *b);
void  buf_free(Buf *b);
void  buf_reset(Buf *b);
void  buf_reserve(Buf *b, size_t extra);
void  buf_add(Buf *b, const void *data, size_t len);
void  buf_addc(Buf *b, char c);
void  buf_adds(Buf *b, const char *s);
void  buf_addn(Buf *b, const char *s, size_t n);
void  buf_addf(Buf *b, const char *fmt, ...);
/* Append `s` as a JSON string literal (quotes + escaping). */
void  buf_json_str(Buf *b, const char *s);
void  buf_json_strn(Buf *b, const char *s, size_t n);

/* base64 (standard alphabet, padded) */
size_t b64_encoded_len(size_t n);
void   b64_encode(Buf *out, const unsigned char *in, size_t n);
int    b64_decode(Buf *out, const char *in, size_t n);
int    b64_is_valid(const char *in, size_t n);

/* A tiny JSON reader: enough for the suite's request bodies. */
typedef struct { const char *s; size_t n, i; } Json;
int   json_find(const char *body, size_t len, const char *key, const char **val, size_t *vlen); /* top-level */
int   json_is_object(const char *body, size_t len);
/* Copy a JSON string value into out (unescaped), returns length or -1. */
int   json_unescape(const char *s, size_t n, Buf *out);

int   ci_eq(const char *a, const char *b);
int   ci_prefix(const char *a, const char *pfx);

char *xstrdup(const char *s);
char *xstrndup(const char *s, size_t n);

#endif
