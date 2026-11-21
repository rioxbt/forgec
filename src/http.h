/* SPDX-License-Identifier: MIT */
#ifndef FORGE_HTTP_H
#define FORGE_HTTP_H
#include "util.h"

typedef struct {
    char method[16];
    char path[2048];      /* raw, percent-encoded, no query */
    char query[2048];     /* raw, without '?' */
    char *authorization;  /* header value or NULL */
    char *content_type;
    char *git_protocol;
    char *host;
    char *body;           /* request body (may be NULL) */
    size_t body_len;
} Req;

typedef struct {
    int status;
    Buf body;
    Buf hdr;              /* extra header lines, each ending \r\n */
    const char *ctype;
} Resp;

void resp_reset(Resp *r);
void resp_status(Resp *r, int status);
void resp_set_type(Resp *r, const char *ct);
void resp_add_header(Resp *r, const char *line);
/* JSON body helpers */
void resp_json(Resp *r, int status, const char *json, size_t len);
void resp_json_buf(Resp *r, int status, const Buf *b);
void resp_bytes(Resp *r, int status, const char *ctype, const char *data, size_t len);

/* query helper: returns pointer to value (NOT decoded) or NULL */
const char *query_get(const char *query, const char *key, size_t *vlen);
/* percent-decode in place-ish: returns a newly malloc'd string */
char *pct_decode(const char *s, size_t n);

extern const char *g_token;      /* MAKEFUN_SHOP_TOKEN */
extern const char *g_login;      /* the token's login */
extern uint64_t g_req_counter;

int rest_handle(Req *q, Resp *r);
int mcp_handle(Req *q, Resp *r);
int gql_handle(Req *q, Resp *r);
int git_handle(Req *q, Resp *r);

int  http_serve(int fd);
void http_run(int listen_fd);

#endif
