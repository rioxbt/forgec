/* SPDX-License-Identifier: MIT */
#define _GNU_SOURCE
#include "http.h"
#include "forge.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

const char *g_token = "";
const char *g_login = "adaiversen";
uint64_t g_req_counter = 1;

/* ---------------------------------------------------------------- resp */

void resp_reset(Resp *r) { r->status = 200; buf_reset(&r->body); buf_reset(&r->hdr); r->ctype = "application/json; charset=utf-8"; }
void resp_status(Resp *r, int status) { r->status = status; }
void resp_set_type(Resp *r, const char *ct) { r->ctype = ct; }
void resp_add_header(Resp *r, const char *line) { buf_adds(&r->hdr, line); buf_adds(&r->hdr, "\r\n"); }
void resp_json(Resp *r, int status, const char *json, size_t len) { r->status = status; r->ctype = "application/json; charset=utf-8"; buf_reset(&r->body); buf_add(&r->body, json, len); }
/* A body with an explicit content type (git smart HTTP and MCP reuse this). */
void resp_bytes(Resp *r, int status, const char *ctype, const char *data, size_t len) {
    r->status = status; r->ctype = ctype; buf_reset(&r->body); if (len) buf_add(&r->body, data, len);
}
void resp_json_buf(Resp *r, int status, const Buf *b) { resp_json(r, status, b->p ? b->p : "", b->len); }

/* ---------------------------------------------------------------- helpers */

const char *query_get(const char *query, const char *key, size_t *vlen) {
    size_t klen = strlen(key);
    const char *p = query;
    while (p && *p) {
        const char *amp = strchr(p, '&');
        const char *end = amp ? amp : p + strlen(p);
        const char *eq = memchr(p, '=', (size_t)(end - p));
        if (eq) {
            if ((size_t)(eq - p) == klen && strncmp(p, key, klen) == 0) {
                if (vlen) *vlen = (size_t)(end - (eq + 1));
                return eq + 1;
            }
        } else if ((size_t)(end - p) == klen && strncmp(p, key, klen) == 0) {
            if (vlen) *vlen = 0;
            return end;
        }
        p = amp ? amp + 1 : NULL;
    }
    return NULL;
}

char *pct_decode(const char *s, size_t n) {
    char *out = (char *)malloc(n + 1);
    if (!out) { fputs("oom\n", stderr); exit(1); }
    size_t j = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] == '%' && i + 2 < n) {
            int h1 = (unsigned char)s[i + 1], h2 = (unsigned char)s[i + 2];
            int a = h1 >= '0' && h1 <= '9' ? h1 - '0' : ((h1 | 32) >= 'a' && (h1 | 32) <= 'f') ? (h1 | 32) - 'a' + 10 : -1;
            int b = h2 >= '0' && h2 <= '9' ? h2 - '0' : ((h2 | 32) >= 'a' && (h2 | 32) <= 'f') ? (h2 | 32) - 'a' + 10 : -1;
            if (a >= 0 && b >= 0) { out[j++] = (char)((a << 4) | b); i += 2; continue; }
        }
        out[j++] = s[i];
    }
    out[j] = '\0';
    return out;
}

/* ---------------------------------------------------------------- connections */

typedef struct {
    int fd;
    Buf in, out;
    size_t out_off;
    int want_close;
    int in_epoll_out;
    char *scratch;      /* reusable header-parsing scratch */
    size_t scratch_cap;
    Resp resp;          /* reusable request/response scratch */
} Conn;

static Conn **g_conns = NULL;
static size_t g_conns_cap = 0;
static int g_epfd = -1;

static Conn *conn_new(int fd) {
    if ((size_t)fd >= g_conns_cap) {
        size_t ncap = g_conns_cap ? g_conns_cap : 1024;
        while (ncap <= (size_t)fd) ncap *= 2;
        g_conns = (Conn **)realloc(g_conns, ncap * sizeof(Conn *));
        if (!g_conns) { fputs("oom\n", stderr); exit(1); }
        memset(g_conns + g_conns_cap, 0, (ncap - g_conns_cap) * sizeof(Conn *));
        g_conns_cap = ncap;
    }
    Conn *c = (Conn *)calloc(1, sizeof(Conn));
    if (!c) { fputs("oom\n", stderr); exit(1); }
    c->fd = fd;
    buf_init(&c->in); buf_init(&c->out);
    c->scratch = NULL; c->scratch_cap = 0;
    resp_reset(&c->resp); buf_init(&c->resp.body); buf_init(&c->resp.hdr);
    g_conns[fd] = c;
    return c;
}

static void conn_close(Conn *c) {
    if (!c) return;
    if (g_conns[c->fd] == c) g_conns[c->fd] = NULL;
    epoll_ctl(g_epfd, EPOLL_CTL_DEL, c->fd, NULL);
    close(c->fd);
    buf_free(&c->in); buf_free(&c->out);
    free(c->scratch);
    buf_free(&c->resp.body); buf_free(&c->resp.hdr);
    free(c);
}

static int conn_flush(Conn *c) {
    while (c->out_off < c->out.len) {
        ssize_t n = send(c->fd, c->out.p + c->out_off, c->out.len - c->out_off, MSG_NOSIGNAL);
        if (n > 0) { c->out_off += (size_t)n; continue; }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (!c->in_epoll_out) {
                struct epoll_event ev; ev.events = EPOLLIN | EPOLLOUT; ev.data.fd = c->fd;
                epoll_ctl(g_epfd, EPOLL_CTL_MOD, c->fd, &ev);
                c->in_epoll_out = 1;
            }
            return 0;
        }
        return -1;
    }
    if (c->want_close) return -1;
    buf_reset(&c->out);
    c->out_off = 0;
    if (c->in_epoll_out) {
        struct epoll_event ev; ev.events = EPOLLIN; ev.data.fd = c->fd;
        epoll_ctl(g_epfd, EPOLL_CTL_MOD, c->fd, &ev);
        c->in_epoll_out = 0;
    }
    return 0;
}

/* ---------------------------------------------------------------- parsing */

static const char *find_crlfcrlf(const char *p, size_t n) {
    if (n < 4) return NULL;
    for (size_t i = 0; i + 3 < n; i++)
        if (p[i] == '\r' && p[i + 1] == '\n' && p[i + 2] == '\r' && p[i + 3] == '\n') return p + i + 4;
    return NULL;
}

/* Turn every CRLF into a NUL so each header line is a C string (the LF stays as a separator). */
static void split_headers(char *hdr, size_t hlen) {
    for (size_t i = 0; i + 1 < hlen; i++) if (hdr[i] == '\r' && hdr[i + 1] == '\n') hdr[i] = '\0';
    hdr[hlen] = '\0';
}

/* Header lookup over the split header block starting at `p`. Returns a NUL-terminated value. */
static char *hdr_lookup(char *p, size_t hlen, const char *name) {
    size_t nl = strlen(name);
    size_t off = 0;
    while (off < hlen) {
        char *line = p + off;
        size_t ll = strlen(line);
        if (ll > nl && line[nl] == ':' && strncasecmp(line, name, nl) == 0) {
            char *v = line + nl + 1;
            while (*v == ' ' || *v == '\t') v++;
            size_t vl = strlen(v);
            while (vl && (v[vl - 1] == ' ' || v[vl - 1] == '\t')) v[--vl] = '\0';
            return v;
        }
        off += ll + 1;
        if (off < hlen && p[off - 1] == '\0' && p[off] == '\n') off++; /* skip the LF */
        if (off <= 0) break;
    }
    return NULL;
}

/* Decode a chunked body. Returns malloc'd decoded bytes, sets *out_len and *used (bytes of encoding). */
static char *decode_chunked(const char *p, size_t n, size_t *out_len, size_t *used) {
    Buf out; buf_init(&out);
    size_t i = 0;
    for (;;) {
        size_t j = i;
        while (j + 1 < n && !(p[j] == '\r' && p[j + 1] == '\n')) j++;
        if (j + 1 >= n) { buf_free(&out); return NULL; }
        char sz[32]; size_t sl = j - i; if (sl >= sizeof sz) sl = sizeof sz - 1;
        memcpy(sz, p + i, sl); sz[sl] = '\0';
        long cl = strtol(sz, NULL, 16);
        i = j + 2;
        if (cl == 0) { if (i + 1 < n) i += 2; break; }
        if (i + (size_t)cl + 1 >= n) { buf_free(&out); return NULL; }
        buf_add(&out, p + i, (size_t)cl);
        i += (size_t)cl + 2;
    }
    *out_len = out.len; *used = i;
    return out.p;
}

/* Returns 1 when one request was consumed, 0 when more bytes are needed. */
static int handle_one(Conn *c) {
    const char *data = c->in.p;
    size_t n = c->in.len;
    if (!data || n == 0) return 0;
    const char *hend = find_crlfcrlf(data, n);
    if (!hend) return 0;
    size_t hlen = (size_t)(hend - data);

    if (hlen + 1 > c->scratch_cap) {
        c->scratch_cap = hlen + 64;
        c->scratch = (char *)realloc(c->scratch, c->scratch_cap);
        if (!c->scratch) { fputs("oom\n", stderr); exit(1); }
    }
    char *hdr = c->scratch;
    memcpy(hdr, data, hlen); hdr[hlen] = '\0';
    split_headers(hdr, hlen);

    Req q; memset(&q, 0, sizeof q);
    size_t reqline_len = strlen(hdr); /* measured before the request line is split */
    {
        char *methodend = strchr(hdr, ' ');
        if (!methodend) return 0;
        *methodend = '\0';
        snprintf(q.method, sizeof q.method, "%s", hdr);
        char *target = methodend + 1;
        char *sp2 = strchr(target, ' ');
        if (sp2) *sp2 = '\0';
        const char *qs = strchr(target, '?');
        if (qs) {
            size_t plen = (size_t)(qs - target);
            if (plen >= sizeof q.path) plen = sizeof q.path - 1;
            memcpy(q.path, target, plen); q.path[plen] = '\0';
            snprintf(q.query, sizeof q.query, "%s", qs + 1);
        } else {
            snprintf(q.path, sizeof q.path, "%s", target);
        }
    }
    char *hbase = hdr + reqline_len + 2; /* first header line (method line NUL + LF) */
    size_t hblen = hlen > reqline_len + 2 ? hlen - (reqline_len + 2) : 0;
    q.authorization = hdr_lookup(hbase, hblen, "authorization");
    q.content_type = hdr_lookup(hbase, hblen, "content-type");
    q.git_protocol = hdr_lookup(hbase, hblen, "git-protocol");
    q.host = hdr_lookup(hbase, hblen, "host");

    size_t body_off = (size_t)(hend - data);
    size_t total_used = body_off;
    char *body_alloc = NULL;
    char *te = hdr_lookup(hbase, hblen, "transfer-encoding");
    if (te && strstr(te, "chunked")) {
        size_t olen = 0, used = 0;
        body_alloc = decode_chunked(data + body_off, n - body_off, &olen, &used);
        if (!body_alloc) return 0;
        q.body = body_alloc; q.body_len = olen; total_used = body_off + used;
    } else {
        char *clv = hdr_lookup(hbase, hblen, "content-length");
        long cl = clv ? strtol(clv, NULL, 10) : 0;
        if (cl < 0) cl = 0;
        if (n - body_off < (size_t)cl) return 0;
        q.body = (char *)(data + body_off);
        q.body_len = (size_t)cl;
        total_used = body_off + (size_t)cl;
    }

    Resp *rp = &c->resp;
    resp_reset(rp);
    #define r (*rp)
    if (strcmp(q.path, "/healthz") == 0 && strcmp(q.method, "GET") == 0) {
        static const char HZ[] = "{\"ok\":true}\n";
        resp_json(&r, 200, HZ, sizeof HZ - 1);
    } else if (ci_prefix(q.path, "/api/v3")) {
        rest_handle(&q, &r);
    } else if (strcmp(q.path, "/api/graphql") == 0) {
        gql_handle(&q, &r);
    } else if (strcmp(q.path, "/mcp") == 0) {
        mcp_handle(&q, &r);
    } else if (strstr(q.path, ".git")) {
        git_handle(&q, &r);
    } else {
        static const char NF[] = "{\"message\":\"Not Found\"}\n";
        resp_json(&r, 404, NF, sizeof NF - 1);
    }

    static const char *REASONS[512];
    buf_reset(&c->out); c->out_off = 0;
    const char *reason = "OK";
    switch (r.status) {
        case 200: reason = "OK"; break;
        case 201: reason = "Created"; break;
        case 204: reason = "No Content"; break;
        case 400: reason = "Bad Request"; break;
        case 401: reason = "Unauthorized"; break;
        case 403: reason = "Forbidden"; break;
        case 404: reason = "Not Found"; break;
        case 405: reason = "Method Not Allowed"; break;
        case 409: reason = "Conflict"; break;
        case 422: reason = "Unprocessable Entity"; break;
        case 500: reason = "Internal Server Error"; break;
        default: reason = "OK"; break;
    }
    (void)REASONS;
    buf_addf(&c->out, "HTTP/1.1 %d %s\r\n", r.status, reason);
    buf_adds(&c->out, "Server: forgec\r\n");
    buf_addf(&c->out, "X-GitHub-Request-Id: %llu:%llu\r\n",
             (unsigned long long)(g_req_counter), (unsigned long long)(g_req_counter * 2654435761u));
    if (r.status != 204) {
        buf_addf(&c->out, "Content-Type: %s\r\n", r.ctype);
        buf_addf(&c->out, "Content-Length: %zu\r\n", r.body.len);
    } else {
        buf_adds(&c->out, "Content-Length: 0\r\n");
    }
    if (r.hdr.len) buf_add(&c->out, r.hdr.p, r.hdr.len);
    buf_adds(&c->out, "Connection: keep-alive\r\n\r\n");
    if (r.status != 204 && r.body.len) buf_add(&c->out, r.body.p, r.body.len);
    g_req_counter++;

    size_t consumed = total_used;
    memmove(c->in.p, c->in.p + consumed, c->in.len - consumed);
    c->in.len -= consumed;

    free(body_alloc);
    #undef r
    return 1;
}

static void handle_conn_read(Conn *c) {
    char tmp[262144];
    for (;;) {
        ssize_t n = recv(c->fd, tmp, sizeof tmp, 0);
        if (n > 0) { buf_add(&c->in, tmp, (size_t)n); continue; }
        if (n == 0) { c->want_close = 1; return; }
        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        c->want_close = 1;
        return;
    }
    while (!c->want_close && c->out.len == 0) {
        if (!handle_one(c)) break;
        if (conn_flush(c) < 0) { c->want_close = 1; break; }
    }
}

void http_run(int listen_fd) {
    g_epfd = epoll_create1(0);
    if (g_epfd < 0) { perror("epoll_create1"); exit(1); }
    extern int g_done_fd;
    if (g_done_fd >= 0) {
        struct epoll_event dev; dev.events = EPOLLIN; dev.data.fd = g_done_fd;
        epoll_ctl(g_epfd, EPOLL_CTL_ADD, g_done_fd, &dev);
    }
    struct epoll_event ev;
    ev.events = EPOLLIN; ev.data.fd = listen_fd;
    epoll_ctl(g_epfd, EPOLL_CTL_ADD, listen_fd, &ev);
    fcntl(listen_fd, F_SETFL, O_NONBLOCK);

    struct epoll_event events[512];
    static struct epoll_event cev;
    for (;;) {
        int k = epoll_wait(g_epfd, events, 512, -1);
        if (k < 0) { if (errno == EINTR) continue; perror("epoll_wait"); break; }
        for (int i = 0; i < k; i++) {
            int fd = events[i].data.fd;
            extern int g_done_fd;
            if (fd == g_done_fd) {
                char c; ssize_t rr = read(g_done_fd, &c, 1); (void)rr;
                fprintf(stderr, "[entry] done\n");
                exit(0);
            }
            if (fd == listen_fd) {
                for (;;) {
                    int cfd = accept4(listen_fd, NULL, NULL, SOCK_NONBLOCK);
                    if (cfd < 0) break;
                    int one = 1;
                    setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
                    conn_new(cfd);
                    cev.events = EPOLLIN; cev.data.fd = cfd;
                    epoll_ctl(g_epfd, EPOLL_CTL_ADD, cfd, &cev);
                }
                continue;
            }
            Conn *c = (g_conns && (size_t)fd < g_conns_cap) ? g_conns[fd] : NULL;
            if (!c) continue;
            if (events[i].events & (EPOLLHUP | EPOLLERR)) { conn_close(c); continue; }
            if (events[i].events & EPOLLOUT) {
                if (conn_flush(c) < 0) { conn_close(c); continue; }
                if (c->out.len == 0) handle_conn_read(c);
            }
            if (events[i].events & EPOLLIN) handle_conn_read(c);
            if (c->out.len) { if (conn_flush(c) < 0) { conn_close(c); continue; } }
            if (c->want_close && c->out.len == 0) { conn_close(c); continue; }
        }
    }
}
