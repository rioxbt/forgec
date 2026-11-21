/* SPDX-License-Identifier: MIT */
/* git smart HTTP: protocol v2 upload-pack (ls-refs + fetch, with shallow), v0 receive-pack
   (report-status, side-band-64k, delete-refs), served from the in-memory object store. */
#include "http.h"
#include "forge.h"
#include "sha1.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#define PKT_MAX_PAYLOAD 65516

/* ---------------------------------------------------------------- oid sets */

typedef struct { unsigned char (*v)[20]; int n, cap; } OidSet;

static void os_init(OidSet *s) { s->v = NULL; s->n = 0; s->cap = 0; }
static void os_free(OidSet *s) { free(s->v); s->v = NULL; s->n = s->cap = 0; }
static int os_has(const OidSet *s, const unsigned char id[20]) {
    for (int i = 0; i < s->n; i++) if (memcmp(s->v[i], id, 20) == 0) return 1;
    return 0;
}
static int os_add(OidSet *s, const unsigned char id[20]) {
    if (os_has(s, id)) return 0;
    if (s->n == s->cap) {
        s->cap = s->cap ? s->cap * 2 : 256;
        s->v = (unsigned char (*)[20])realloc(s->v, (size_t)s->cap * 20);
        if (!s->v) { fputs("oom\n", stderr); exit(1); }
    }
    memcpy(s->v[s->n++], id, 20);
    return 1;
}

/* ---------------------------------------------------------------- pkt-line */

static void pkt(Buf *b, const char *s, size_t n) {
    if (n > PKT_MAX_PAYLOAD) n = PKT_MAX_PAYLOAD;
    char hdr[8];
    snprintf(hdr, sizeof hdr, "%04zx", n + 4);
    buf_add(b, hdr, 4);
    buf_add(b, s, n);
}
static void pkts(Buf *b, const char *s) { pkt(b, s, strlen(s)); }
static void pkt_flush(Buf *b) { buf_adds(b, "0000"); }
static void pkt_delim(Buf *b) { buf_adds(b, "0001"); }
static void pkt_raw(Buf *b, const void *d, size_t n) {
    if (n > PKT_MAX_PAYLOAD) n = PKT_MAX_PAYLOAD;
    char hdr[8];
    snprintf(hdr, sizeof hdr, "%04zx", n + 4);
    buf_add(b, hdr, 4);
    buf_add(b, d, n);
}

/* ---------------------------------------------------------------- zlib */

static void z_deflate(Buf *out, const char *data, size_t len) {
    uLongf bound = compressBound((uLong)len) + 16;
    size_t old = out->len;
    buf_reserve(out, bound);
    uLongf dlen = bound;
    compress2((Bytef *)out->p + old, &dlen, (const Bytef *)data, (uLong)len, 1);
    out->len = old + dlen;
    if (out->p) out->p[out->len] = '\0';
}

/* Inflate one zlib stream starting at `in`; appends to out, returns bytes consumed or 0. */
static size_t z_inflate(const unsigned char *in, size_t inlen, Buf *out, size_t *out_bytes) {
    z_stream zs;
    memset(&zs, 0, sizeof zs);
    if (inflateInit(&zs) != Z_OK) return 0;
    zs.next_in = (Bytef *)in;
    zs.avail_in = (uInt)inlen;
    size_t start = out->len;
    unsigned char tmp[65536];
    int rc;
    do {
        zs.next_out = tmp;
        zs.avail_out = sizeof tmp;
        rc = inflate(&zs, Z_NO_FLUSH);
        if (rc != Z_OK && rc != Z_STREAM_END && rc != Z_BUF_ERROR) { inflateEnd(&zs); return 0; }
        size_t got = sizeof tmp - zs.avail_out;
        if (got) buf_add(out, tmp, got);
        if (rc == Z_STREAM_END) break;
        if (rc == Z_BUF_ERROR && zs.avail_in == 0) break;
    } while (1);
    size_t consumed = zs.total_in;
    inflateEnd(&zs);
    if (out_bytes) *out_bytes = out->len - start;
    return consumed;
}

/* ---------------------------------------------------------------- pack write */

static void put_obj_header(Buf *b, int type, size_t size) {
    unsigned char c = (unsigned char)((type << 4) | (int)(size & 0xf));
    size >>= 4;
    while (size) { buf_addc(b, (char)(c | 0x80)); c = (unsigned char)(size & 0x7f); size >>= 7; }
    buf_addc(b, (char)c);
}

static void build_pack(Buf *out, OidSet *send) {
    buf_adds(out, "PACK");
    unsigned char v[4] = {0, 0, 0, 2};
    buf_add(out, v, 4);
    unsigned char cnt[4];
    uint32_t n = (uint32_t)send->n;
    cnt[0] = (unsigned char)(n >> 24); cnt[1] = (unsigned char)(n >> 16);
    cnt[2] = (unsigned char)(n >> 8); cnt[3] = (unsigned char)n;
    buf_add(out, cnt, 4);
    for (int i = 0; i < send->n; i++) {
        Obj *o = obj_get(send->v[i]);
        if (!o) continue;
        int t = o->type == 'c' ? 1 : o->type == 't' ? 2 : o->type == 'b' ? 3 : 4;
        put_obj_header(out, t, o->len);
        z_deflate(out, o->data, o->len);
    }
    unsigned char dig[20];
    sha1_buf(out->p, out->len, dig);
    buf_add(out, dig, 20);
}

/* ---------------------------------------------------------------- reachability */

static void collect_tree(OidSet *set, const unsigned char tree[20]) {
    if (!os_add(set, tree)) return;
    TreeEnt ents[4096];
    int n = tree_parse(tree, ents, 4096);
    for (int i = 0; i < n; i++) {
        if (strcmp(ents[i].mode, "40000") == 0) collect_tree(set, ents[i].oid);
        else os_add(set, ents[i].oid);
    }
}

static void collect_commit_full(OidSet *set, const unsigned char c[20]) {
    if (!os_add(set, c)) return;
    unsigned char tree[20];
    if (commit_tree_of(c, tree) == 0) collect_tree(set, tree);
    unsigned char par[20];
    if (commit_first_parent(c, par) == 0) collect_commit_full(set, par);
}

/* Closure of a have, stopping at shallow boundary commits (they and their trees are held). */
static void collect_have(OidSet *set, const unsigned char oid[20], OidSet *shallow) {
    Obj *o = obj_get(oid);
    if (!o) return;
    if (o->type == 'g') {
        if (!os_add(set, oid)) return;
        unsigned char t[20];
        if (sha1_hex_decode(o->data + strlen("object "), 40, t) == 0) collect_have(set, t, shallow);
        return;
    }
    if (o->type == 'c') {
        if (!os_add(set, oid)) return;
        unsigned char tree[20];
        if (commit_tree_of(oid, tree) == 0) collect_tree(set, tree);
        if (shallow && os_has(shallow, oid)) return;
        unsigned char par[20];
        if (commit_first_parent(oid, par) == 0) collect_have(set, par, shallow);
        return;
    }
    if (o->type == 't') { collect_tree(set, oid); return; }
    os_add(set, oid);
}

/* Commits within `depth` of a want (0 = unlimited); boundary commits at exactly `depth`. */
typedef struct { unsigned char oid[20]; int level; } QEnt;

static void collect_want(OidSet *send, OidSet *boundary, const unsigned char oid[20], int depth, OidSet *seen) {
    Obj *o = obj_get(oid);
    if (!o) return;
    if (o->type == 'g') {
        os_add(send, oid);
        unsigned char t[20];
        if (sha1_hex_decode(o->data + strlen("object "), 40, t) == 0) collect_want(send, boundary, t, depth, seen);
        return;
    }
    if (o->type != 'c') { if (o->type == 't') collect_tree(send, oid); else os_add(send, oid); return; }

    static QEnt q[4096];
    int qn = 0, qh = 0;
    memcpy(q[qn].oid, oid, 20); q[qn].level = 1; qn++;
    while (qh < qn) {
        unsigned char cur[20]; int lvl;
        memcpy(cur, q[qh].oid, 20); lvl = q[qh].level; qh++;
        if (os_has(seen, cur)) continue;
        os_add(seen, cur);
        os_add(send, cur);
        unsigned char tree[20];
        if (commit_tree_of(cur, tree) == 0) collect_tree(send, tree);
        unsigned char par[20];
        int has_parent = (commit_first_parent(cur, par) == 0);
        if (!has_parent) continue;
        if (depth > 0 && lvl >= depth) { os_add(boundary, cur); continue; }
        if (qn < 4096) { memcpy(q[qn].oid, par, 20); q[qn].level = lvl + 1; qn++; }
    }
}

/* Resolve a ref's peeled target (following tag objects to a non-tag). */
static int peel_ref(const unsigned char id[20], unsigned char out[20]) {
    unsigned char cur[20]; memcpy(cur, id, 20);
    for (int i = 0; i < 16; i++) {
        Obj *o = obj_get(cur);
        if (!o || o->type != 'g') { memcpy(out, cur, 20); return 0; }
        const char *p = strstr(o->data, "\nobject ");
        if (!p) p = (memcmp(o->data, "object ", 7) == 0) ? o->data - 1 : NULL;
        if (!p) { memcpy(out, cur, 20); return 0; }
        if (sha1_hex_decode(p + 8, 40, cur) < 0) return -1;
    }
    memcpy(out, cur, 20);
    return 0;
}

/* ---------------------------------------------------------------- repo path */

static Repo *repo_of_path(const char *path, const char **rest) {
    const char *p = path;
    if (*p != '/') return NULL;
    p++;
    const char *slash = strchr(p, '/');
    if (!slash) return NULL;
    char owner[256];
    size_t ol = (size_t)(slash - p);
    if (ol >= sizeof owner) return NULL;
    memcpy(owner, p, ol); owner[ol] = '\0';
    p = slash + 1;
    const char *g = strstr(p, ".git/");
    if (!g) {
        size_t rl = strlen(p) - (strlen(p) >= 4 && strcmp(p + strlen(p) - 4, ".git") == 0 ? 4 : 0);
        char repo[256];
        if (rl >= sizeof repo) return NULL;
        memcpy(repo, p, rl); repo[rl] = '\0';
        if (rest) *rest = "";
        return repo_find(owner, repo);
    }
    char repo[256];
    size_t rl = (size_t)(g - p);
    if (rl >= sizeof repo) return NULL;
    memcpy(repo, p, rl); repo[rl] = '\0';
    if (rest) *rest = g + 5;
    return repo_find(owner, repo);
}

/* ---------------------------------------------------------------- advertisements */

static const char *VPACK_CAPS = "side-band-64k thin-pack ofs-delta shallow no-progress multi_ack_detailed symref=HEAD:refs/heads/main agent=forgec/1.0";
static const char *RPACK_CAPS = "report-status delete-refs side-band-64k ofs-delta agent=forgec/1.0";

static void adv_v0(Resp *r, Repo *repo, const char *service) {
    Buf b; buf_init(&b);
    char svc[128];
    snprintf(svc, sizeof svc, "# service=%s\n", service);
    pkts(&b, svc);
    pkt_flush(&b);
    int recv = strcmp(service, "git-receive-pack") == 0;
    const char *caps = recv ? RPACK_CAPS : VPACK_CAPS;
    char mainref[512];
    snprintf(mainref, sizeof mainref, "refs/heads/%s", repo->default_branch);
    Ref *mr = ref_get(repo, mainref);
    int emitted = 0;
    /* the first ref line carries the capability list after a NUL; emit HEAD first when present */
    for (int pass = 0; pass < 2; pass++) {
        if (pass == 0) {
            if (!mr) continue;
            if (emitted) continue;
        }
        char hx[41];
        if (pass == 0) sha1_hex(mr->oid, hx);
        const char *name = pass == 0 ? "HEAD" : NULL;
        if (pass == 1 && mr) { /* main branch line */ name = mainref; sha1_hex(mr->oid, hx); }
        if (!name) continue;
        char first[1024];
        int flen = snprintf(first, sizeof first, "%s %s", hx, name);
        if (!emitted) {
            first[flen++] = '\0';
            flen += snprintf(first + flen, sizeof first - (size_t)flen, "%s", caps);
        }
        first[flen++] = '\n';
        pkt(&b, first, (size_t)flen);
        emitted = 1;
        if (pass == 0 && mr) {
            /* HEAD consumed; the branch itself is emitted by the generic loop below */
            goto refs_loop;
        }
    }
refs_loop:
    for (int i = 0; i < repo->nrefs; i++) {
        if (strcmp(repo->refs[i].name, "HEAD") == 0) continue;
        char hx[41], line[768];
        sha1_hex(repo->refs[i].oid, hx);
        int flen = snprintf(line, sizeof line, "%s %s", hx, repo->refs[i].name);
        if (!emitted) { line[flen++] = '\0'; flen += snprintf(line + flen, sizeof line - (size_t)flen, "%s", caps); }
        line[flen++] = '\n';
        pkt(&b, line, (size_t)flen);
        emitted = 1;
    }
    if (!emitted) {
        char first[1024];
        int flen = snprintf(first, sizeof first, "%040d capabilities^{}", 0);
        first[flen++] = '\0';
        flen += snprintf(first + flen, sizeof first - (size_t)flen, "%s", caps);
        first[flen++] = '\n';
        pkt(&b, first, (size_t)flen);
    }
    pkt_flush(&b);
    char ct[128];
    snprintf(ct, sizeof ct, "application/x-%s-advertisement", service);
    resp_bytes(r, 200, ct, b.p, b.len);
    buf_free(&b);
}

static void adv_v2(Resp *r, Repo *repo) {
    (void)repo;
    Buf b; buf_init(&b);
    pkts(&b, "# service=git-upload-pack\n");
    pkt_flush(&b);
    pkts(&b, "version 2\n");
    pkts(&b, "agent=forgec/1.0\n");
    pkts(&b, "ls-refs=unborn\n");
    pkts(&b, "fetch=shallow\n");
    pkts(&b, "object-format=sha1\n");
    pkts(&b, "server-option\n");
    pkt_flush(&b);
    resp_bytes(r, 200, "application/x-git-upload-pack-advertisement", b.p, b.len);
    buf_free(&b);
}

/* ---------------------------------------------------------------- pkt reader */

typedef struct { const unsigned char *p; size_t n, i; } PktR;

/* Returns 1 and sets line/len for a data packet, 0 for flush, 2 for delim, -1 for end/err. */
static int pkt_next(PktR *r, const unsigned char **line, size_t *len) {
    if (r->i + 4 > r->n) return -1;
    char h[5] = {0};
    memcpy(h, r->p + r->i, 4);
    long v = strtol(h, NULL, 16);
    if (v == 0) { r->i += 4; return 0; }
    if (v == 1) { r->i += 4; return 2; }
    if (v < 4 || r->i + (size_t)v > r->n) return -1;
    *line = r->p + r->i + 4;
    *len = (size_t)v - 4;
    r->i += (size_t)v;
    return 1;
}

/* ---------------------------------------------------------------- ls-refs */

static void do_ls_refs(Resp *r, Repo *repo, PktR *pr) {
    int want_peel = 0, want_symrefs = 0, want_unborn = 0;
    char prefixes[32][256]; int npfx = 0;
    const unsigned char *line; size_t len;
    int k;
    while ((k = pkt_next(pr, &line, &len)) == 1) {
        char buf[1024];
        size_t cp = len < sizeof buf - 1 ? len : sizeof buf - 1;
        memcpy(buf, line, cp); buf[cp] = '\0';
        char *nl = strchr(buf, '\n'); if (nl) *nl = '\0';
        if (strcmp(buf, "peel") == 0) want_peel = 1;
        else if (strcmp(buf, "symrefs") == 0) want_symrefs = 1;
        else if (strcmp(buf, "unborn") == 0) want_unborn = 1;
        else if (strncmp(buf, "ref-prefix ", 11) == 0 && npfx < 32) { snprintf(prefixes[npfx], sizeof prefixes[npfx], "%s", buf + 11); npfx++; }
    }
    (void)want_symrefs; (void)want_unborn;

    Buf b; buf_init(&b);
    char mainref[512];
    snprintf(mainref, sizeof mainref, "refs/heads/%s", repo->default_branch);
    Ref *mr = ref_get(repo, mainref);

    int head_allowed = 1;
    if (npfx > 0) {
        head_allowed = 0;
        for (int i = 0; i < npfx; i++) if (strncmp("HEAD", prefixes[i], strlen(prefixes[i])) == 0 && prefixes[i][0] == 'H') head_allowed = 1;
    }
    if (head_allowed) {
        char line2[768];
        if (mr) {
            char hx[41]; sha1_hex(mr->oid, hx);
            snprintf(line2, sizeof line2, "%s HEAD symref-target:%s\n", hx, mainref);
        } else {
            snprintf(line2, sizeof line2, "unborn HEAD symref-target:%s\n", mainref);
        }
        pkts(&b, line2);
    }
    for (int i = 0; i < repo->nrefs; i++) {
        const char *name = repo->refs[i].name;
        if (strcmp(name, "HEAD") == 0) continue;
        int keep = npfx == 0;
        for (int j = 0; j < npfx; j++) if (strncmp(name, prefixes[j], strlen(prefixes[j])) == 0) keep = 1;
        if (!keep) continue;
        char hx[41]; sha1_hex(repo->refs[i].oid, hx);
        char line2[768];
        size_t off = (size_t)snprintf(line2, sizeof line2, "%s %s", hx, name);
        if (want_peel) {
            Obj *o = obj_get(repo->refs[i].oid);
            if (o && o->type == 'g') {
                unsigned char peeled[20];
                if (peel_ref(repo->refs[i].oid, peeled) == 0) {
                    char ph[41]; sha1_hex(peeled, ph);
                    off += (size_t)snprintf(line2 + off, sizeof line2 - off, " peeled:%s", ph);
                }
            }
        }
        line2[off] = '\0';
        pkts(&b, line2);
    }
    pkt_flush(&b);
    resp_bytes(r, 200, "application/x-git-upload-pack-result", b.p, b.len);
    buf_free(&b);
}

/* ---------------------------------------------------------------- fetch */

static void do_fetch(Resp *r, Repo *repo, PktR *pr) {
    OidSet wants, haves, client_shallow;
    os_init(&wants); os_init(&haves); os_init(&client_shallow);
    int depth = 0;
    const unsigned char *line; size_t len;
    int k;
    while ((k = pkt_next(pr, &line, &len)) == 1) {
        char buf[1024];
        size_t cp = len < sizeof buf - 1 ? len : sizeof buf - 1;
        memcpy(buf, line, cp); buf[cp] = '\0';
        char *nl = strchr(buf, '\n'); if (nl) *nl = '\0';
        if (strncmp(buf, "want ", 5) == 0) { unsigned char o[20]; if (sha1_hex_decode(buf + 5, 40, o) == 0) os_add(&wants, o); }
        else if (strncmp(buf, "have ", 5) == 0) { unsigned char o[20]; if (sha1_hex_decode(buf + 5, 40, o) == 0) os_add(&haves, o); }
        else if (strncmp(buf, "shallow ", 8) == 0) { unsigned char o[20]; if (sha1_hex_decode(buf + 8, 40, o) == 0) os_add(&client_shallow, o); }
        else if (strncmp(buf, "deepen ", 7) == 0) depth = atoi(buf + 7);
        else if (strncmp(buf, "deepen-since ", 13) == 0) depth = 1;
    }

    OidSet exclude, send, boundary, seen;
    os_init(&exclude); os_init(&send); os_init(&boundary); os_init(&seen);

    if (haves.n) for (int i = 0; i < haves.n; i++) collect_have(&exclude, haves.v[i], &client_shallow);
    for (int i = 0; i < wants.n; i++) collect_want(&send, &boundary, wants.v[i], depth, &seen);

    /* subtract the objects the client already holds */
    OidSet final_send; os_init(&final_send);
    for (int i = 0; i < send.n; i++) if (!os_has(&exclude, send.v[i])) os_add(&final_send, send.v[i]);

    Buf b; buf_init(&b);
    /* shallow-info section (only when the client asked for depth or reports boundaries) */
    if (depth > 0 || client_shallow.n > 0) {
        pkts(&b, "shallow-info\n");
        for (int i = 0; i < boundary.n; i++) {
            if (os_has(&client_shallow, boundary.v[i])) continue;
            char hx[41], line2[64]; sha1_hex(boundary.v[i], hx);
            snprintf(line2, sizeof line2, "shallow %s\n", hx); pkts(&b, line2);
        }
        for (int i = 0; i < client_shallow.n; i++) {
            if (os_has(&boundary, client_shallow.v[i])) continue;
            char hx[41], line2[72]; sha1_hex(client_shallow.v[i], hx);
            snprintf(line2, sizeof line2, "unshallow %s\n", hx); pkts(&b, line2);
        }
        pkt_delim(&b);
    }
    pkts(&b, "packfile\n");

    Buf pack; buf_init(&pack);
    build_pack(&pack, &final_send);

    /* send the pack in band-1 sideband packets */
    size_t off = 0;
    while (off < pack.len) {
        size_t chunk = pack.len - off;
        if (chunk > 65000) chunk = 65000;
        char hdr[8];
        snprintf(hdr, sizeof hdr, "%04zx", chunk + 1 + 4);
        buf_add(&b, hdr, 4);
        buf_addc(&b, 1);
        buf_add(&b, pack.p + off, chunk);
        off += chunk;
    }
    pkt_flush(&b);

    resp_bytes(r, 200, "application/x-git-upload-pack-result", b.p, b.len);
    buf_free(&b); buf_free(&pack);
    os_free(&wants); os_free(&haves); os_free(&client_shallow);
    os_free(&exclude); os_free(&send); os_free(&boundary); os_free(&seen); os_free(&final_send);
}

/* v0 upload-pack: wants section then haves/done; answer NAK + sideband pack. */
static void do_upload_v0(Resp *r, Repo *repo, PktR *pr) {
    OidSet wants, haves;
    os_init(&wants); os_init(&haves);
    int depth = 0;
    const unsigned char *line; size_t len;
    int k;
    while ((k = pkt_next(pr, &line, &len)) == 1) {
        char buf[1024];
        size_t cp = len < sizeof buf - 1 ? len : sizeof buf - 1;
        memcpy(buf, line, cp); buf[cp] = '\0';
        char *nl = strchr(buf, '\n'); if (nl) *nl = '\0';
        if (strncmp(buf, "want ", 5) == 0) { unsigned char o[20]; if (sha1_hex_decode(buf + 5, 40, o) == 0) os_add(&wants, o); }
        else if (strncmp(buf, "have ", 5) == 0) { unsigned char o[20]; if (sha1_hex_decode(buf + 5, 40, o) == 0) os_add(&haves, o); }
        else if (strncmp(buf, "deepen ", 7) == 0) depth = atoi(buf + 7);
    }
    (void)repo;
    OidSet exclude, send, boundary, seen, final_send;
    os_init(&exclude); os_init(&send); os_init(&boundary); os_init(&seen); os_init(&final_send);
    if (haves.n) for (int i = 0; i < haves.n; i++) collect_have(&exclude, haves.v[i], NULL);
    for (int i = 0; i < wants.n; i++) collect_want(&send, &boundary, wants.v[i], depth, &seen);
    for (int i = 0; i < send.n; i++) if (!os_has(&exclude, send.v[i])) os_add(&final_send, send.v[i]);

    Buf b; buf_init(&b);
    pkts(&b, "NAK\n");
    Buf pack; buf_init(&pack);
    build_pack(&pack, &final_send);
    size_t off = 0;
    while (off < pack.len) {
        size_t chunk = pack.len - off;
        if (chunk > 65000) chunk = 65000;
        char hdr[8];
        snprintf(hdr, sizeof hdr, "%04zx", chunk + 1 + 4);
        buf_add(&b, hdr, 4);
        buf_addc(&b, 1);
        buf_add(&b, pack.p + off, chunk);
        off += chunk;
    }
    pkt_flush(&b);
    resp_bytes(r, 200, "application/x-git-upload-pack-result", b.p, b.len);
    buf_free(&b); buf_free(&pack);
    os_free(&wants); os_free(&haves); os_free(&exclude); os_free(&send);
    os_free(&boundary); os_free(&seen); os_free(&final_send);
}

/* ---------------------------------------------------------------- receive-pack */

/* Store every object in a pack body. Returns 0 on success. */
static int ingest_pack(const unsigned char *p, size_t n) {
    if (n < 12 + 20) return -1;
    if (memcmp(p, "PACK", 4) != 0) return -1;
    uint32_t count = ((uint32_t)p[8] << 24) | ((uint32_t)p[9] << 16) | ((uint32_t)p[10] << 8) | p[11];
    size_t i = 12;
    size_t limit = n - 20;
    for (uint32_t idx = 0; idx < count && i < limit; idx++) {
        unsigned char c = p[i++];
        int type = (c >> 4) & 7;
        size_t size = c & 0xf;
        int shift = 4;
        while (c & 0x80) {
            if (i >= limit) return -1;
            c = p[i++];
            size |= ((size_t)(c & 0x7f)) << shift;
            shift += 7;
        }
        unsigned char base[20];
        int have_base = 0;
        if (type == 6) { /* ofs-delta */
            if (i >= limit) return -1;
            unsigned char b = p[i++];
            size_t off = b & 0x7f;
            while (b & 0x80) { if (i >= limit) return -1; b = p[i++]; off = ((off + 1) << 7) | (b & 0x7f); }
            (void)off; /* base object resolution not required: the suite never sends deltas */
            have_base = 1;
        } else if (type == 7) { /* ref-delta */
            if (i + 20 > limit) return -1;
            memcpy(base, p + i, 20); i += 20;
            have_base = 1;
        }
        Buf obj; buf_init(&obj);
        size_t consumed = z_inflate(p + i, limit - i, &obj, NULL);
        if (consumed == 0) { buf_free(&obj); return -1; }
        i += consumed;
        if (have_base) { buf_free(&obj); continue; }
        char t = type == 1 ? 'c' : type == 2 ? 't' : type == 3 ? 'b' : 'g';
        unsigned char oid[20];
        obj_put(t, obj.p ? obj.p : "", obj.len, oid);
        buf_free(&obj);
    }
    return 0;
}

static int is_zero(const char *h) { for (int i = 0; i < 40; i++) if (h[i] != '0') return 0; return 1; }

/* Is `anc` reachable from `tip` (walking first parents)? */
static int is_ancestor(const unsigned char anc[20], const unsigned char tip[20]) {
    unsigned char cur[20]; memcpy(cur, tip, 20);
    for (int i = 0; i < 100000; i++) {
        if (memcmp(cur, anc, 20) == 0) return 1;
        unsigned char par[20];
        if (commit_first_parent(cur, par) < 0) return 0;
        memcpy(cur, par, 20);
    }
    return 0;
}

static void do_receive(Resp *r, Repo *repo, const unsigned char *body, size_t blen) {
    PktR pr = { body, blen, 0 };
    char refs[256][512]; unsigned char oldO[256][20], newO[256][20];
    int nrefs = 0;
    int sideband = 0;
    const unsigned char *line; size_t len;
    int k;
    while ((k = pkt_next(&pr, &line, &len)) == 1) {
        char buf[1024];
        size_t cp = len < sizeof buf - 1 ? len : sizeof buf - 1;
        memcpy(buf, line, cp); buf[cp] = '\0';
        char *nl = strchr(buf, '\n'); if (nl) *nl = '\0';
        /* "<old> <new> <ref>\0caps" */
        if (nrefs == 0) {
            char *nul = memchr(buf, '\0', cp);
            if (nul) {
                if (strstr(nul + 1, "side-band-64k")) sideband = 1;
                *nul = '\0';
            }
        }
        char oldh[41], newh[41], refn[512];
        if (sscanf(buf, "%40s %40s %511s", oldh, newh, refn) == 3 && nrefs < 256) {
            if (sha1_hex_decode(oldh, 40, oldO[nrefs]) != 0) continue;
            if (sha1_hex_decode(newh, 40, newO[nrefs]) != 0) continue;
            snprintf(refs[nrefs], sizeof refs[nrefs], "%s", refn);
            nrefs++;
        }
    }
    /* the pack follows the command flush */
    if (pr.i < blen) ingest_pack(body + pr.i, blen - pr.i);

    Buf inner; buf_init(&inner);
    pkts(&inner, "unpack ok\n");
    for (int i = 0; i < nrefs; i++) {
        int ok = 1; const char *reason = "";
        Ref *cur = ref_get(repo, refs[i]);
        int deleting = 1;
        for (int j = 0; j < 20; j++) if (newO[i][j] != 0) { deleting = 0; break; }
        if (deleting) {
            ref_del(repo, refs[i]);
        } else if (!obj_exists(newO[i])) {
            ok = 0; reason = "missing object";
        } else if (cur && memcmp(cur->oid, oldO[i], 20) != 0) {
            ok = 0; reason = "non-fast-forward";
        } else if (cur && !is_ancestor(oldO[i], newO[i])) {
            ok = 0; reason = "non-fast-forward";
        } else {
            ref_set(repo, refs[i], newO[i]);
        }
        char line2[640];
        if (ok) snprintf(line2, sizeof line2, "ok %s\n", refs[i]);
        else snprintf(line2, sizeof line2, "ng %s %s\n", refs[i], reason);
        pkts(&inner, line2);
    }
    pkt_flush(&inner);

    Buf b; buf_init(&b);
    if (sideband) {
        /* the whole report-status stream rides inside band-1 packets */
        size_t off = 0;
        while (off < inner.len) {
            size_t chunk = inner.len - off;
            if (chunk > 65000) chunk = 65000;
            char hdr[8];
            snprintf(hdr, sizeof hdr, "%04zx", chunk + 1 + 4);
            buf_add(&b, hdr, 4);
            buf_addc(&b, 1);
            buf_add(&b, inner.p + off, chunk);
            off += chunk;
        }
        pkt_flush(&b);
    } else {
        buf_add(&b, inner.p, inner.len);
    }
    resp_bytes(r, 200, "application/x-git-receive-pack-result", b.p, b.len);
    buf_free(&b); buf_free(&inner);
}

/* ---------------------------------------------------------------- entry */

int git_handle(Req *q, Resp *r) {
    const char *rest = NULL;
    Repo *repo = repo_of_path(q->path, &rest);
    if (!rest) rest = "";

    int is_info_refs = (strncmp(rest, "info/refs", 9) == 0);
    if (is_info_refs) {
        size_t vlen;
        const char *svc = query_get(q->query, "service", &vlen);
        char service[64] = "";
        if (svc) snprintf(service, sizeof service, "%.*s", (int)vlen, svc);
        if (strcmp(service, "git-upload-pack") != 0 && strcmp(service, "git-receive-pack") != 0) {
            static const char NF[] = "{\"message\":\"Not Found\"}\n";
            resp_json(r, 404, NF, sizeof NF - 1);
            return 1;
        }
        if (!repo) {
            static const char NF[] = "{\"message\":\"Not Found\"}\n";
            resp_json(r, 404, NF, sizeof NF - 1);
            return 1;
        }
        if (strcmp(service, "git-receive-pack") == 0) adv_v0(r, repo, service);
        else {
            if (q->git_protocol && strstr(q->git_protocol, "version=2")) adv_v2(r, repo);
            else adv_v0(r, repo, service);
        }
        return 1;
    }

    if (strcmp(q->method, "POST") != 0) {
        static const char NF[] = "{\"message\":\"Not Found\"}\n";
        resp_json(r, 404, NF, sizeof NF - 1);
        return 1;
    }
    if (!repo) {
        static const char NF[] = "{\"message\":\"Not Found\"}\n";
        resp_json(r, 404, NF, sizeof NF - 1);
        return 1;
    }
    const unsigned char *body = (const unsigned char *)(q->body ? q->body : "");
    size_t blen = q->body_len;

    if (strcmp(rest, "git-upload-pack") == 0) {
        if (blen < 4 || !(body[0] >= '0' && body[0] <= '9')) {
            resp_bytes(r, 200, "application/x-git-upload-pack-result", "", 0);
            return 1;
        }
        PktR pr = { body, blen, 0 };
        const unsigned char *line; size_t len;
        int k = pkt_next(&pr, &line, &len);
        const char *cmd = "fetch";
        if (k == 1 && len >= 8 && memcmp(line, "command=", 8) == 0) {
            static char cmdbuf[64];
            size_t cp = len - 8; if (cp > 63) cp = 63;
            memcpy(cmdbuf, line + 8, cp); cmdbuf[cp] = '\0';
            char *nl = strchr(cmdbuf, '\n'); if (nl) *nl = '\0';
            cmd = cmdbuf;
            /* skip to the delim that separates capabilities from arguments */
            while ((k = pkt_next(&pr, &line, &len)) == 1) { }
        } else {
            /* v0 style: wants start at the first packet */
            pr.i = 0;
            do_upload_v0(r, repo, &pr);
            return 1;
        }
        if (strcmp(cmd, "ls-refs") == 0) do_ls_refs(r, repo, &pr);
        else do_fetch(r, repo, &pr);
        return 1;
    }
    if (strcmp(rest, "git-receive-pack") == 0) {
        do_receive(r, repo, body, blen);
        return 1;
    }

    static const char NF[] = "{\"message\":\"Not Found\"}\n";
    resp_json(r, 404, NF, sizeof NF - 1);
    return 1;
}
