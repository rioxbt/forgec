/* SPDX-License-Identifier: MIT */
#include "http.h"
#include "forge.h"
#include "sha1.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* forward decl from store.c */
uint64_t store_next_comment_id(void);
int tree_list_entries(const unsigned char id[20], TreeEnt *out, int max);

/* ---------------------------------------------------------------- auth + json */

static int is_authed(Req *q) {
    if (!q->authorization) return 0;
    const char *a = q->authorization;
    if (!(ci_prefix(a, "Bearer ") || ci_prefix(a, "token "))) return 0;
    return 1;
}

/* Extract a JSON string field into `out` (malloc'd); returns 1 on success. */
static int jstr(const char *body, size_t len, const char *key, char **out) {
    const char *v; size_t vl;
    if (!json_find(body, len, key, &v, &vl)) return 0;
    if (vl >= 1 && v[0] == '"') {
        Buf b; buf_init(&b);
        if (json_unescape(v, vl, &b) < 0) { buf_free(&b); return 0; }
        buf_addc(&b, '\0');
        *out = b.p;
        return 1;
    }
    *out = xstrndup(v, vl);
    return 1;
}
static int jbool(const char *body, size_t len, const char *key, int *out) {
    const char *v; size_t vl;
    if (!json_find(body, len, key, &v, &vl)) return 0;
    *out = (strncmp(v, "true", 4) == 0);
    return 1;
}
/* array of strings: copies into out (max), returns count */
static int jstr_array(const char *body, size_t len, const char *key, char **out, int max) {
    const char *v; size_t vl;
    if (!json_find(body, len, key, &v, &vl)) return 0;
    if (vl < 2 || v[0] != '[') return 0;
    int n = 0;
    const char *p = v + 1, *end = v + vl - 1;
    while (p < end && n < max) {
        while (p < end && (*p == ' ' || *p == ',' || *p == '\n')) p++;
        if (p >= end || *p == ']') break;
        if (*p == '"') {
            const char *s = p; p++;
            while (p < end && *p != '"') { if (*p == '\\') p++; p++; }
            if (p < end) p++;
            Buf b; buf_init(&b);
            if (json_unescape(s, (size_t)(p - s), &b) == 0) { buf_addc(&b, '\0'); out[n++] = b.p; }
            else buf_free(&b);
        } else {
            while (p < end && *p != ',') p++;
        }
    }
    return n;
}

/* Is a JSON body well-formed enough to be an object? */
static int json_ok(const char *body, size_t len) {
    if (len == 0) return 0;
    int depth = 0; int in_str = 0;
    int ncommas = 0, ncolons = 0;
    for (size_t i = 0; i < len; i++) {
        char c = body[i];
        if (in_str) {
            if (c == '\\') { i++; continue; }
            if (c == '"') in_str = 0;
            continue;
        }
        if (c == '"') in_str = 1;
        else if (c == '{' || c == '[') depth++;
        else if (c == '}' || c == ']') { depth--; if (depth < 0) return 0; }
        else if (c == ',') ncommas++;
        else if (c == ':') ncolons++;
        else if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '-' || c == '.' ||
                 (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == '+' || c == 'e' || c == 'E') {
        } else {
            return 0;
        }
    }
    if (in_str || depth != 0) return 0;
    (void)ncommas; (void)ncolons;
    return 1;
}

/* ---------------------------------------------------------------- json writers */

static void j_login(Buf *b, const char *login) { buf_adds(b, "{\"login\":"); buf_json_str(b, login); buf_adds(b, ",\"id\":1000,\"type\":\"User\"}"); }

static void j_repo(Buf *b, Repo *r) {
    buf_addc(b, '{');
    buf_addf(b, "\"id\":%d,", r->id);
    buf_adds(b, "\"name\":"); buf_json_str(b, r->name); buf_addc(b, ',');
    buf_adds(b, "\"full_name\":");
    { Buf t; buf_init(&t); buf_addf(&t, "%s/%s", r->owner, r->name); buf_json_str(b, t.p); buf_free(&t); }
    buf_addc(b, ',');
    buf_adds(b, "\"private\":"); buf_adds(b, r->is_private ? "true" : "false"); buf_addc(b, ',');
    buf_adds(b, "\"description\":"); buf_json_str(b, r->description); buf_addc(b, ',');
    buf_adds(b, "\"default_branch\":"); buf_json_str(b, r->default_branch); buf_addc(b, ',');
    buf_adds(b, "\"owner\":"); j_login(b, r->owner); buf_addc(b, ',');
    buf_adds(b, "\"html_url\":\"\",\"url\":\"\",\"node_id\":\"\"");
    buf_addc(b, '}');
}

static void j_label(Buf *b, const char *name, const char *color) {
    buf_addc(b, '{');
    buf_adds(b, "\"id\":1,\"name\":"); buf_json_str(b, name); buf_addc(b, ',');
    buf_adds(b, "\"color\":"); buf_json_str(b, color ? color : "ededed");
    buf_addc(b, '}');
}

static void j_issue(Buf *b, Repo *r, Issue *is) {
    buf_addc(b, '{');
    buf_addf(b, "\"id\":%d,", 100000 + is->number);
    buf_adds(b, "\"node_id\":\"\",");
    buf_addf(b, "\"number\":%d,", is->number);
    buf_adds(b, "\"title\":"); buf_json_str(b, is->title); buf_addc(b, ',');
    buf_adds(b, "\"body\":"); buf_json_str(b, is->body ? is->body : ""); buf_addc(b, ',');
    buf_adds(b, "\"state\":"); buf_json_str(b, is->state ? "closed" : "open"); buf_addc(b, ',');
    buf_adds(b, "\"labels\":[");
    for (int i = 0; i < is->nlabels; i++) { if (i) buf_addc(b, ','); j_label(b, is->labels[i], "ededed"); }
    buf_adds(b, "],");
    buf_adds(b, "\"user\":"); j_login(b, r->owner); buf_addc(b, ',');
    buf_adds(b, "\"comments\":");
    buf_addf(b, "%d,", is->ncomments);
    buf_adds(b, "\"html_url\":\"\",\"url\":\"\"");
    buf_addc(b, '}');
}

static void j_pull(Buf *b, Repo *r, Pull *p) {
    const char *state = p->merged ? "closed" : (p->state ? "closed" : "open");
    char hs[41], bs[41];
    sha1_hex(p->head_sha, hs); sha1_hex(p->base_sha, bs);
    buf_addc(b, '{');
    buf_addf(b, "\"id\":%d,", 200000 + p->number);
    buf_adds(b, "\"node_id\":\"\",");
    buf_addf(b, "\"number\":%d,", p->number);
    buf_adds(b, "\"state\":"); buf_json_str(b, state); buf_addc(b, ',');
    buf_adds(b, "\"title\":"); buf_json_str(b, p->title); buf_addc(b, ',');
    buf_adds(b, "\"body\":"); buf_json_str(b, p->body ? p->body : ""); buf_addc(b, ',');
    buf_adds(b, "\"merged\":"); buf_adds(b, p->merged ? "true" : "false"); buf_addc(b, ',');
    buf_adds(b, "\"merged_at\":");
    if (p->merged) { buf_adds(b, "\"2025-01-02T00:00:00Z\""); } else buf_adds(b, "null");
    buf_addc(b, ',');
    if (p->merged) {
        char ms[41]; sha1_hex(p->merge_commit, ms);
        buf_adds(b, "\"merge_commit_sha\":"); buf_json_str(b, ms); buf_addc(b, ',');
    } else { buf_adds(b, "\"merge_commit_sha\":null,"); }
    buf_adds(b, "\"head\":{\"ref\":"); buf_json_str(b, p->head_ref); buf_adds(b, ",\"sha\":"); buf_json_str(b, hs);
    buf_adds(b, ",\"label\":"); buf_json_str(b, p->head_ref); buf_adds(b, ",\"user\":{\"login\":\"\"}},");
    buf_adds(b, "\"base\":{\"ref\":"); buf_json_str(b, p->base_ref); buf_adds(b, ",\"sha\":"); buf_json_str(b, bs);
    buf_adds(b, ",\"label\":"); buf_json_str(b, p->base_ref); buf_adds(b, ",\"user\":{\"login\":\"\"}},");
    buf_adds(b, "\"user\":"); j_login(b, r->owner); buf_addc(b, ',');
    buf_adds(b, "\"html_url\":\"\",\"url\":\"\"");
    buf_addc(b, '}');
}

/* ---------------------------------------------------------------- tree helpers */

typedef struct { char **paths; unsigned char (*oids)[20]; int n, cap; } PathMap;

static void pm_add(PathMap *m, const char *path, const unsigned char oid[20]) {
    if (m->n == m->cap) {
        m->cap = m->cap ? m->cap * 2 : 64;
        m->paths = (char **)realloc(m->paths, (size_t)m->cap * sizeof(char *));
        m->oids = (unsigned char (*)[20])realloc(m->oids, (size_t)m->cap * 20);
    }
    m->paths[m->n] = xstrdup(path);
    memcpy(m->oids[m->n], oid, 20);
    m->n++;
}
static void pm_free(PathMap *m) { for (int i = 0; i < m->n; i++) free(m->paths[i]); free(m->paths); free(m->oids); m->n = m->cap = 0; }
static int pm_find(PathMap *m, const char *path) { for (int i = 0; i < m->n; i++) if (strcmp(m->paths[i], path) == 0) return i; return -1; }

static void flatten(const unsigned char tree[20], const char *prefix, PathMap *m) {
    TreeEnt ents[4096];
    int n = tree_parse(tree, ents, 4096);
    if (n < 0) return;
    for (int i = 0; i < n; i++) {
        char full[2048];
        if (prefix[0]) snprintf(full, sizeof full, "%s/%s", prefix, ents[i].name);
        else snprintf(full, sizeof full, "%s", ents[i].name);
        if (strcmp(ents[i].mode, "40000") == 0) flatten(ents[i].oid, full, m);
        else pm_add(m, full, ents[i].oid);
    }
}

/* ---------------------------------------------------------------- refs */

static int resolve_ref(Repo *r, const char *ref, unsigned char out[20]) {
    if (!ref || !ref[0]) return 0;
    if (strlen(ref) == 40) {
        if (sha1_hex_decode(ref, 40, out) == 0 && obj_exists(out)) return 1;
    }
    char buf[512];
    if (strncmp(ref, "refs/", 5) == 0) snprintf(buf, sizeof buf, "%s", ref);
    else snprintf(buf, sizeof buf, "refs/heads/%s", ref);
    Ref *e = ref_get(r, buf);
    if (e) { memcpy(out, e->oid, 20); return 1; }
    if (strcmp(ref, "HEAD") == 0) {
        char db[512]; snprintf(db, sizeof db, "refs/heads/%s", r->default_branch);
        e = ref_get(r, db);
        if (e) { memcpy(out, e->oid, 20); return 1; }
    }
    return 0;
}

/* ---------------------------------------------------------------- repo routes */

static int err_json(Resp *r, int status, const char *msg) {
    Buf b; buf_init(&b);
    buf_adds(&b, "{\"message\":"); buf_json_str(&b, msg); buf_adds(&b, "}\n");
    resp_json_buf(r, status, &b);
    buf_free(&b);
    return 1;
}

static void list_user_repos(Req *q, Resp *r) {
    size_t vlen;
    int per_page = 30, page = 1;
    const char *pp = query_get(q->query, "per_page", &vlen);
    if (pp) per_page = (int)strtol(pp, NULL, 10);
    const char *pg = query_get(q->query, "page", &vlen);
    if (pg) page = (int)strtol(pg, NULL, 10);
    if (per_page < 1) per_page = 30;
    if (per_page > 100) per_page = 100;
    if (page < 1) page = 1;

    int total = 0;
    for (int i = 0; i < repo_count_all(); i++) {
        Repo *rr = repo_at(i);
        if (strcmp(rr->owner, g_login) == 0) total++;
    }
    int start = (page - 1) * per_page;
    int end = start + per_page > total ? total : start + per_page;

    Buf b; buf_init(&b);
    buf_addc(&b, '[');
    int idx = 0, emitted = 0;
    for (int i = 0; i < repo_count_all(); i++) {
        Repo *rr = repo_at(i);
        if (strcmp(rr->owner, g_login) != 0) continue;
        if (idx >= start && idx < end) { if (emitted) buf_addc(&b, ','); j_repo(&b, rr); emitted++; }
        idx++;
    }
    buf_addc(&b, ']');
    resp_json_buf(r, 200, &b);
    buf_free(&b);

    if (end < total) {
        char host[512]; snprintf(host, sizeof host, "%s", q->host ? q->host : "127.0.0.1");
        char link[1200];
        snprintf(link, sizeof link,
                 "Link: <http://%s/api/v3/user/repos?per_page=%d&page=%d>; rel=\"next\"",
                 host, per_page, page + 1);
        resp_add_header(r, link);
    }
}

/* ---------------------------------------------------------------- git object mutation for contents */

static const char *AUTHOR = "adaiversen <adaiversen@example.invalid>";

static void commit_on_ref(Repo *r, const char *branch, const unsigned char newtree[20],
                          int have_parent, const unsigned char parent[20], const char *message,
                          unsigned char out[20]) {
    unsigned char parents[1][20];
    int np = 0;
    if (have_parent) { memcpy(parents[0], parent, 20); np = 1; }
    commit_build(newtree, parents, np, message, 1735689600L, AUTHOR, out);
    char refname[512]; snprintf(refname, sizeof refname, "refs/heads/%s", branch);
    ref_set(r, refname, out);
}

/* ---------------------------------------------------------------- main router */

/* Split /repos/{owner}/{repo}/... */
static int handle_repo_scoped(Req *q, Resp *r, const char *rest_after_prefix);

int rest_handle(Req *q, Resp *r) {
    const char *p = q->path + 7; /* skip "/api/v3" */
    if (*p == '\0' || strcmp(p, "/") == 0) {
        static const char ROOT[] = "{\"current_user_url\":\"/api/v3/user\",\"user_url\":\"/api/v3/user\",\"repository_url\":\"/api/v3/repos\"}\n";
        resp_json(r, 200, ROOT, sizeof ROOT - 1);
        resp_add_header(r, "X-OAuth-Scopes: repo, read:org");
        return 1;
    }
    if (!is_authed(q)) return err_json(r, 401, "Requires authentication");
    if (strcmp(p, "/meta") == 0) {
        static const char META[] = "{\"installed_version\":\"forgec-1.0.0\",\"verifiable_password_authentication\":false}\n";
        resp_json(r, 200, META, sizeof META - 1);
        return 1;
    }
    if (strcmp(p, "/user") == 0) {
        Buf b; buf_init(&b); j_login(&b, g_login); buf_addc(&b, '\n');
        resp_json_buf(r, 200, &b); buf_free(&b);
        return 1;
    }
    if (strcmp(p, "/user/repos") == 0) {
        if (strcmp(q->method, "GET") == 0) { list_user_repos(q, r); return 1; }
        if (strcmp(q->method, "POST") == 0) {
            if (!json_ok(q->body, q->body_len)) return err_json(r, 400, "Problems parsing JSON");
            char *name = NULL;
            if (!jstr(q->body, q->body_len, "name", &name) || !name || !name[0]) return err_json(r, 422, "Repository name is required");
            char *desc = NULL; jstr(q->body, q->body_len, "description", &desc);
            int priv = 0; jbool(q->body, q->body_len, "private", &priv);
            if (repo_find(g_login, name)) { free(name); free(desc); return err_json(r, 422, "Repository creation failed: name already exists on this account"); }
            Repo *rr = repo_create(g_login, name, desc ? desc : "", priv, "main");
            Buf b; buf_init(&b); j_repo(&b, rr); buf_addc(&b, '\n');
            resp_json_buf(r, 201, &b); buf_free(&b);
            free(name); free(desc);
            return 1;
        }
        return err_json(r, 405, "Method Not Allowed");
    }
    if (strncmp(p, "/repos/", 7) == 0) return handle_repo_scoped(q, r, p + 7);
    return err_json(r, 404, "Not Found");
}

static int handle_repo_scoped(Req *q, Resp *r, const char *rest) {
    /* rest = {owner}/{repo}[/...] */
    const char *slash = strchr(rest, '/');
    if (!slash) return err_json(r, 404, "Not Found");
    char *owner = xstrndup(rest, (size_t)(slash - rest));
    const char *after = slash + 1;
    const char *slash2 = strchr(after, '/');
    char *repo_name = slash2 ? xstrndup(after, (size_t)(slash2 - after)) : xstrdup(after);
    const char *sub = slash2 ? slash2 + 1 : "";

    Repo *rr = repo_find(owner, repo_name);
    /* try pct-decoded names too */
    if (!rr) { char *d = pct_decode(owner, strlen(owner)); Repo *t = repo_find(d, repo_name); free(d); rr = t; }
    if (!rr) { free(owner); free(repo_name); return err_json(r, 404, "Not Found"); }

    int rc = 0;
    /* --- repo root */
    if (sub[0] == '\0') {
        if (strcmp(q->method, "GET") == 0) {
            Buf b; buf_init(&b); j_repo(&b, rr); buf_addc(&b, '\n');
            resp_json_buf(r, 200, &b); buf_free(&b); rc = 1;
        } else if (strcmp(q->method, "PATCH") == 0) {
            if (!json_ok(q->body, q->body_len)) rc = err_json(r, 400, "Problems parsing JSON");
            else {
                char *desc = NULL; int priv;
                if (jstr(q->body, q->body_len, "description", &desc)) { free(rr->description); rr->description = desc; }
                if (jbool(q->body, q->body_len, "private", &priv)) rr->is_private = priv;
                char *nm = NULL; if (jstr(q->body, q->body_len, "name", &nm)) { free(nm); }
                Buf b; buf_init(&b); j_repo(&b, rr); buf_addc(&b, '\n');
                resp_json_buf(r, 200, &b); buf_free(&b); rc = 1;
            }
        } else if (strcmp(q->method, "DELETE") == 0) {
            repo_delete(rr); r->status = 204; rc = 1;
        } else rc = err_json(r, 405, "Method Not Allowed");
        free(owner); free(repo_name); return rc;
    }

    /* --- branches */
    if (strcmp(sub, "branches") == 0 && strcmp(q->method, "GET") == 0) {
        Buf b; buf_init(&b); buf_addc(&b, '[');
        int em = 0;
        for (int i = 0; i < rr->nrefs; i++) {
            if (strncmp(rr->refs[i].name, "refs/heads/", 11) != 0) continue;
            if (em) buf_addc(&b, ',');
            char hx[41]; sha1_hex(rr->refs[i].oid, hx);
            buf_adds(&b, "{\"name\":"); buf_json_str(&b, rr->refs[i].name + 11);
            buf_adds(&b, ",\"commit\":{\"sha\":"); buf_json_str(&b, hx); buf_adds(&b, "}}");
            em++;
        }
        buf_addc(&b, ']');
        resp_json_buf(r, 200, &b); buf_free(&b);
        free(owner); free(repo_name); return 1;
    }

    /* --- commits */
    if (strncmp(sub, "commits", 7) == 0 && (sub[7] == '\0' || sub[7] == '/') && strcmp(q->method, "GET") == 0) {
        size_t vlen;
        const char *shaval = query_get(q->query, "sha", &vlen);
        char ref[512] = "";
        if (shaval) { snprintf(ref, sizeof ref, "%.*s", (int)vlen, shaval); }
        unsigned char tip[20];
        if (ref[0] == '\0') { if (!resolve_ref(rr, rr->default_branch, tip)) { free(owner); free(repo_name); return err_json(r, 409, "Git Repository is empty."); } }
        else if (!resolve_ref(rr, ref, tip)) { free(owner); free(repo_name); return err_json(r, 409, "Git Repository is empty."); }
        Buf b; buf_init(&b); buf_addc(&b, '[');
        unsigned char cur[20]; memcpy(cur, tip, 20);
        int em = 0, guard = 0;
        while (guard++ < 5000) {
            const char *msg; size_t mlen;
            commit_message(cur, &msg, &mlen);
            char hx[41]; sha1_hex(cur, hx);
            if (em) buf_addc(&b, ',');
            buf_adds(&b, "{\"sha\":"); buf_json_str(&b, hx);
            buf_adds(&b, ",\"commit\":{\"message\":");
            buf_json_strn(&b, msg, mlen);
            buf_adds(&b, ",\"author\":{\"name\":\"adaiversen\",\"email\":\"adaiversen@example.invalid\",\"date\":\"2025-01-01T00:00:00Z\"}");
            buf_adds(&b, ",\"committer\":{\"name\":\"adaiversen\",\"email\":\"adaiversen@example.invalid\",\"date\":\"2025-01-01T00:00:00Z\"}}");
            buf_adds(&b, ",\"url\":\"\",\"html_url\":\"\"}");
            em++;
            unsigned char par[20];
            if (commit_first_parent(cur, par) < 0) break;
            memcpy(cur, par, 20);
        }
        buf_addc(&b, ']');
        resp_json_buf(r, 200, &b); buf_free(&b);
        free(owner); free(repo_name); return 1;
    }

    /* --- git/refs */
    if (strncmp(sub, "git/refs", 8) == 0) {
        if (strcmp(q->method, "POST") == 0) {
            if (!json_ok(q->body, q->body_len)) { free(owner); free(repo_name); return err_json(r, 400, "Problems parsing JSON"); }
            char *ref = NULL, *sha = NULL;
            jstr(q->body, q->body_len, "ref", &ref);
            jstr(q->body, q->body_len, "sha", &sha);
            if (!ref || !sha) { free(owner); free(repo_name); free(ref); free(sha); return err_json(r, 422, "ref and sha are required"); }
            unsigned char oid[20];
            if (sha1_hex_decode(sha, 40, oid) < 0) { free(owner); free(repo_name); free(ref); free(sha); return err_json(r, 422, "invalid sha"); }
            ref_set(rr, ref, oid);
            char hx[41]; sha1_hex(oid, hx);
            Buf b; buf_init(&b);
            buf_adds(&b, "{\"ref\":"); buf_json_str(&b, ref);
            buf_adds(&b, ",\"node_id\":\"\",\"url\":\"\",\"object\":{\"sha\":"); buf_json_str(&b, hx);
            buf_adds(&b, ",\"type\":\"commit\",\"url\":\"\"}}\n");
            resp_json_buf(r, 201, &b); buf_free(&b);
            free(ref); free(sha);
            free(owner); free(repo_name); return 1;
        }
        if (strcmp(q->method, "GET") == 0 && strncmp(sub, "git/refs/heads/", 15) == 0) {
            Ref *e = ref_get(rr, sub + 5);
            if (!e) { free(owner); free(repo_name); return err_json(r, 404, "Not Found"); }
            char hx[41]; sha1_hex(e->oid, hx);
            Buf b; buf_init(&b);
            buf_adds(&b, "{\"ref\":"); buf_json_str(&b, sub + 5);
            buf_adds(&b, ",\"object\":{\"sha\":"); buf_json_str(&b, hx); buf_adds(&b, ",\"type\":\"commit\"}}\n");
            resp_json_buf(r, 200, &b); buf_free(&b);
            free(owner); free(repo_name); return 1;
        }
        free(owner); free(repo_name); return err_json(r, 404, "Not Found");
    }

    /* --- contents */
    if (strncmp(sub, "contents", 8) == 0 && (sub[8] == '\0' || sub[8] == '/')) {
        char *path = NULL;
        if (sub[8] == '/') path = pct_decode(sub + 9, strlen(sub + 9)); else path = xstrdup("");
        int done = 0;
        if (strcmp(q->method, "PUT") == 0) {
            if (!json_ok(q->body, q->body_len)) { free(path); free(owner); free(repo_name); return err_json(r, 400, "Problems parsing JSON"); }
            char *msg = NULL, *content = NULL, *branch = NULL, *sha = NULL;
            jstr(q->body, q->body_len, "message", &msg);
            jstr(q->body, q->body_len, "content", &content);
            jstr(q->body, q->body_len, "branch", &branch);
            jstr(q->body, q->body_len, "sha", &sha);
            if (!msg) msg = xstrdup("update");
            if (!content) content = xstrdup("");
            if (!branch) branch = xstrdup(rr->default_branch);

            unsigned char tip[20]; int have_tip = resolve_ref(rr, branch, tip);
            unsigned char tree[20];
            if (have_tip) { if (commit_tree_of(tip, tree) < 0) tree_build(NULL, 0, tree); }
            else tree_build(NULL, 0, tree);

            unsigned char exists[20]; int existed = 0;
            if (have_tip && commit_lookup_path(tip, path, exists, NULL)) existed = 1;
            if (sha && sha[0] && strlen(sha) == 40) {
                unsigned char want[20]; sha1_hex_decode(sha, 40, want);
                if (!existed || memcmp(want, exists, 20) != 0) {
                    free(path); free(owner); free(repo_name); free(msg); free(content); free(branch); free(sha);
                    return err_json(r, 409, "sha does not match the current file");
                }
            }
            Buf raw; buf_init(&raw);
            b64_decode(&raw, content, strlen(content));
            unsigned char blob[20]; obj_put('b', raw.p ? raw.p : "", raw.len, blob);
            buf_free(&raw);
            unsigned char newtree[20];
            tree_set_path(tree, path, blob, 0, newtree);
            unsigned char commit[20];
            commit_on_ref(rr, branch, newtree, have_tip, tip, msg, commit);

            char bh[41], ch[41]; sha1_hex(blob, bh); sha1_hex(commit, ch);
            Buf b; buf_init(&b);
            buf_adds(&b, "{\"content\":{\"name\":\"");
            const char *base = strrchr(path, '/'); buf_adds(&b, base ? base + 1 : path);
            buf_adds(&b, "\",\"path\":"); buf_json_str(&b, path);
            buf_adds(&b, ",\"sha\":"); buf_json_str(&b, bh);
            buf_adds(&b, ",\"size\":"); buf_addf(&b, "%zu", raw.len);
            buf_adds(&b, ",\"type\":\"file\",\"encoding\":\"base64\",\"content\":");
            buf_json_str(&b, content);
            buf_adds(&b, "},\"commit\":{\"sha\":"); buf_json_str(&b, ch);
            buf_adds(&b, ",\"message\":"); buf_json_str(&b, msg);
            buf_adds(&b, ",\"tree\":{\"sha\":\"\"}}}\n");
            resp_json_buf(r, existed ? 200 : 201, &b); buf_free(&b);
            free(msg); free(content); free(branch); free(sha);
            done = 1;
        } else if (strcmp(q->method, "GET") == 0) {
            size_t vlen;
            const char *refp = query_get(q->query, "ref", &vlen);
            char ref[512] = "";
            if (refp) snprintf(ref, sizeof ref, "%.*s", (int)vlen, refp);
            unsigned char tip[20];
            if (!resolve_ref(rr, ref[0] ? ref : rr->default_branch, tip)) { free(path); free(owner); free(repo_name); return err_json(r, 404, "Not Found"); }
            unsigned char oid[20]; int is_tree = 0;
            if (commit_lookup_path(tip, path, oid, &is_tree)) {
                if (!is_tree) {
                    Obj *o = obj_get(oid);
                    const char *base = strrchr(path, '/');
                    Buf b; buf_init(&b);
                    char hx[41]; sha1_hex(oid, hx);
                    buf_adds(&b, "{\"name\":"); buf_json_str(&b, base ? base + 1 : path);
                    buf_adds(&b, ",\"path\":"); buf_json_str(&b, path);
                    buf_adds(&b, ",\"sha\":"); buf_json_str(&b, hx);
                    buf_addf(&b, ",\"size\":%zu", o ? o->len : 0);
                    buf_adds(&b, ",\"type\":\"file\",\"encoding\":\"base64\",\"content\":\"");
                    if (o) { Buf e; buf_init(&e); b64_encode(&e, (const unsigned char *)o->data, o->len); buf_add(&b, e.p, e.len); buf_free(&e); }
                    buf_adds(&b, "\"}\n");
                    resp_json_buf(r, 200, &b); buf_free(&b);
                } else {
                    TreeEnt ents[4096];
                    int n = tree_parse(oid, ents, 4096);
                    Buf b; buf_init(&b); buf_addc(&b, '[');
                    for (int i = 0; i < n; i++) {
                        if (i) buf_addc(&b, ',');
                        char hx[41]; sha1_hex(ents[i].oid, hx);
                        int dir = strcmp(ents[i].mode, "40000") == 0;
                        buf_adds(&b, "{\"name\":"); buf_json_str(&b, ents[i].name);
                        buf_adds(&b, ",\"path\":");
                        { Buf t; buf_init(&t); if (path[0]) buf_addf(&t, "%s/%s", path, ents[i].name); else buf_adds(&t, ents[i].name); buf_json_str(&b, t.p); buf_free(&t); }
                        buf_adds(&b, ",\"sha\":"); buf_json_str(&b, hx);
                        buf_addf(&b, ",\"size\":%d", 0);
                        buf_addf(&b, ",\"type\":\"%s\"}", dir ? "dir" : "file");
                    }
                    buf_addc(&b, ']');
                    resp_json_buf(r, 200, &b); buf_free(&b);
                }
            } else {
                err_json(r, 404, "Not Found");
            }
            done = 1;
        } else if (strcmp(q->method, "DELETE") == 0) {
            char *msg = NULL; jstr(q->body, q->body_len, "message", &msg);
            if (!msg) msg = xstrdup("delete");
            unsigned char tip[20];
            if (!resolve_ref(rr, rr->default_branch, tip)) { free(msg); free(path); free(owner); free(repo_name); return err_json(r, 404, "Not Found"); }
            unsigned char tree[20]; commit_tree_of(tip, tree);
            unsigned char oid[20]; int is_tree = 0;
            if (!commit_lookup_path(tip, path, oid, &is_tree) || is_tree) { free(msg); free(path); free(owner); free(repo_name); return err_json(r, 404, "Not Found"); }
            unsigned char newtree[20]; tree_del_path(tree, path, newtree);
            unsigned char commit[20];
            commit_on_ref(rr, rr->default_branch, newtree, 1, tip, msg, commit);
            char ch[41]; sha1_hex(commit, ch);
            Buf b; buf_init(&b);
            buf_adds(&b, "{\"commit\":{\"sha\":"); buf_json_str(&b, ch); buf_adds(&b, ",\"message\":"); buf_json_str(&b, msg);
            buf_adds(&b, ",\"tree\":{\"sha\":\"\"}}}\n");
            resp_json_buf(r, 200, &b); buf_free(&b);
            free(msg); done = 1;
        }
        free(path);
        if (done) { free(owner); free(repo_name); return 1; }
        free(owner); free(repo_name); return err_json(r, 404, "Not Found");
    }

    /* --- labels */
    if (strcmp(sub, "labels") == 0 && strcmp(q->method, "POST") == 0) {
        if (!json_ok(q->body, q->body_len)) { free(owner); free(repo_name); return err_json(r, 400, "Problems parsing JSON"); }
        char *name = NULL, *color = NULL;
        jstr(q->body, q->body_len, "name", &name);
        jstr(q->body, q->body_len, "color", &color);
        if (!name) { free(color); free(owner); free(repo_name); return err_json(r, 422, "name is required"); }
        if (!label_exists(rr, name)) {
            rr->labels = (Label *)realloc(rr->labels, (size_t)(rr->nlabels + 1) * sizeof(Label));
            rr->labels[rr->nlabels].name = xstrdup(name);
            rr->labels[rr->nlabels].color = xstrdup(color ? color : "ededed");
            rr->nlabels++;
        }
        Buf b; buf_init(&b); j_label(&b, name, color); buf_addc(&b, '\n');
        resp_json_buf(r, 201, &b); buf_free(&b);
        free(name); free(color);
        free(owner); free(repo_name); return 1;
    }

    /* --- issues */
    if (strncmp(sub, "issues", 6) == 0 && (sub[6] == '\0' || sub[6] == '/')) {
        const char *irest = sub + 6;
        if (irest[0] == '\0') {
            if (strcmp(q->method, "POST") == 0) {
                if (!json_ok(q->body, q->body_len)) { free(owner); free(repo_name); return err_json(r, 400, "Problems parsing JSON"); }
                char *title = NULL, *body = NULL;
                jstr(q->body, q->body_len, "title", &title);
                jstr(q->body, q->body_len, "body", &body);
                char *labels[64]; int nl = jstr_array(q->body, q->body_len, "labels", labels, 64);
                for (int i = 0; i < nl; i++) {
                    if (!label_exists(rr, labels[i])) {
                        for (int j = 0; j < nl; j++) free(labels[j]);
                        free(title); free(body); free(owner); free(repo_name);
                        return err_json(r, 422, "Validation Failed: label does not exist");
                    }
                }
                Issue *is = NULL;
                if (rr->nissues == 0) rr->issues = NULL;
                rr->issues = (Issue *)realloc(rr->issues, (size_t)(rr->nissues + 1) * sizeof(Issue));
                is = &rr->issues[rr->nissues];
                memset(is, 0, sizeof *is);
                is->number = rr->next_issue++;
                is->title = xstrdup(title ? title : "");
                is->body = xstrdup(body ? body : "");
                is->state = 0;
                is->user = xstrdup(rr->owner);
                if (nl > 0) { is->labels = (char **)malloc((size_t)nl * sizeof(char *)); for (int i = 0; i < nl; i++) is->labels[i] = xstrdup(labels[i]); is->nlabels = nl; }
                rr->nissues++;
                Buf b; buf_init(&b); j_issue(&b, rr, is); buf_addc(&b, '\n');
                resp_json_buf(r, 201, &b); buf_free(&b);
                for (int i = 0; i < nl; i++) free(labels[i]);
                free(title); free(body); free(owner); free(repo_name); return 1;
            }
            if (strcmp(q->method, "GET") == 0) {
                size_t vlen;
                const char *st = query_get(q->query, "state", &vlen);
                char state[32] = "open";
                if (st) snprintf(state, sizeof state, "%.*s", (int)vlen, st);
                const char *srt = query_get(q->query, "sort", &vlen);
                char sort[32] = ""; if (srt) snprintf(sort, sizeof sort, "%.*s", (int)vlen, srt);
                const char *dir = query_get(q->query, "direction", &vlen);
                char direction[16] = "desc"; if (dir) snprintf(direction, sizeof direction, "%.*s", (int)vlen, dir);
                int idxs[8192]; int n = 0;
                for (int i = 0; i < rr->nissues; i++) {
                    int istate = rr->issues[i].state;
                    if (strcmp(state, "all") != 0) {
                        if (strcmp(state, "open") == 0 && istate != 0) continue;
                        if (strcmp(state, "closed") == 0 && istate != 1) continue;
                    }
                    if (n < 8192) idxs[n++] = i;
                }
                /* sort by number */
                for (int i = 1; i < n; i++) { int k = idxs[i]; int j = i - 1;
                    while (j >= 0 && ((strcmp(direction, "asc") == 0) ? (rr->issues[idxs[j]].number > rr->issues[k].number) : (rr->issues[idxs[j]].number < rr->issues[k].number))) { idxs[j + 1] = idxs[j]; j--; }
                    idxs[j + 1] = k; }
                Buf b; buf_init(&b); buf_addc(&b, '[');
                for (int i = 0; i < n; i++) { if (i) buf_addc(&b, ','); j_issue(&b, rr, &rr->issues[idxs[i]]); }
                buf_addc(&b, ']');
                resp_json_buf(r, 200, &b); buf_free(&b);
                free(owner); free(repo_name); return 1;
            }
            free(owner); free(repo_name); return err_json(r, 405, "Method Not Allowed");
        }
        /* /issues/{n}[/comments] */
        int num = (int)strtol(irest + 1, NULL, 10);
        const char *after_num = strchr(irest + 1, '/');
        Issue *is = issue_find(rr, num);
        if (!is) { free(owner); free(repo_name); return err_json(r, 404, "Not Found"); }
        if (!after_num) {
            if (strcmp(q->method, "GET") == 0) {
                Buf b; buf_init(&b); j_issue(&b, rr, is); buf_addc(&b, '\n');
                resp_json_buf(r, 200, &b); buf_free(&b);
                free(owner); free(repo_name); return 1;
            }
            if (strcmp(q->method, "PATCH") == 0) {
                char *state = NULL; jstr(q->body, q->body_len, "state", &state);
                if (state) { is->state = strcmp(state, "closed") == 0 ? 1 : 0; free(state); }
                char *title = NULL; if (jstr(q->body, q->body_len, "title", &title)) { free(is->title); is->title = title; }
                Buf b; buf_init(&b); j_issue(&b, rr, is); buf_addc(&b, '\n');
                resp_json_buf(r, 200, &b); buf_free(&b);
                free(owner); free(repo_name); return 1;
            }
            free(owner); free(repo_name); return err_json(r, 405, "Method Not Allowed");
        }
        if (strcmp(after_num + 1, "comments") == 0) {
            if (strcmp(q->method, "POST") == 0) {
                if (!json_ok(q->body, q->body_len)) { free(owner); free(repo_name); return err_json(r, 400, "Problems parsing JSON"); }
                char *body = NULL; jstr(q->body, q->body_len, "body", &body);
                is->comments = (Comment *)realloc(is->comments, (size_t)(is->ncomments + 1) * sizeof(Comment));
                Comment *cm = &is->comments[is->ncomments];
                memset(cm, 0, sizeof *cm);
                cm->id = store_next_comment_id();
                cm->body = xstrdup(body ? body : "");
                cm->user = xstrdup(rr->owner);
                cm->created = 1735689600L;
                is->ncomments++;
                Buf b; buf_init(&b);
                buf_addf(&b, "{\"id\":%llu,\"node_id\":\"\",\"body\":", (unsigned long long)cm->id);
                buf_json_str(&b, cm->body);
                buf_adds(&b, ",\"user\":{\"login\":\"adaiversen\"},\"created_at\":\"2025-01-01T00:00:00Z\",\"url\":\"\"}\n");
                resp_json_buf(r, 201, &b); buf_free(&b);
                free(body); free(owner); free(repo_name); return 1;
            }
            if (strcmp(q->method, "GET") == 0) {
                Buf b; buf_init(&b); buf_addc(&b, '[');
                for (int i = 0; i < is->ncomments; i++) {
                    if (i) buf_addc(&b, ',');
                    buf_addf(&b, "{\"id\":%llu,\"body\":", (unsigned long long)is->comments[i].id);
                    buf_json_str(&b, is->comments[i].body);
                    buf_adds(&b, ",\"user\":{\"login\":\"adaiversen\"},\"created_at\":\"2025-01-01T00:00:00Z\"}");
                }
                buf_addc(&b, ']');
                resp_json_buf(r, 200, &b); buf_free(&b);
                free(owner); free(repo_name); return 1;
            }
            free(owner); free(repo_name); return err_json(r, 405, "Method Not Allowed");
        }
        free(owner); free(repo_name); return err_json(r, 404, "Not Found");
    }

    /* --- pulls */
    if (strncmp(sub, "pulls", 5) == 0 && (sub[5] == '\0' || sub[5] == '/')) {
        const char *prest = sub + 5;
        if (prest[0] == '\0') {
            if (strcmp(q->method, "POST") == 0) {
                if (!json_ok(q->body, q->body_len)) { free(owner); free(repo_name); return err_json(r, 400, "Problems parsing JSON"); }
                char *head = NULL, *base = NULL, *title = NULL, *body = NULL;
                jstr(q->body, q->body_len, "head", &head);
                jstr(q->body, q->body_len, "base", &base);
                jstr(q->body, q->body_len, "title", &title);
                jstr(q->body, q->body_len, "body", &body);
                if (!head || !base) { free(head); free(base); free(title); free(body); free(owner); free(repo_name); return err_json(r, 422, "head and base are required"); }
                unsigned char hsha[20], bsha[20];
                if (!resolve_ref(rr, head, hsha) || !resolve_ref(rr, base, bsha)) {
                    free(head); free(base); free(title); free(body); free(owner); free(repo_name);
                    return err_json(r, 422, "Validation Failed: base or head does not exist");
                }
                rr->pulls = (Pull *)realloc(rr->pulls, (size_t)(rr->npulls + 1) * sizeof(Pull));
                Pull *p = &rr->pulls[rr->npulls]; memset(p, 0, sizeof *p);
                p->number = rr->next_pull++;
                p->title = xstrdup(title ? title : "");
                p->body = xstrdup(body ? body : "");
                p->state = 0; p->merged = 0;
                p->head_ref = xstrdup(head);
                p->base_ref = xstrdup(base);
                memcpy(p->head_sha, hsha, 20); memcpy(p->base_sha, bsha, 20);
                p->user = xstrdup(rr->owner);
                rr->npulls++;
                Buf b; buf_init(&b); j_pull(&b, rr, p); buf_addc(&b, '\n');
                resp_json_buf(r, 201, &b); buf_free(&b);
                free(head); free(base); free(title); free(body); free(owner); free(repo_name); return 1;
            }
            if (strcmp(q->method, "GET") == 0) {
                size_t vlen;
                const char *st = query_get(q->query, "state", &vlen);
                char state[32] = "open"; if (st) snprintf(state, sizeof state, "%.*s", (int)vlen, st);
                Buf b; buf_init(&b); buf_addc(&b, '[');
                int em = 0;
                for (int i = 0; i < rr->npulls; i++) {
                    Pull *p = &rr->pulls[i];
                    int open = !p->state && !p->merged;
                    if (strcmp(state, "open") == 0 && !open) continue;
                    if (em) buf_addc(&b, ',');
                    j_pull(&b, rr, p);
                    em++;
                }
                buf_addc(&b, ']');
                resp_json_buf(r, 200, &b); buf_free(&b);
                free(owner); free(repo_name); return 1;
            }
            free(owner); free(repo_name); return err_json(r, 405, "Method Not Allowed");
        }
        int num = (int)strtol(prest + 1, NULL, 10);
        const char *after_num = strchr(prest + 1, '/');
        Pull *p = pull_find(rr, num);
        if (!after_num) {
            if (!p) { free(owner); free(repo_name); return err_json(r, 404, "Not Found"); }
            if (strcmp(q->method, "GET") == 0) {
                Buf b; buf_init(&b); j_pull(&b, rr, p); buf_addc(&b, '\n');
                resp_json_buf(r, 200, &b); buf_free(&b);
                free(owner); free(repo_name); return 1;
            }
            free(owner); free(repo_name); return err_json(r, 405, "Method Not Allowed");
        }
        if (!p) { free(owner); free(repo_name); return err_json(r, 404, "Not Found"); }
        if (strcmp(after_num + 1, "files") == 0 && strcmp(q->method, "GET") == 0) {
            PathMap base_m, head_m;
            memset(&base_m, 0, sizeof base_m); memset(&head_m, 0, sizeof head_m);
            unsigned char btree[20], htree[20];
            if (commit_tree_of(p->base_sha, btree) == 0) flatten(btree, "", &base_m);
            if (commit_tree_of(p->head_sha, htree) == 0) flatten(htree, "", &head_m);
            Buf b; buf_init(&b); buf_addc(&b, '[');
            int em = 0;
            for (int i = 0; i < head_m.n; i++) {
                int bi = pm_find(&base_m, head_m.paths[i]);
                int changed = (bi < 0) || (memcmp(base_m.oids[bi], head_m.oids[i], 20) != 0);
                if (!changed) continue;
                Obj *o = obj_get(head_m.oids[i]);
                int adds = 0; if (o) { adds = 1; for (size_t k = 0; k < o->len; k++) if (o->data[k] == '\n') adds++; }
                int dels = 0;
                if (bi >= 0) { Obj *ob = obj_get(base_m.oids[bi]); if (ob) { dels = 1; for (size_t k = 0; k < ob->len; k++) if (ob->data[k] == '\n') dels++; } }
                if (em) buf_addc(&b, ',');
                buf_adds(&b, "{\"sha\":\"\",\"filename\":"); buf_json_str(&b, head_m.paths[i]);
                buf_adds(&b, ",\"status\":");
                buf_json_str(&b, bi < 0 ? "added" : "modified");
                buf_addf(&b, ",\"additions\":%d,\"deletions\":%d,\"changes\":%d", adds, dels, adds + dels);
                buf_adds(&b, ",\"blob_url\":\"\",\"raw_url\":\"\"}");
                em++;
            }
            buf_addc(&b, ']');
            resp_json_buf(r, 200, &b); buf_free(&b);
            pm_free(&base_m); pm_free(&head_m);
            free(owner); free(repo_name); return 1;
        }
        if (strcmp(after_num + 1, "merge") == 0 && strcmp(q->method, "PUT") == 0) {
            if (p->merged) { free(owner); free(repo_name); return err_json(r, 405, "Pull Request is not mergeable"); }
            unsigned char tip[20];
            if (!resolve_ref(rr, p->base_ref, tip) || memcmp(tip, p->base_sha, 20) != 0) {
                free(owner); free(repo_name);
                return err_json(r, 405, "Pull Request is not mergeable");
            }
            unsigned char htree[20]; commit_tree_of(p->head_sha, htree);
            unsigned char parents[1][20]; memcpy(parents[0], tip, 20);
            char msg[256]; snprintf(msg, sizeof msg, "Merge pull request #%d from %s", p->number, p->head_ref);
            unsigned char mc[20];
            commit_build(htree, parents, 1, msg, 1735689600L, AUTHOR, mc);
            char bname[512]; snprintf(bname, sizeof bname, "refs/heads/%s", p->base_ref);
            ref_set(rr, bname, mc);
            p->merged = 1; p->state = 1; memcpy(p->merge_commit, mc, 20); p->has_merge = 1;
            char mh[41]; sha1_hex(mc, mh);
            Buf b; buf_init(&b);
            buf_adds(&b, "{\"sha\":"); buf_json_str(&b, mh);
            buf_adds(&b, ",\"merged\":true,\"message\":\"Pull Request successfully merged\"}\n");
            resp_json_buf(r, 200, &b); buf_free(&b);
            free(owner); free(repo_name); return 1;
        }
        free(owner); free(repo_name); return err_json(r, 404, "Not Found");
    }

    free(owner); free(repo_name);
    return err_json(r, 404, "Not Found");
}

int tree_list_entries(const unsigned char id[20], TreeEnt *out, int max) { return tree_parse(id, out, max); }
