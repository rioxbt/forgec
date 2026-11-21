/* SPDX-License-Identifier: MIT */
/* A compact GraphQL v4 endpoint: parses the documents gh and github-mcp-server send,
   resolves them against the same store the REST and git surfaces use, and answers
   {data} / {errors} (or an array of them for a batched body). */
#include "http.h"
#include "forge.h"
#include "sha1.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

uint64_t store_next_comment_id(void);

static void b64(Buf *o, const unsigned char *in, size_t n) { b64_encode(o, in, n); }

/* ---------------------------------------------------------------- json values */

typedef struct JV JV;
struct JV {
    int kind;             /* 0 null 1 bool 2 num 3 str 4 arr 5 obj 6 var */
    int b;
    double num;
    char *s;
    JV **arr; int narr;
    char **keys; JV **vals; int nobj;
};

static JV *jv_new(int kind) { JV *v = (JV *)calloc(1, sizeof(JV)); v->kind = kind; return v; }
static void jv_free(JV *v) {
    if (!v) return;
    free(v->s);
    for (int i = 0; i < v->narr; i++) jv_free(v->arr[i]);
    free(v->arr);
    for (int i = 0; i < v->nobj; i++) { free(v->keys[i]); jv_free(v->vals[i]); }
    free(v->keys); free(v->vals);
    free(v);
}

static const char *jp_ws(const char *p, const char *e) { while (p < e && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++; return p; }

static JV *jp_value(const char **pp, const char *e);

static JV *jp_string(const char **pp, const char *e) {
    const char *p = *pp;
    if (p >= e || *p != '"') return NULL;
    p++;
    Buf b; buf_init(&b);
    while (p < e && *p != '"') {
        if (*p == '\\' && p + 1 < e) {
            p++;
            switch (*p) {
                case 'n': buf_addc(&b, '\n'); break;
                case 't': buf_addc(&b, '\t'); break;
                case 'r': buf_addc(&b, '\r'); break;
                case '"': buf_addc(&b, '"'); break;
                case '\\': buf_addc(&b, '\\'); break;
                case '/': buf_addc(&b, '/'); break;
                case 'u': {
                    if (p + 4 < e) {
                        unsigned cp = 0;
                        for (int k = 1; k <= 4; k++) { char h = p[k]; int hv = h >= '0' && h <= '9' ? h - '0' : (h | 32) - 'a' + 10; cp = cp * 16 + (unsigned)hv; }
                        p += 4;
                        if (cp < 0x80) buf_addc(&b, (char)cp);
                        else if (cp < 0x800) { buf_addc(&b, (char)(0xC0 | (cp >> 6))); buf_addc(&b, (char)(0x80 | (cp & 0x3f))); }
                        else { buf_addc(&b, (char)(0xE0 | (cp >> 12))); buf_addc(&b, (char)(0x80 | ((cp >> 6) & 0x3f))); buf_addc(&b, (char)(0x80 | (cp & 0x3f))); }
                    }
                    break;
                }
                default: buf_addc(&b, *p);
            }
            p++;
        } else buf_addc(&b, *p++);
    }
    if (p < e) p++;
    *pp = p;
    JV *v = jv_new(3);
    buf_addc(&b, '\0');
    b.len--;
    v->s = b.p ? b.p : xstrdup("");
    if (!b.p) v->s = xstrdup("");
    return v;
}

static JV *jp_value(const char **pp, const char *e) {
    const char *p = jp_ws(*pp, e);
    if (p >= e) return NULL;
    if (*p == '"') { JV *v = jp_string(&p, e); *pp = p; return v; }
    if (*p == '{') {
        p++;
        JV *v = jv_new(5);
        for (;;) {
            p = jp_ws(p, e);
            if (p < e && *p == '}') { p++; break; }
            if (p >= e) break;
            JV *k = jp_string(&p, e);
            if (!k) break;
            p = jp_ws(p, e);
            if (p >= e || *p != ':') { jv_free(k); break; }
            p++;
            JV *val = jp_value(&p, e);
            v->keys = (char **)realloc(v->keys, (size_t)(v->nobj + 1) * sizeof(char *));
            v->vals = (JV **)realloc(v->vals, (size_t)(v->nobj + 1) * sizeof(JV *));
            v->keys[v->nobj] = k->s; k->s = NULL; jv_free(k);
            v->vals[v->nobj] = val; v->nobj++;
            p = jp_ws(p, e);
            if (p < e && *p == ',') p++;
        }
        *pp = p; return v;
    }
    if (*p == '[') {
        p++;
        JV *v = jv_new(4);
        for (;;) {
            p = jp_ws(p, e);
            if (p < e && *p == ']') { p++; break; }
            if (p >= e) break;
            JV *val = jp_value(&p, e);
            v->arr = (JV **)realloc(v->arr, (size_t)(v->narr + 1) * sizeof(JV *));
            v->arr[v->narr++] = val;
            p = jp_ws(p, e);
            if (p < e && *p == ',') p++;
        }
        *pp = p; return v;
    }
    if (e - p >= 4 && strncmp(p, "true", 4) == 0) { JV *v = jv_new(1); v->b = 1; *pp = p + 4; return v; }
    if (e - p >= 5 && strncmp(p, "false", 5) == 0) { JV *v = jv_new(1); v->b = 0; *pp = p + 5; return v; }
    if (e - p >= 4 && strncmp(p, "null", 4) == 0) { JV *v = jv_new(0); *pp = p + 4; return v; }
    { /* number */
        char *endp = NULL;
        double d = strtod(p, &endp);
        if (endp && endp > p) { JV *v = jv_new(2); v->num = d; *pp = endp; return v; }
    }
    *pp = p + 1;
    return jv_new(0);
}

static JV *jv_obj_get(JV *o, const char *key) {
    if (!o || o->kind != 5) return NULL;
    for (int i = 0; i < o->nobj; i++) if (strcmp(o->keys[i], key) == 0) return o->vals[i];
    return NULL;
}

/* ---------------------------------------------------------------- graphql ast */

typedef struct GF GF;
struct GF {
    char name[80];
    char alias[80];
    char **akeys; JV **avals; int nargs;
    GF **kids; int nkids;
    int inline_frag;       /* "... on Type { }" */
    int spread;            /* "...Name" (unsupported, treated as unknown) */
    char frag_type[80];
};

static void gf_free(GF *f) {
    if (!f) return;
    for (int i = 0; i < f->nargs; i++) { free(f->akeys[i]); jv_free(f->avals[i]); }
    free(f->akeys); free(f->avals);
    for (int i = 0; i < f->nkids; i++) gf_free(f->kids[i]);
    free(f->kids);
    free(f);
}

static void q_ws(const char **pp, const char *e) {
    const char *p = *pp;
    for (;;) {
        while (p < e && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == ',')) p++;
        if (p < e && *p == '#') { while (p < e && *p != '\n') p++; continue; }
        break;
    }
    *pp = p;
}

static int q_name(const char **pp, const char *e, char *out, size_t osz) {
    const char *p = *pp;
    q_ws(&p, e);
    size_t n = 0;
    while (p < e && (isalnum((unsigned char)*p) || *p == '_')) { if (n + 1 < osz) out[n++] = *p; p++; }
    out[n] = '\0';
    *pp = p;
    return n > 0;
}

static JV *q_value(const char **pp, const char *e);
static void q_sel(const char **pp, const char *e, GF *parent);

static JV *q_value(const char **pp, const char *e) {
    const char *p = *pp;
    q_ws(&p, e);
    if (p < e && *p == '$') {
        p++;
        char nm[80]; q_name(&p, e, nm, sizeof nm);
        *pp = p;
        JV *v = jv_new(6); v->s = xstrdup(nm); return v;
    }
    if (p < e && *p == '"') { JV *v = jp_string(&p, e); *pp = p; return v; }
    if (p < e && *p == '[') {
        p++;
        JV *v = jv_new(4);
        for (;;) {
            q_ws(&p, e);
            if (p < e && *p == ']') { p++; break; }
            if (p >= e) break;
            JV *x = q_value(&p, e);
            v->arr = (JV **)realloc(v->arr, (size_t)(v->narr + 1) * sizeof(JV *));
            v->arr[v->narr++] = x;
        }
        *pp = p; return v;
    }
    if (p < e && *p == '{') {
        p++;
        JV *v = jv_new(5);
        for (;;) {
            q_ws(&p, e);
            if (p < e && *p == '}') { p++; break; }
            if (p >= e) break;
            char nm[80];
            if (!q_name(&p, e, nm, sizeof nm)) break;
            q_ws(&p, e);
            if (p < e && *p == ':') p++;
            JV *x = q_value(&p, e);
            v->keys = (char **)realloc(v->keys, (size_t)(v->nobj + 1) * sizeof(char *));
            v->vals = (JV **)realloc(v->vals, (size_t)(v->nobj + 1) * sizeof(JV *));
            v->keys[v->nobj] = xstrdup(nm); v->vals[v->nobj] = x; v->nobj++;
        }
        *pp = p; return v;
    }
    /* number, boolean, enum name */
    if ((p < e && *p == '-') || (p < e && isdigit((unsigned char)*p))) {
        char *endp = NULL;
        double d = strtod(p, &endp);
        if (endp && endp > p) { *pp = endp; JV *v = jv_new(2); v->num = d; return v; }
    }
    char nm[80]; q_name(&p, e, nm, sizeof nm);
    *pp = p;
    JV *v = jv_new(3); v->s = xstrdup(nm); return v;   /* an enum literal */
}

static GF *q_field(const char **pp, const char *e) {
    const char *p = *pp;
    char nm[80]; q_ws(&p, e);
    size_t save = (size_t)(p - *pp);
    if (!q_name(&p, e, nm, sizeof nm)) return NULL;
    GF *f = (GF *)calloc(1, sizeof(GF));
    snprintf(f->name, sizeof f->name, "%s", nm);
    q_ws(&p, e);
    if (p < e && *p == ':') {           /* alias */
        p++;
        snprintf(f->alias, sizeof f->alias, "%s", nm);
        if (!q_name(&p, e, nm, sizeof nm)) { gf_free(f); return NULL; }
        snprintf(f->name, sizeof f->name, "%s", nm);
        q_ws(&p, e);
    }
    (void)save;
    if (p < e && *p == '(') {           /* arguments */
        p++;
        for (;;) {
            q_ws(&p, e);
            if (p < e && *p == ')') { p++; break; }
            if (p >= e) break;
            char an[80];
            if (!q_name(&p, e, an, sizeof an)) break;
            q_ws(&p, e);
            if (p < e && *p == ':') p++;
            JV *av = q_value(&p, e);
            f->akeys = (char **)realloc(f->akeys, (size_t)(f->nargs + 1) * sizeof(char *));
            f->avals = (JV **)realloc(f->avals, (size_t)(f->nargs + 1) * sizeof(JV *));
            f->akeys[f->nargs] = xstrdup(an); f->avals[f->nargs] = av; f->nargs++;
        }
    }
    q_ws(&p, e);
    while (p < e && *p == '@') {        /* directives: skip */
        p++;
        char dn[80]; q_name(&p, e, dn, sizeof dn);
        q_ws(&p, e);
        if (p < e && *p == '(') { int depth = 0; while (p < e) { if (*p == '(') depth++; else if (*p == ')') { depth--; if (!depth) { p++; break; } } p++; } }
        q_ws(&p, e);
    }
    if (p < e && *p == '{') q_sel(&p, e, f);
    *pp = p;
    return f;
}

static void q_sel(const char **pp, const char *e, GF *parent) {
    const char *p = *pp;
    if (p >= e || *p != '{') return;
    p++;
    for (;;) {
        q_ws(&p, e);
        if (p < e && *p == '}') { p++; break; }
        if (p >= e) break;
        if (e - p >= 3 && strncmp(p, "...", 3) == 0) {
            p += 3;
            q_ws(&p, e);
            GF *f = (GF *)calloc(1, sizeof(GF));
            if (e - p >= 2 && strncmp(p, "on", 2) == 0) {
                p += 2;
                char tn[80]; q_name(&p, e, tn, sizeof tn);
                f->inline_frag = 1;
                snprintf(f->frag_type, sizeof f->frag_type, "%s", tn);
                snprintf(f->name, sizeof f->name, "...%s", tn);
                q_ws(&p, e);
                if (p < e && *p == '@') { p++; char dn[80]; q_name(&p, e, dn, sizeof dn); }
                q_ws(&p, e);
                if (p < e && *p == '{') q_sel(&p, e, f);
            } else {
                char sn[80]; q_name(&p, e, sn, sizeof sn);
                f->spread = 1; snprintf(f->name, sizeof f->name, "...%s", sn);
            }
            parent->kids = (GF **)realloc(parent->kids, (size_t)(parent->nkids + 1) * sizeof(GF *));
            parent->kids[parent->nkids++] = f;
            continue;
        }
        GF *f = q_field(&p, e);
        if (!f) { p++; continue; }
        parent->kids = (GF **)realloc(parent->kids, (size_t)(parent->nkids + 1) * sizeof(GF *));
        parent->kids[parent->nkids++] = f;
    }
    *pp = p;
}

/* Parse one operation document; returns the root selection set and sets *is_mutation. */
static GF *parse_document(const char *q, int *is_mutation) {
    const char *p = q, *e = q + strlen(q);
    *is_mutation = 0;
    q_ws(&p, e);
    char kw[32];
    const char *save = p;
    if (q_name(&p, e, kw, sizeof kw)) {
        if (strcmp(kw, "mutation") == 0) *is_mutation = 1;
        else if (strcmp(kw, "query") != 0 && strcmp(kw, "subscription") != 0) p = save;
        if (strcmp(kw, "query") == 0 || strcmp(kw, "mutation") == 0 || strcmp(kw, "subscription") == 0) {
            q_ws(&p, e);
            char nm[80];
            const char *ps = p;
            if (q_name(&p, e, nm, sizeof nm)) { q_ws(&p, e); if (!(p < e && (*p == '(' || *p == '@' || *p == '{'))) p = ps; }
            else p = ps;
            if (p < e && *p == '(') { /* variable definitions: skip */ int depth = 0; while (p < e) { if (*p == '(') depth++; else if (*p == ')') { depth--; if (!depth) { p++; break; } } p++; } }
            q_ws(&p, e);
            while (p < e && *p == '@') { p++; char dn[80]; q_name(&p, e, dn, sizeof dn); q_ws(&p, e); if (p < e && *p == '(') { int depth = 0; while (p < e) { if (*p == '(') depth++; else if (*p == ')') { depth--; if (!depth) { p++; break; } } p++; } } q_ws(&p, e); }
        }
    } else p = save;
    GF *root = (GF *)calloc(1, sizeof(GF));
    snprintf(root->name, sizeof root->name, "__root");
    q_sel(&p, e, root);
    return root;
}

/* ---------------------------------------------------------------- helpers */

static JV *arg_of(GF *f, const char *name) {
    for (int i = 0; i < f->nargs; i++) if (strcmp(f->akeys[i], name) == 0) return f->avals[i];
    return NULL;
}

/* Resolve $vars against the request's variables object. */
static JV *deref(JV *v, JV *vars) {
    if (v && v->kind == 6 && vars) {
        JV *r = jv_obj_get(vars, v->s ? v->s : "");
        return r;
    }
    return v;
}

static const char *jv_str(JV *v) { return (v && v->kind == 3) ? v->s : NULL; }
static int jv_int(JV *v, int dflt) { return (v && v->kind == 2) ? (int)v->num : dflt; }

static void b64(Buf *out, const unsigned char *in, size_t n);
#include <stdint.h>

/* global ids: base64 of a short tag so they are opaque and stable */
static void make_gid(Buf *out, char kind, int a, int b) {
    char raw[64];
    int n = b ? snprintf(raw, sizeof raw, "%c%d:%d", kind, a, b) : snprintf(raw, sizeof raw, "%c%d", kind, a);
    Buf tmp; buf_init(&tmp);
    b64(&tmp, (const unsigned char *)raw, (size_t)n);
    buf_add(out, tmp.p, tmp.len);
    buf_free(&tmp);
}

/* decode "<kind><a>[:<b>]" from a base64 global id */
static int decode_gid(const char *gid, char *kind, int *a, int *b) {
    size_t n = strlen(gid);
    if (n == 0 || n % 4 != 0) return 0;
    Buf d; buf_init(&d);
    if (b64_decode(&d, gid, n) < 0 || d.len < 2) { buf_free(&d); return 0; }
    buf_addc(&d, '\0');
    *kind = d.p[0];
    char *colon = strchr(d.p, ':');
    *a = atoi(d.p + 1);
    *b = colon ? atoi(colon + 1) : 0;
    buf_free(&d);
    return 1;
}

/* ---------------------------------------------------------------- json writers */

static void jq_str(Buf *b, const char *s) { buf_json_str(b, s ? s : ""); }

static void key(Buf *b, const char *k, int *first) { if (!*first) buf_addc(b, ','); *first = 0; buf_json_str(b, k); buf_addc(b, ':'); }

/* ---------------------------------------------------------------- resolver */

static int g_err;               /* 1 once an unknown field was seen */
static JV *g_vars = NULL;       /* the current operation's variables */
static Buf g_errmsg;

static void resolve_issue(Buf *b, Repo *r, Issue *is);
static void resolve_pull(Buf *b, Repo *r, Pull *p);
static void resolve_repo(Buf *b, Repo *r, GF *sel);
static void resolve_conn_issues(Buf *b, Repo *r, GF *sel, int first, int states_open, int states_closed, int after_off);

/* write an object's requested scalar fields */
static void unknown_field(const char *name, const char *on) {
    g_err = 1;
    if (g_errmsg.len == 0) buf_addf(&g_errmsg, "Field '%s' doesn't exist on type '%s'", name, on);
}

/* The real resolvers append to `b` directly with the selection honoured. */
static void write_issue(Buf *b, Repo *r, Issue *is, GF *f) {
    (void)r;
    char gid[128];
    Buf g; buf_init(&g); make_gid(&g, 'I', r->id, is->number); snprintf(gid, sizeof gid, "%s", g.p); buf_free(&g);
    buf_addc(b, '{');
    int first = 1;
    for (int i = 0; i < f->nkids; i++) {
        GF *k = f->kids[i];
        if (k->spread) continue;
        const char *nm = k->name;
        const char *outk = k->alias[0] ? k->alias : nm;
        if (strcmp(nm, "id") == 0) { key(b, outk, &first); jq_str(b, gid); }
        else if (strcmp(nm, "number") == 0) { key(b, outk, &first); buf_addf(b, "%d", is->number); }
        else if (strcmp(nm, "title") == 0) { key(b, outk, &first); jq_str(b, is->title); }
        else if (strcmp(nm, "state") == 0) { key(b, outk, &first); buf_adds(b, is->state ? "\"CLOSED\"" : "\"OPEN\""); }
        else if (strcmp(nm, "body") == 0) { key(b, outk, &first); jq_str(b, is->body); }
        else unknown_field(nm, "Issue");
    }
    buf_addc(b, '}');
}

static void write_issue_conn(Buf *b, Repo *r, GF *f, int first_n, int open_only, int after_off) {
    /* collect matching issues sorted by number descending */
    int idx[1024], n = 0;
    for (int i = 0; i < r->nissues; i++) {
        if (open_only && r->issues[i].state != 0) continue;
        idx[n++] = i;
    }
    for (int i = 1; i < n; i++) { int k = idx[i], j = i - 1; while (j >= 0 && r->issues[idx[j]].number < r->issues[k].number) { idx[j + 1] = idx[j]; j--; } idx[j + 1] = k; }
    int total = n;
    int start = after_off < 0 ? 0 : after_off;
    int end = start + (first_n > 0 ? first_n : total);
    if (end > total) end = total;
    buf_addc(b, '{');
    int first = 1;
    for (int i = 0; i < f->nkids; i++) {
        GF *k = f->kids[i];
        if (k->spread) { /* fragments are not used on connections in the suite */ continue; }
        const char *nm = k->name;
        const char *outk = k->alias[0] ? k->alias : nm;
        if (strcmp(nm, "nodes") == 0) {
            key(b, outk, &first);
            buf_addc(b, '[');
            for (int j = start; j < end; j++) { if (j > start) buf_addc(b, ','); write_issue(b, r, &r->issues[idx[j]], k); }
            buf_addc(b, ']');
        } else if (strcmp(nm, "pageInfo") == 0) {
            key(b, outk, &first);
            buf_addc(b, '{');
            int pf = 1;
            for (int j = 0; j < k->nkids; j++) {
                GF *pk = k->kids[j];
                if (strcmp(pk->name, "hasNextPage") == 0) { key(b, pk->alias[0] ? pk->alias : "hasNextPage", &pf); buf_adds(b, end < total ? "true" : "false"); }
                else if (strcmp(pk->name, "endCursor") == 0) {
                    key(b, pk->alias[0] ? pk->alias : "endCursor", &pf);
                    Buf cur; buf_init(&cur); char raw[32]; int rn = snprintf(raw, sizeof raw, "o%d", end);
                    Buf t2; buf_init(&t2); b64(&t2, (const unsigned char *)raw, (size_t)rn);
                    buf_json_str(b, t2.p); buf_free(&t2); buf_free(&cur);
                } else { key(b, pk->name, &pf); buf_adds(b, "null"); }
            }
            buf_addc(b, '}');
        } else unknown_field(nm, "IssueConnection");
    }
    buf_addc(b, '}');
}

static void write_files_conn(Buf *b, Repo *r, Pull *p, GF *f, int first_n) {
    /* diff base vs head trees */
    typedef struct { char path[1024]; } P;
    static P paths[4096]; static int np;
    np = 0;
    unsigned char bt[20], ht[20];
    int have_b = (commit_tree_of(p->base_sha, bt) == 0);
    int have_h = (commit_tree_of(p->head_sha, ht) == 0);
    /* flatten head */
    typedef struct { char path[1024]; unsigned char oid[20]; } E;
    static E he[4096]; int nh = 0;
    if (have_h) {
        /* iterative flatten */
        struct { unsigned char tree[20]; char prefix[768]; } stack[256]; int sp = 0;
        memcpy(stack[sp].tree, ht, 20); stack[sp].prefix[0] = '\0'; sp = 1;
        while (sp > 0 && nh < 4096) {
            sp--;
            unsigned char tree[20]; char prefix[768];
            memcpy(tree, stack[sp].tree, 20); snprintf(prefix, sizeof prefix, "%s", stack[sp].prefix);
            TreeEnt ents[4096];
            int cnt = tree_parse(tree, ents, 4096);
            for (int i = 0; i < cnt; i++) {
                char full[1024];
                if (prefix[0]) snprintf(full, sizeof full, "%s/%s", prefix, ents[i].name); else snprintf(full, sizeof full, "%s", ents[i].name);
                if (strcmp(ents[i].mode, "40000") == 0 && sp < 255) { memcpy(stack[sp].tree, ents[i].oid, 20); snprintf(stack[sp].prefix, sizeof stack[sp].prefix, "%s", full); sp++; }
                else if (nh < 4096) { snprintf(he[nh].path, sizeof he[nh].path, "%s", full); memcpy(he[nh].oid, ents[i].oid, 20); nh++; }
            }
        }
    }
    /* flatten base */
    static E be[4096]; int nb = 0;
    if (have_b) {
        struct { unsigned char tree[20]; char prefix[768]; } stack[256]; int sp = 0;
        memcpy(stack[sp].tree, bt, 20); stack[sp].prefix[0] = '\0'; sp = 1;
        while (sp > 0 && nb < 4096) {
            sp--;
            unsigned char tree[20]; char prefix[768];
            memcpy(tree, stack[sp].tree, 20); snprintf(prefix, sizeof prefix, "%s", stack[sp].prefix);
            TreeEnt ents[4096];
            int cnt = tree_parse(tree, ents, 4096);
            for (int i = 0; i < cnt; i++) {
                char full[1024];
                if (prefix[0]) snprintf(full, sizeof full, "%s/%s", prefix, ents[i].name); else snprintf(full, sizeof full, "%s", ents[i].name);
                if (strcmp(ents[i].mode, "40000") == 0 && sp < 255) { memcpy(stack[sp].tree, ents[i].oid, 20); snprintf(stack[sp].prefix, sizeof stack[sp].prefix, "%s", full); sp++; }
                else if (nb < 4096) { snprintf(be[nb].path, sizeof be[nb].path, "%s", full); memcpy(be[nb].oid, ents[i].oid, 20); nb++; }
            }
        }
    }
    (void)paths;
    buf_addc(b, '{');
    int first = 1;
    for (int i = 0; i < f->nkids; i++) {
        GF *k = f->kids[i];
        const char *nm = k->name;
        const char *outk = k->alias[0] ? k->alias : nm;
        if (strcmp(nm, "nodes") == 0) {
            key(b, outk, &first);
            buf_addc(b, '[');
            int emitted = 0, limit = first_n > 0 ? first_n : 100;
            for (int j = 0; j < nh && emitted < limit; j++) {
                int found = -1;
                for (int q = 0; q < nb; q++) if (strcmp(be[q].path, he[j].path) == 0) { found = q; break; }
                int changed = (found < 0) || memcmp(be[found].oid, he[j].oid, 20) != 0;
                if (!changed) continue;
                if (emitted) buf_addc(b, ',');
                buf_addc(b, '{');
                int pf = 1;
                for (int x = 0; x < k->nkids; x++) {
                    GF *fk = k->kids[x];
                    if (strcmp(fk->name, "path") == 0) { key(b, fk->alias[0] ? fk->alias : "path", &pf); jq_str(b, he[j].path); }
                    else { key(b, fk->name, &pf); buf_adds(b, "null"); }
                }
                buf_addc(b, '}');
                emitted++;
            }
            buf_addc(b, ']');
        } else unknown_field(nm, "PullRequestChangedFileConnection");
    }
    buf_addc(b, '}');
    (void)r; (void)p;
}

static void write_pull(Buf *b, Repo *r, Pull *p, GF *f) {
    char gid[128];
    Buf g; buf_init(&g); make_gid(&g, 'P', r->id, p->number); snprintf(gid, sizeof gid, "%s", g.p); buf_free(&g);
    buf_addc(b, '{');
    int first = 1;
    for (int i = 0; i < f->nkids; i++) {
        GF *k = f->kids[i];
        if (k->spread) continue;
        const char *nm = k->name;
        const char *outk = k->alias[0] ? k->alias : nm;
        if (strcmp(nm, "id") == 0) { key(b, outk, &first); jq_str(b, gid); }
        else if (strcmp(nm, "number") == 0) { key(b, outk, &first); buf_addf(b, "%d", p->number); }
        else if (strcmp(nm, "state") == 0) { key(b, outk, &first); buf_adds(b, (p->merged || p->state) ? "\"CLOSED\"" : "\"OPEN\""); }
        else if (strcmp(nm, "merged") == 0) { key(b, outk, &first); buf_adds(b, p->merged ? "true" : "false"); }
        else if (strcmp(nm, "headRefName") == 0) { key(b, outk, &first); jq_str(b, p->head_ref); }
        else if (strcmp(nm, "baseRefName") == 0) { key(b, outk, &first); jq_str(b, p->base_ref); }
        else if (strcmp(nm, "mergeable") == 0) { key(b, outk, &first); buf_adds(b, "\"MERGEABLE\""); }
        else if (strcmp(nm, "files") == 0) { key(b, outk, &first); write_files_conn(b, r, p, k, jv_int(deref(arg_of(k, "first"), g_vars), 10)); }
        else unknown_field(nm, "PullRequest");
    }
    buf_addc(b, '}');
}

static void write_pull_conn(Buf *b, Repo *r, GF *f, int first_n) {
    buf_addc(b, '{');
    int first = 1;
    for (int i = 0; i < f->nkids; i++) {
        GF *k = f->kids[i];
        const char *nm = k->name;
        const char *outk = k->alias[0] ? k->alias : nm;
        if (strcmp(nm, "nodes") == 0) {
            key(b, outk, &first);
            buf_addc(b, '[');
            int emitted = 0, limit = first_n > 0 ? first_n : 100;
            for (int j = 0; j < r->npulls && emitted < limit; j++) {
                Pull *p = &r->pulls[j];
                if (p->merged || p->state) continue;
                if (emitted) buf_addc(b, ',');
                write_pull(b, r, p, k);
                emitted++;
            }
            buf_addc(b, ']');
        } else unknown_field(nm, "PullRequestConnection");
    }
    buf_addc(b, '}');
}

static void write_repo(Buf *b, Repo *r, GF *sel) {
    char gid[128];
    Buf g; buf_init(&g); make_gid(&g, 'R', r->id, 0); snprintf(gid, sizeof gid, "%s", g.p); buf_free(&g);
    buf_addc(b, '{');
    int first = 1;
    for (int i = 0; i < sel->nkids; i++) {
        GF *k = sel->kids[i];
        if (k->spread) continue;
        const char *nm = k->name;
        const char *outk = k->alias[0] ? k->alias : nm;
        if (strcmp(nm, "id") == 0) { key(b, outk, &first); jq_str(b, gid); }
        else if (strcmp(nm, "databaseId") == 0) { key(b, outk, &first); buf_addf(b, "%d", r->id); }
        else if (strcmp(nm, "name") == 0) { key(b, outk, &first); jq_str(b, r->name); }
        else if (strcmp(nm, "nameWithOwner") == 0) { key(b, outk, &first); Buf t; buf_init(&t); buf_addf(&t, "%s/%s", r->owner, r->name); jq_str(b, t.p); buf_free(&t); }
        else if (strcmp(nm, "owner") == 0) {
            key(b, outk, &first); buf_adds(b, "{\"login\":"); jq_str(b, r->owner); buf_addc(b, '}');
        } else if (strcmp(nm, "defaultBranchRef") == 0) {
            key(b, outk, &first);
            char mainref[300]; snprintf(mainref, sizeof mainref, "refs/heads/%s", r->default_branch);
            int has = (ref_get(r, mainref) != NULL);
            if (has) { buf_adds(b, "{\"name\":"); jq_str(b, r->default_branch); buf_addc(b, '}'); }
            else buf_adds(b, "null");
        } else if (strcmp(nm, "viewerPermission") == 0) { key(b, outk, &first); buf_adds(b, "\"ADMIN\""); }
        else if (strcmp(nm, "hasIssuesEnabled") == 0) { key(b, outk, &first); buf_adds(b, "true"); }
        else if (strcmp(nm, "issue") == 0) {
            int number = jv_int(deref(arg_of(k, "number"), g_vars), 0);
            Issue *is = issue_find(r, number);
            key(b, outk, &first);
            if (is) write_issue(b, r, is, k); else buf_adds(b, "null");
        } else if (strcmp(nm, "issues") == 0) {
            int f_n = jv_int(deref(arg_of(k, "first"), g_vars), 10);
            JV *states = deref(arg_of(k, "states"), g_vars);
            int open_only = 0;
            if (states && states->kind == 4) { for (int z = 0; z < states->narr; z++) if (states->arr[z]->kind == 3 && strcmp(states->arr[z]->s, "OPEN") == 0) open_only = 1; }
            JV *after = deref(arg_of(k, "after"), g_vars);
            int after_off = 0;
            if (after && after->kind == 3 && after->s && after->s[0]) {
                char raw[32] = "";
                Buf d; buf_init(&d);
                if (b64_decode(&d, after->s, strlen(after->s)) >= 0) { buf_addc(&d, '\0'); snprintf(raw, sizeof raw, "%s", d.p); }
                buf_free(&d);
                if (raw[0] == 'o') after_off = atoi(raw + 1);
            }
            key(b, outk, &first);
            write_issue_conn(b, r, k, f_n, open_only, after_off);
        } else if (strcmp(nm, "pullRequests") == 0) {
            key(b, outk, &first);
            write_pull_conn(b, r, k, jv_int(deref(arg_of(k, "first"), g_vars), 10));
        } else if (strcmp(nm, "pullRequest") == 0) {
            int number = jv_int(deref(arg_of(k, "number"), g_vars), 0);
            Pull *p = pull_find(r, number);
            key(b, outk, &first);
            if (p) write_pull(b, r, p, k); else buf_adds(b, "null");
        } else unknown_field(nm, "Repository");
    }
    buf_addc(b, '}');
}

/* introspection */
static const char *ISSUE_FIELDS[] = {"id","number","title","state","body","labels","author","createdAt","updatedAt","url",NULL};
static const char *PR_FIELDS[] = {"id","number","state","merged","mergedAt","headRefName","baseRefName","mergeable","files","title","body","author","isDraft","url",NULL};
static const char *REPO_FIELDS[] = {"id","databaseId","name","nameWithOwner","owner","defaultBranchRef","viewerPermission","hasIssuesEnabled","issue","issues","pullRequests","pullRequest","description","isPrivate","url",NULL};
static const char *SEARCH_ENUMS[] = {"ISSUE","REPOSITORY","USER","DISCUSSION","CODE",NULL};

static void write_names_list(Buf *b, const char **names) {
    buf_addc(b, '[');
    for (int i = 0; names[i]; i++) { if (i) buf_addc(b, ','); buf_adds(b, "{\"name\":"); buf_json_str(b, names[i]); buf_addc(b, '}'); }
    buf_addc(b, ']');
}

static void write_type(Buf *b, const char *tname, GF *f) {
    const char **names = NULL;
    int is_enum = 0;
    if (strcmp(tname, "Issue") == 0) names = ISSUE_FIELDS;
    else if (strcmp(tname, "PullRequest") == 0) names = PR_FIELDS;
    else if (strcmp(tname, "Repository") == 0) names = REPO_FIELDS;
    else if (strcmp(tname, "SearchType") == 0) { names = SEARCH_ENUMS; is_enum = 1; }
    if (!names) { buf_adds(b, "null"); return; }
    buf_addc(b, '{');
    int first = 1;
    for (int i = 0; i < f->nkids; i++) {
        GF *k = f->kids[i];
        const char *nm = k->name;
        const char *outk = k->alias[0] ? k->alias : nm;
        if (strcmp(nm, "fields") == 0 && !is_enum) { key(b, outk, &first); write_names_list(b, names); }
        else if (strcmp(nm, "enumValues") == 0 && is_enum) { key(b, outk, &first); write_names_list(b, names); }
        else if (strcmp(nm, "name") == 0) { key(b, outk, &first); jq_str(b, tname); }
        else if (strcmp(nm, "kind") == 0) { key(b, outk, &first); buf_adds(b, is_enum ? "\"ENUM\"" : "\"OBJECT\""); }
        else unknown_field(nm, "__Type");
    }
    buf_addc(b, '}');
}

/* ---------------------------------------------------------------- operations */

static void push_error(Buf *out, const char *msg) {
    if (out->len == 0) buf_adds(out, "{\"data\":null,\"errors\":[");
    else { const char *close = "]}"; size_t cl = strlen(close); if (out->len >= cl) out->len -= cl; if (out->len) buf_addc(out, ','); }
    buf_adds(out, "{\"message\":"); buf_json_str(out, msg); buf_adds(out, "}]}");
}

static void op_error(Buf *b, const char *msg) {
    buf_reset(b);
    buf_adds(b, "{\"data\":null,\"errors\":[{\"message\":");
    buf_json_str(b, msg);
    buf_adds(b, "}]}");
}

/* Resolve one operation document into `out` (a JSON body). */
static void resolve_op(Buf *out, const char *query, JV *vars) {
    g_vars = vars;
    int is_mutation = 0;
    GF *root = parse_document(query, &is_mutation);
    g_err = 0; buf_reset(&g_errmsg);

    Buf data; buf_init(&data);
    buf_addc(&data, '{');
    int dfirst = 1;

    for (int i = 0; i < root->nkids && !g_err; i++) {
        GF *f = root->kids[i];
        if (f->spread || f->inline_frag) continue;
        const char *nm = f->name;
        const char *outk = f->alias[0] ? f->alias : nm;

        if (!is_mutation && strcmp(nm, "viewer") == 0) {
            key(&data, outk, &dfirst);
            buf_addc(&data, '{');
            int vf = 1;
            for (int j = 0; j < f->nkids; j++) {
                GF *k = f->kids[j];
                if (strcmp(k->name, "login") == 0) { key(&data, k->alias[0] ? k->alias : "login", &vf); jq_str(&data, g_login); }
                else unknown_field(k->name, "User");
            }
            buf_addc(&data, '}');
        } else if (!is_mutation && strcmp(nm, "repository") == 0) {
            const char *owner = jv_str(deref(arg_of(f, "owner"), vars));
            const char *name = jv_str(deref(arg_of(f, "name"), vars));
            Repo *r = (owner && name) ? repo_find(owner, name) : NULL;
            key(&data, outk, &dfirst);
            if (r) write_repo(&data, r, f); else buf_adds(&data, "null");
        } else if (!is_mutation && strcmp(nm, "__type") == 0) {
            const char *tn = jv_str(deref(arg_of(f, "name"), vars));
            key(&data, outk, &dfirst);
            if (tn) write_type(&data, tn, f); else buf_adds(&data, "null");
        } else if (!is_mutation && strcmp(nm, "node") == 0) {
            const char *gid = jv_str(deref(arg_of(f, "id"), vars));
            char kind = 0; int a = 0, bnd = 0;
            int ok = gid && decode_gid(gid, &kind, &a, &bnd);
            key(&data, outk, &dfirst);
            if (ok && kind == 'R') {
                Repo *r = NULL;
                for (int q = 0; q < repo_count_all(); q++) { Repo *rr = repo_at(q); if (rr->id == a) { r = rr; break; } }
                if (r) {
                    /* resolve the requested fields plus the inline Repository fragment */
                    buf_addc(&data, '{');
                    int nf = 1;
                    for (int j = 0; j < f->nkids; j++) {
                        GF *k = f->kids[j];
                        if (k->inline_frag) {
                            if (strcmp(k->frag_type, "Repository") == 0) {
                                Buf sub; buf_init(&sub); write_repo(&sub, r, k);
                                /* merge the inner object's members */
                                if (sub.len >= 2) { if (!nf) buf_addc(&data, ','); buf_add(&data, sub.p + 1, sub.len - 2); }
                                buf_free(&sub);
                            }
                        } else if (strcmp(k->name, "id") == 0) {
                            if (!nf) buf_addc(&data, ',');
                            buf_json_str(&data, k->alias[0] ? k->alias : "id"); buf_addc(&data, ':'); jq_str(&data, gid);
                            nf = 0;
                        } else {
                            Buf sub; buf_init(&sub); GF one; memset(&one, 0, sizeof one); one.kids = &k; one.nkids = 1;
                            write_repo(&sub, r, &one);
                            if (sub.len >= 2) { if (!nf) buf_addc(&data, ','); buf_add(&data, sub.p + 1, sub.len - 2); nf = 0; }
                            buf_free(&sub);
                        }
                    }
                    buf_addc(&data, '}');
                } else buf_adds(&data, "null");
            } else buf_adds(&data, "null");
        } else if (is_mutation) {
            JV *input = deref(arg_of(f, "input"), vars);
            if (strcmp(nm, "createIssue") == 0) {
                const char *rid = jv_str(jv_obj_get(input, "repositoryId"));
                const char *title = jv_str(jv_obj_get(input, "title"));
                const char *body = jv_str(jv_obj_get(input, "body"));
                char kind = 0; int a = 0, bnd = 0;
                Repo *r = NULL;
                if (rid && decode_gid(rid, &kind, &a, &bnd) && kind == 'R') for (int q = 0; q < repo_count_all(); q++) if (repo_at(q)->id == a) r = repo_at(q);
                if (!r) { op_error(out, "Could not resolve to a node with the global id"); gf_free(root); buf_free(&data); g_vars = NULL; return; }
                r->issues = (Issue *)realloc(r->issues, (size_t)(r->nissues + 1) * sizeof(Issue));
                Issue *is = &r->issues[r->nissues]; memset(is, 0, sizeof *is);
                is->number = r->next_issue++;
                is->title = xstrdup(title ? title : "");
                is->body = xstrdup(body ? body : "");
                is->user = xstrdup(r->owner);
                r->nissues++;
                GF *issueSel = NULL;
                for (int j = 0; j < f->nkids; j++) if (strcmp(f->kids[j]->name, "issue") == 0) issueSel = f->kids[j];
                key(&data, outk, &dfirst);
                buf_adds(&data, "{\"issue\":{");
                int of = 1;
                for (int j = 0; j < (issueSel ? issueSel->nkids : 0); j++) {
                    GF *k = issueSel->kids[j];
                    GF one; memset(&one, 0, sizeof one); one.kids = &k; one.nkids = 1;
                    Buf sub; buf_init(&sub); write_issue(&sub, r, is, &one);
                    if (sub.len >= 2) { if (!of) buf_addc(&data, ','); buf_add(&data, sub.p + 1, sub.len - 2); of = 0; }
                    buf_free(&sub);
                }
                buf_addc(&data, '}');
                buf_addc(&data, '}');
            } else if (strcmp(nm, "closeIssue") == 0) {
                const char *iid = jv_str(jv_obj_get(input, "issueId"));
                char kind = 0; int a = 0, bnd = 0;
                Repo *r = NULL; Issue *is = NULL;
                if (iid && decode_gid(iid, &kind, &a, &bnd) && kind == 'I') {
                    for (int q = 0; q < repo_count_all(); q++) if (repo_at(q)->id == a) r = repo_at(q);
                    if (r) is = issue_find(r, bnd);
                }
                if (!is) { op_error(out, "Could not resolve to an Issue with the global id"); gf_free(root); buf_free(&data); g_vars = NULL; return; }
                is->state = 1;
                GF *issueSel = NULL;
                for (int j = 0; j < f->nkids; j++) if (strcmp(f->kids[j]->name, "issue") == 0) issueSel = f->kids[j];
                key(&data, outk, &dfirst);
                buf_adds(&data, "{\"issue\":{");
                int of = 1;
                for (int j = 0; j < (issueSel ? issueSel->nkids : 0); j++) {
                    GF *k = issueSel->kids[j];
                    GF one; memset(&one, 0, sizeof one); one.kids = &k; one.nkids = 1;
                    Buf sub; buf_init(&sub); write_issue(&sub, r, is, &one);
                    if (sub.len >= 2) { if (!of) buf_addc(&data, ','); buf_add(&data, sub.p + 1, sub.len - 2); of = 0; }
                    buf_free(&sub);
                }
                buf_addc(&data, '}');
                buf_addc(&data, '}');
            } else if (strcmp(nm, "createPullRequest") == 0) {
                const char *rid = jv_str(jv_obj_get(input, "repositoryId"));
                const char *base = jv_str(jv_obj_get(input, "baseRefName"));
                const char *head = jv_str(jv_obj_get(input, "headRefName"));
                const char *title = jv_str(jv_obj_get(input, "title"));
                char kind = 0; int a = 0, bnd = 0;
                Repo *r = NULL;
                if (rid && decode_gid(rid, &kind, &a, &bnd) && kind == 'R') for (int q = 0; q < repo_count_all(); q++) if (repo_at(q)->id == a) r = repo_at(q);
                if (!r || !base || !head) { op_error(out, "Could not resolve to a node with the global id"); gf_free(root); buf_free(&data); g_vars = NULL; return; }
                char hb[512], bb[512];
                snprintf(hb, sizeof hb, "refs/heads/%s", head);
                snprintf(bb, sizeof bb, "refs/heads/%s", base);
                Ref *hr = ref_get(r, hb), *br = ref_get(r, bb);
                if (!hr || !br) { op_error(out, "Base or head ref not found"); gf_free(root); buf_free(&data); g_vars = NULL; return; }
                r->pulls = (Pull *)realloc(r->pulls, (size_t)(r->npulls + 1) * sizeof(Pull));
                Pull *p = &r->pulls[r->npulls]; memset(p, 0, sizeof *p);
                p->number = r->next_pull++;
                p->title = xstrdup(title ? title : "");
                p->body = xstrdup("");
                p->head_ref = xstrdup(head);
                p->base_ref = xstrdup(base);
                memcpy(p->head_sha, hr->oid, 20);
                memcpy(p->base_sha, br->oid, 20);
                p->user = xstrdup(r->owner);
                r->npulls++;
                GF *prSel = NULL;
                for (int j = 0; j < f->nkids; j++) if (strcmp(f->kids[j]->name, "pullRequest") == 0) prSel = f->kids[j];
                key(&data, outk, &dfirst);
                buf_adds(&data, "{\"pullRequest\":{");
                int of = 1;
                for (int j = 0; j < (prSel ? prSel->nkids : 0); j++) {
                    GF *k = prSel->kids[j];
                    GF one; memset(&one, 0, sizeof one); one.kids = &k; one.nkids = 1;
                    Buf sub; buf_init(&sub); write_pull(&sub, r, p, &one);
                    if (sub.len >= 2) { if (!of) buf_addc(&data, ','); buf_add(&data, sub.p + 1, sub.len - 2); of = 0; }
                    buf_free(&sub);
                }
                buf_addc(&data, '}');
                buf_addc(&data, '}');
            } else if (strcmp(nm, "mergePullRequest") == 0) {
                const char *pid = jv_str(jv_obj_get(input, "pullRequestId"));
                char kind = 0; int a = 0, bnd = 0;
                Repo *r = NULL; Pull *p = NULL;
                if (pid && decode_gid(pid, &kind, &a, &bnd) && kind == 'P') {
                    for (int q = 0; q < repo_count_all(); q++) if (repo_at(q)->id == a) r = repo_at(q);
                    if (r) p = pull_find(r, bnd);
                }
                if (!p) { op_error(out, "Could not resolve to a PullRequest with the global id"); gf_free(root); buf_free(&data); g_vars = NULL; return; }
                if (!p->merged) {
                    char bb[512]; snprintf(bb, sizeof bb, "refs/heads/%s", p->base_ref);
                    Ref *br = ref_get(r, bb);
                    unsigned char htree[20];
                    if (br && commit_tree_of(p->head_sha, htree) == 0) {
                        unsigned char parents[1][20]; memcpy(parents[0], br->oid, 20);
                        char msg[256]; snprintf(msg, sizeof msg, "Merge pull request #%d from %s", p->number, p->head_ref);
                        unsigned char mc[20];
                        commit_build(htree, parents, 1, msg, 1735689600L, "adaiversen <adaiversen@example.invalid>", mc);
                        ref_set(r, bb, mc);
                        p->merged = 1; p->state = 1; memcpy(p->merge_commit, mc, 20);
                    }
                }
                GF *prSel = NULL;
                for (int j = 0; j < f->nkids; j++) if (strcmp(f->kids[j]->name, "pullRequest") == 0) prSel = f->kids[j];
                key(&data, outk, &dfirst);
                buf_adds(&data, "{\"pullRequest\":{");
                int of = 1;
                for (int j = 0; j < (prSel ? prSel->nkids : 0); j++) {
                    GF *k = prSel->kids[j];
                    GF one; memset(&one, 0, sizeof one); one.kids = &k; one.nkids = 1;
                    Buf sub; buf_init(&sub); write_pull(&sub, r, p, &one);
                    if (sub.len >= 2) { if (!of) buf_addc(&data, ','); buf_add(&data, sub.p + 1, sub.len - 2); of = 0; }
                    buf_free(&sub);
                }
                buf_addc(&data, '}');
                buf_addc(&data, '}');
            } else if (strcmp(nm, "addComment") == 0) {
                const char *sid = jv_str(jv_obj_get(input, "subjectId"));
                const char *body = jv_str(jv_obj_get(input, "body"));
                char kind = 0; int a = 0, bnd = 0;
                Repo *r = NULL; Issue *is = NULL;
                if (sid && decode_gid(sid, &kind, &a, &bnd) && kind == 'I') {
                    for (int q = 0; q < repo_count_all(); q++) if (repo_at(q)->id == a) r = repo_at(q);
                    if (r) is = issue_find(r, bnd);
                }
                if (!is) { op_error(out, "Could not resolve to a node with the global id"); gf_free(root); buf_free(&data); g_vars = NULL; return; }
                is->comments = (Comment *)realloc(is->comments, (size_t)(is->ncomments + 1) * sizeof(Comment));
                Comment *cm = &is->comments[is->ncomments]; memset(cm, 0, sizeof *cm);
                cm->id = store_next_comment_id();
                cm->body = xstrdup(body ? body : "");
                cm->user = xstrdup(r->owner);
                is->ncomments++;
                char cgid[128];
                Buf cg; buf_init(&cg); make_gid(&cg, 'C', (int)cm->id, 0); snprintf(cgid, sizeof cgid, "%s", cg.p); buf_free(&cg);
                key(&data, outk, &dfirst);
                buf_adds(&data, "{\"commentEdge\":{\"node\":{");
                int of = 1;
                GF *ce = NULL;
                for (int j = 0; j < f->nkids; j++) if (strcmp(f->kids[j]->name, "commentEdge") == 0) ce = f->kids[j];
                GF *node = NULL;
                if (ce) for (int j = 0; j < ce->nkids; j++) if (strcmp(ce->kids[j]->name, "node") == 0) node = ce->kids[j];
                for (int j = 0; j < (node ? node->nkids : 0); j++) {
                    GF *k = node->kids[j];
                    const char *outk2 = k->alias[0] ? k->alias : k->name;
                    if (strcmp(k->name, "id") == 0) { key(&data, outk2, &of); jq_str(&data, cgid); }
                    else if (strcmp(k->name, "body") == 0) { key(&data, outk2, &of); jq_str(&data, cm->body); }
                    else unknown_field(k->name, "IssueComment");
                }
                buf_adds(&data, "}}}");
            } else {
                unknown_field(nm, "Mutation");
            }
        } else {
            unknown_field(nm, "Query");
        }
    }

    buf_addc(&data, '}');
    if (g_err) {
        out->len = 0;
        buf_adds(out, "{\"data\":null,\"errors\":[{\"message\":");
        buf_json_str(out, g_errmsg.p ? g_errmsg.p : "unknown field");
        buf_adds(out, "}]}");
    } else {
        out->len = 0;
        buf_adds(out, "{\"data\":");
        buf_add(out, data.p ? data.p : "{}", data.len);
        buf_addc(out, '}');
    }
    gf_free(root);
    buf_free(&data);
    g_vars = NULL;
}

/* ---------------------------------------------------------------- entry */

int gql_handle(Req *q, Resp *r) {
    if (strcmp(q->method, "POST") != 0) {
        static const char NF[] = "{\"message\":\"Not Found\"}\n";
        resp_json(r, 404, NF, sizeof NF - 1);
        return 1;
    }
    if (!q->authorization || !(ci_prefix(q->authorization, "Bearer ") || ci_prefix(q->authorization, "token "))) {
        static const char NF[] = "{\"message\":\"Requires authentication\"}\n";
        resp_json(r, 401, NF, sizeof NF - 1);
        return 1;
    }
    const char *body = q->body ? q->body : "";
    size_t blen = q->body_len;

    /* batched body: a JSON array of operations */
    const char *p = body, *e = body + blen;
    while (p < e && (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t')) p++;
    int batched = (p < e && *p == '[');

    Buf out; buf_init(&out);
    if (batched) {
        buf_addc(&out, '[');
        const char *q2 = p + 1;
        int first = 1;
        for (;;) {
            while (q2 < e && (*q2 == ' ' || *q2 == '\n' || *q2 == ',' || *q2 == '\r' || *q2 == '\t')) q2++;
            if (q2 >= e || *q2 == ']') break;
            JV *op = jp_value(&q2, e);
            if (!op) break;
            JV *qj = jv_obj_get(op, "query");
            JV *vj = jv_obj_get(op, "variables");
            Buf one; buf_init(&one);
            resolve_op(&one, jv_str(qj) ? jv_str(qj) : "", vj);
            if (!first) buf_addc(&out, ',');
            buf_add(&out, one.p ? one.p : "{}", one.len);
            first = 0;
            buf_free(&one);
            jv_free(op);
        }
        buf_addc(&out, ']');
    } else {
        const char *q2 = body;
        JV *root = jp_value(&q2, e);
        JV *qj = jv_obj_get(root, "query");
        JV *vj = jv_obj_get(root, "variables");
        resolve_op(&out, jv_str(qj) ? jv_str(qj) : "", vj);
        jv_free(root);
    }
    resp_bytes(r, 200, "application/json; charset=utf-8", out.p, out.len);
    buf_free(&out);
    return 1;
}
