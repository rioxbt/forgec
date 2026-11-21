/* SPDX-License-Identifier: MIT */
#include "forge.h"
#include "sha1.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ---------------------------------------------------------------- object hash */

typedef struct { unsigned char id[20]; Obj *obj; } Slot;

static Slot *g_slots;
static size_t g_nslots, g_nobjs;

static uint64_t hash20(const unsigned char id[20]) {
    uint64_t h = 1469598103934665603ULL;
    for (int i = 0; i < 20; i++) { h ^= id[i]; h *= 1099511628211ULL; }
    return h;
}

void obj_init(void) { g_slots = NULL; g_nslots = 0; g_nobjs = 0; }

static void hash_grow(void) {
    size_t ncap = g_nslots ? g_nslots * 2 : 4096;
    Slot *ns = (Slot *)calloc(ncap, sizeof(Slot));
    if (!ns) { fputs("oom\n", stderr); exit(1); }
    for (size_t i = 0; i < g_nslots; i++) {
        if (!g_slots[i].obj) continue;
        size_t j = hash20(g_slots[i].id) & (ncap - 1);
        while (ns[j].obj) j = (j + 1) & (ncap - 1);
        ns[j] = g_slots[i];
    }
    free(g_slots);
    g_slots = ns; g_nslots = ncap;
}

static Slot *slot_for(const unsigned char id[20]) {
    if (g_nslots == 0) return NULL;
    size_t j = hash20(id) & (g_nslots - 1);
    while (g_slots[j].obj) {
        if (memcmp(g_slots[j].id, id, 20) == 0) return &g_slots[j];
        j = (j + 1) & (g_nslots - 1);
    }
    return &g_slots[j];
}

Obj *obj_get(const unsigned char id[20]) {
    Slot *s = slot_for(id);
    return s ? s->obj : NULL;
}
int obj_exists(const unsigned char id[20]) { return obj_get(id) != NULL; }

void obj_id_of(char type, const char *data, size_t len, unsigned char out[20]) {
    char hdr[32];
    const char *tn = type == 'b' ? "blob" : type == 't' ? "tree" : type == 'c' ? "commit" : "tag";
    int hn = snprintf(hdr, sizeof hdr, "%s %zu%c", tn, len, '\0');
    Sha1 s; sha1_init(&s);
    sha1_update(&s, hdr, (size_t)hn);
    sha1_update(&s, data, len);
    sha1_final(&s, out);
}

void obj_put(char type, const char *data, size_t len, unsigned char out[20]) {
    obj_id_of(type, data, len, out);
    if (!g_nslots) hash_grow();
    Slot *s = slot_for(out);
    if (s->obj) return;
    if ((g_nobjs + 1) * 4 >= g_nslots * 3) { hash_grow(); s = slot_for(out); }
    s->obj = (Obj *)malloc(sizeof(Obj));
    if (!s->obj) { fputs("oom\n", stderr); exit(1); }
    memcpy(s->obj->id, out, 20);
    s->obj->type = type;
    s->obj->data = (char *)malloc(len ? len : 1);
    if (!s->obj->data) { fputs("oom\n", stderr); exit(1); }
    memcpy(s->obj->data, data, len);
    s->obj->len = len;
    memcpy(s->id, out, 20);
    g_nobjs++;
}

/* ---------------------------------------------------------------- tree helpers */

static int tree_name_cmp(const char *an, int atree, const char *bn, int btree) {
    size_t i = 0;
    for (;;) {
        int ac = (unsigned char)an[i]; int bc = (unsigned char)bn[i];
        if (atree && an[i] == '\0') ac = '/';
        if (btree && bn[i] == '\0') bc = '/';
        if (ac != bc) return ac < bc ? -1 : 1;
        if (an[i] == '\0' && bn[i] == '\0') return 0;
        i++;
    }
}

int tree_parse(const unsigned char id[20], TreeEnt *out, int max) {
    Obj *o = obj_get(id);
    if (!o || o->type != 't') return -1;
    const char *p = o->data, *end = o->data + o->len;
    int n = 0;
    while (p < end && n < max) {
        const char *sp = memchr(p, ' ', (size_t)(end - p));
        if (!sp) return -1;
        size_t ml = (size_t)(sp - p);
        if (ml >= sizeof out[n].mode) ml = sizeof out[n].mode - 1;
        memcpy(out[n].mode, p, ml); out[n].mode[ml] = '\0';
        p = sp + 1;
        const char *nul = memchr(p, '\0', (size_t)(end - p));
        if (!nul) return -1;
        size_t nl = (size_t)(nul - p);
        if (nl >= sizeof out[n].name) return -1;
        memcpy(out[n].name, p, nl); out[n].name[nl] = '\0';
        p = nul + 1;
        if (p + 20 > end) return -1;
        memcpy(out[n].oid, p, 20);
        p += 20;
        n++;
    }
    return n;
}

void tree_build(const TreeEnt *ents, int n, unsigned char out[20]) {
    Buf b; buf_init(&b);
    for (int i = 0; i < n; i++) {
        buf_adds(&b, ents[i].mode);
        buf_addc(&b, ' ');
        buf_adds(&b, ents[i].name);
        buf_addc(&b, '\0');
        buf_add(&b, ents[i].oid, 20);
    }
    obj_put('t', b.p ? b.p : "", b.len, out);
    buf_free(&b);
}

static void tree_sort(TreeEnt *e, int n) {
    for (int i = 1; i < n; i++) {
        TreeEnt key = e[i];
        int kt = strcmp(key.mode, "40000") == 0;
        int j = i - 1;
        while (j >= 0) {
            int jt = strcmp(e[j].mode, "40000") == 0;
            if (tree_name_cmp(e[j].name, jt, key.name, kt) > 0) { e[j + 1] = e[j]; j--; }
            else break;
        }
        e[j + 1] = key;
    }
}

static void split_path(const char *path, char *head, size_t hsz, const char **rest) {
    const char *slash = strchr(path, '/');
    if (!slash) { snprintf(head, hsz, "%s", path); *rest = NULL; }
    else {
        size_t n = (size_t)(slash - path);
        if (n >= hsz) n = hsz - 1;
        memcpy(head, path, n); head[n] = '\0';
        *rest = slash + 1;
    }
}

void tree_set_path(const unsigned char tree_id[20], const char *path,
                   const unsigned char new_id[20], int is_tree, unsigned char out[20]) {
    char head[256]; const char *rest;
    split_path(path, head, sizeof head, &rest);
    TreeEnt ents[4096];
    int n = tree_parse(tree_id, ents, 4096);
    if (n < 0) n = 0;
    int found = -1;
    for (int i = 0; i < n; i++) if (strcmp(ents[i].name, head) == 0) { found = i; break; }

    if (rest == NULL) {
        if (found >= 0) {
            snprintf(ents[found].mode, sizeof ents[found].mode, "%s", is_tree ? "40000" : "100644");
            memcpy(ents[found].oid, new_id, 20);
        } else {
            if (n >= 4096) { memcpy(out, tree_id, 20); return; }
            snprintf(ents[n].mode, sizeof ents[n].mode, "%s", is_tree ? "40000" : "100644");
            snprintf(ents[n].name, sizeof ents[n].name, "%s", head);
            memcpy(ents[n].oid, new_id, 20);
            n++;
        }
    } else {
        unsigned char sub[20];
        if (found >= 0 && strcmp(ents[found].mode, "40000") == 0) memcpy(sub, ents[found].oid, 20);
        else {
            TreeEnt none; (void)none;
            tree_build(NULL, 0, sub);
        }
        unsigned char newsub[20];
        tree_set_path(sub, rest, new_id, is_tree, newsub);
        if (found >= 0) {
            snprintf(ents[found].mode, sizeof ents[found].mode, "40000");
            memcpy(ents[found].oid, newsub, 20);
        } else {
            if (n >= 4096) { memcpy(out, tree_id, 20); return; }
            snprintf(ents[n].mode, sizeof ents[n].mode, "40000");
            snprintf(ents[n].name, sizeof ents[n].name, "%s", head);
            memcpy(ents[n].oid, newsub, 20);
            n++;
        }
    }
    tree_sort(ents, n);
    tree_build(ents, n, out);
}

void tree_del_path(const unsigned char tree_id[20], const char *path, unsigned char out[20]) {
    char head[256]; const char *rest;
    split_path(path, head, sizeof head, &rest);
    TreeEnt ents[4096];
    int n = tree_parse(tree_id, ents, 4096);
    if (n < 0) { memcpy(out, tree_id, 20); return; }
    int found = -1;
    for (int i = 0; i < n; i++) if (strcmp(ents[i].name, head) == 0) { found = i; break; }
    if (found < 0) { memcpy(out, tree_id, 20); return; }
    if (rest == NULL) {
        for (int i = found; i < n - 1; i++) ents[i] = ents[i + 1];
        n--;
    } else {
        if (strcmp(ents[found].mode, "40000") != 0) { memcpy(out, tree_id, 20); return; }
        unsigned char newsub[20];
        tree_del_path(ents[found].oid, rest, newsub);
        if (obj_get(newsub) && obj_get(newsub)->len == 0) {
            for (int i = found; i < n - 1; i++) ents[i] = ents[i + 1];
            n--;
        } else {
            memcpy(ents[found].oid, newsub, 20);
        }
    }
    tree_build(ents, n, out);
}

int commit_lookup_path(const unsigned char commit_id[20], const char *path,
                       unsigned char out[20], int *is_tree) {
    unsigned char tree[20];
    if (commit_tree_of(commit_id, tree) < 0) return 0;
    if (path[0] == '\0') { memcpy(out, tree, 20); if (is_tree) *is_tree = 1; return 1; }
    char seg[256];
    const char *p = path;
    for (;;) {
        const char *slash = strchr(p, '/');
        size_t n = slash ? (size_t)(slash - p) : strlen(p);
        if (n >= sizeof seg) return 0;
        memcpy(seg, p, n); seg[n] = '\0';
        TreeEnt ents[4096];
        int cnt = tree_parse(tree, ents, 4096);
        if (cnt < 0) return 0;
        int found = -1;
        for (int i = 0; i < cnt; i++) if (strcmp(ents[i].name, seg) == 0) { found = i; break; }
        if (found < 0) return 0;
        int tg = strcmp(ents[found].mode, "40000") == 0;
        if (!slash) { memcpy(out, ents[found].oid, 20); if (is_tree) *is_tree = tg; return 1; }
        if (!tg) return 0;
        memcpy(tree, ents[found].oid, 20);
        p = slash + 1;
    }
}

void commit_build(const unsigned char tree_id[20],
                  const unsigned char (*parents)[20], int nparents,
                  const char *message, long epoch, const char *author_line,
                  unsigned char out[20]) {
    Buf b; buf_init(&b);
    char hx[41];
    sha1_hex(tree_id, hx);
    buf_addf(&b, "tree %s\n", hx);
    for (int i = 0; i < nparents; i++) {
        sha1_hex(parents[i], hx);
        buf_addf(&b, "parent %s\n", hx);
    }
    buf_addf(&b, "author %s %ld +0000\n", author_line, epoch);
    buf_addf(&b, "committer %s %ld +0000\n", author_line, epoch);
    buf_addc(&b, '\n');
    buf_adds(&b, message);
    obj_put('c', b.p ? b.p : "", b.len, out);
    buf_free(&b);
}

int commit_tree_of(const unsigned char commit_id[20], unsigned char out[20]) {
    Obj *o = obj_get(commit_id);
    if (!o || o->type != 'c') return -1;
    if (o->len < 46 || memcmp(o->data, "tree ", 5) != 0) return -1;
    return sha1_hex_decode(o->data + 5, 40, out);
}

int commit_first_parent(const unsigned char commit_id[20], unsigned char out[20]) {
    Obj *o = obj_get(commit_id);
    if (!o || o->type != 'c') return -1;
    const char *nl = memchr(o->data, '\n', o->len);
    if (!nl) return -1;
    const char *p = nl + 1;
    if ((size_t)(o->data + o->len - p) < 7 || memcmp(p, "parent ", 7) != 0) return -1;
    return sha1_hex_decode(p + 7, 40, out);
}

int commit_message(const unsigned char commit_id[20], const char **msg, size_t *len) {
    Obj *o = obj_get(commit_id);
    if (!o || o->type != 'c') return -1;
    const char *p = memchr(o->data, '\n', o->len);
    while (p) {
        const char *nl = (const char *)memchr(p + 1, '\n', (size_t)(o->data + o->len - (p + 1)));
        const char *line = p + 1;
        if (nl == line) { /* blank line -> message follows */
            *msg = nl + 1;
            *len = (size_t)(o->data + o->len - (nl + 1));
            return 0;
        }
        if (!nl) break;
        p = nl;
    }
    *msg = ""; *len = 0;
    return 0;
}

long commit_time(const unsigned char commit_id[20]) {
    Obj *o = obj_get(commit_id);
    if (!o || o->type != 'c') return 0;
    const char *p = strstr(o->data, "\ncommitter ");
    if (!p) p = strstr(o->data, "committer ");
    if (!p) return 0;
    p = strrchr(p, '>');
    if (!p) return 0;
    return strtol(p + 2, NULL, 10);
}

/* ---------------------------------------------------------------- store */

static Repo *g_repos;
static int g_nrepos, g_caprepos;
static uint64_t g_comment_id = 1;

void store_init(void) {
    g_repos = NULL; g_nrepos = 0; g_caprepos = 0; g_comment_id = 1;
}

int repo_count_all(void) { return g_nrepos; }
Repo *repo_at(int i) { return (i >= 0 && i < g_nrepos) ? &g_repos[i] : NULL; }

Repo *repo_find(const char *owner, const char *name) {
    for (int i = 0; i < g_nrepos; i++)
        if (strcmp(g_repos[i].owner, owner) == 0 && strcmp(g_repos[i].name, name) == 0)
            return &g_repos[i];
    return NULL;
}

Repo *repo_create(const char *owner, const char *name, const char *desc, int priv, const char *dflt) {
    if (g_nrepos == g_caprepos) {
        g_caprepos = g_caprepos ? g_caprepos * 2 : 64;
        g_repos = (Repo *)realloc(g_repos, (size_t)g_caprepos * sizeof(Repo));
        if (!g_repos) { fputs("oom\n", stderr); exit(1); }
    }
    Repo *r = &g_repos[g_nrepos];
    memset(r, 0, sizeof *r);
    r->id = 5000 + g_nrepos;
    r->owner = xstrdup(owner);
    r->name = xstrdup(name);
    r->description = xstrdup(desc ? desc : "");
    r->is_private = priv;
    r->default_branch = xstrdup(dflt ? dflt : "main");
    r->next_issue = 1;
    r->next_pull = 1;
    g_nrepos++;
    return r;
}

static void free_refs(Repo *r) { for (int i = 0; i < r->nrefs; i++) free(r->refs[i].name); free(r->refs); }
static void free_labels(Repo *r) { for (int i = 0; i < r->nlabels; i++) { free(r->labels[i].name); free(r->labels[i].color); } free(r->labels); }
static void free_issues(Repo *r) {
    for (int i = 0; i < r->nissues; i++) {
        free(r->issues[i].title); free(r->issues[i].body); free(r->issues[i].user);
        for (int j = 0; j < r->issues[i].nlabels; j++) free(r->issues[i].labels[j]);
        free(r->issues[i].labels);
        for (int j = 0; j < r->issues[i].ncomments; j++) { free(r->issues[i].comments[j].body); free(r->issues[i].comments[j].user); }
        free(r->issues[i].comments);
    }
    free(r->issues);
}
static void free_pulls(Repo *r) {
    for (int i = 0; i < r->npulls; i++) {
        free(r->pulls[i].title); free(r->pulls[i].body); free(r->pulls[i].head_ref);
        free(r->pulls[i].base_ref); free(r->pulls[i].user); free(r->pulls[i].merged_at);
    }
    free(r->pulls);
}

void repo_delete(Repo *r) {
    int idx = (int)(r - g_repos);
    free(r->owner); free(r->name); free(r->description); free(r->default_branch);
    free_refs(r); free_labels(r); free_issues(r); free_pulls(r);
    for (int i = idx; i < g_nrepos - 1; i++) g_repos[i] = g_repos[i + 1];
    g_nrepos--;
}

Ref *ref_get(Repo *r, const char *name) {
    for (int i = 0; i < r->nrefs; i++) if (strcmp(r->refs[i].name, name) == 0) return &r->refs[i];
    return NULL;
}

void ref_set(Repo *r, const char *name, const unsigned char oid[20]) {
    Ref *e = ref_get(r, name);
    if (e) { memcpy(e->oid, oid, 20); return; }
    r->refs = (Ref *)realloc(r->refs, (size_t)(r->nrefs + 1) * sizeof(Ref));
    if (!r->refs) { fputs("oom\n", stderr); exit(1); }
    r->refs[r->nrefs].name = xstrdup(name);
    memcpy(r->refs[r->nrefs].oid, oid, 20);
    r->nrefs++;
}

void ref_del(Repo *r, const char *name) {
    for (int i = 0; i < r->nrefs; i++) {
        if (strcmp(r->refs[i].name, name) == 0) {
            free(r->refs[i].name);
            for (int j = i; j < r->nrefs - 1; j++) r->refs[j] = r->refs[j + 1];
            r->nrefs--;
            return;
        }
    }
}

Issue *issue_find(Repo *r, int number) {
    for (int i = 0; i < r->nissues; i++) if (r->issues[i].number == number) return &r->issues[i];
    return NULL;
}
Pull *pull_find(Repo *r, int number) {
    for (int i = 0; i < r->npulls; i++) if (r->pulls[i].number == number) return &r->pulls[i];
    return NULL;
}
int label_exists(Repo *r, const char *name) {
    for (int i = 0; i < r->nlabels; i++) if (strcmp(r->labels[i].name, name) == 0) return 1;
    return 0;
}

uint64_t store_next_comment_id(void);
uint64_t store_next_comment_id(void) { return g_comment_id++; }
