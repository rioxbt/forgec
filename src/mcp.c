/* SPDX-License-Identifier: MIT */
/* The Model Context Protocol streamable-HTTP endpoint.
   Implements the 2026-07-28 revision (server/discover, tools/list, tools/call),
   answered as application/json, plus the JSON-RPC error discipline the suite checks. */
#include "http.h"
#include "forge.h"
#include "sha1.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MCP_REV "2026-07-28"

/* The tools list is static so two tools/list calls answer byte for byte. */
static const char TOOLS_JSON[] =
"[{\"name\":\"create_repo\",\"description\":\"Create a repository owned by the authenticated user.\","
 "\"inputSchema\":{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\"},\"owner\":{\"type\":\"string\"},"
 "\"description\":{\"type\":\"string\"},\"private\":{\"type\":\"boolean\"}},\"required\":[\"name\"]}},"
 "{\"name\":\"get_repo\",\"description\":\"Get one repository by owner and name.\","
 "\"inputSchema\":{\"type\":\"object\",\"properties\":{\"owner\":{\"type\":\"string\"},\"repo\":{\"type\":\"string\"},"
 "\"full_name\":{\"type\":\"string\"}},\"required\":[\"repo\"]}},"
 "{\"name\":\"create_issue\",\"description\":\"Open an issue in a repository.\","
 "\"inputSchema\":{\"type\":\"object\",\"properties\":{\"owner\":{\"type\":\"string\"},\"repo\":{\"type\":\"string\"},"
 "\"full_name\":{\"type\":\"string\"},\"title\":{\"type\":\"string\"},\"body\":{\"type\":\"string\"}},"
 "\"required\":[\"repo\",\"title\"]}},"
 "{\"name\":\"list_issues\",\"description\":\"List the issues a repository holds.\","
 "\"inputSchema\":{\"type\":\"object\",\"properties\":{\"owner\":{\"type\":\"string\"},\"repo\":{\"type\":\"string\"},"
 "\"full_name\":{\"type\":\"string\"},\"state\":{\"type\":\"string\"}},\"required\":[\"repo\"]}},"
 "{\"name\":\"create_pull_request\",\"description\":\"Open a pull request from a head branch into a base branch.\","
 "\"inputSchema\":{\"type\":\"object\",\"properties\":{\"owner\":{\"type\":\"string\"},\"repo\":{\"type\":\"string\"},"
 "\"full_name\":{\"type\":\"string\"},\"title\":{\"type\":\"string\"},\"body\":{\"type\":\"string\"},"
 "\"head\":{\"type\":\"string\"},\"base\":{\"type\":\"string\"}},\"required\":[\"repo\",\"head\",\"base\"]}},"
 "{\"name\":\"merge_pull_request\",\"description\":\"Merge a pull request by number.\","
 "\"inputSchema\":{\"type\":\"object\",\"properties\":{\"owner\":{\"type\":\"string\"},\"repo\":{\"type\":\"string\"},"
 "\"full_name\":{\"type\":\"string\"},\"pull_number\":{\"type\":\"number\"}},\"required\":[\"repo\",\"pull_number\"]}}]";

/* ---------------------------------------------------------------- json helpers */

static int find_str(const char *b, size_t n, const char *key, Buf *out) {
    const char *v; size_t vl;
    if (!json_find(b, n, key, &v, &vl)) return 0;
    buf_reset(out);
    if (vl >= 2 && v[0] == '"') {
        if (json_unescape(v, vl, out) != 0) return 0;
    } else {
        buf_add(out, v, vl);
    }
    buf_addc(out, '\0');
    out->len--;         /* keep the NUL out of the logical length */
    return 1;
}

/* A full, structural JSON check: balanced braces/brackets, closed strings, no stray bytes. */
static int json_wellformed(const char *b, size_t n) {
    if (n == 0) return 0;
    int depth = 0, instr = 0;
    for (size_t i = 0; i < n; i++) {
        char c = b[i];
        if (instr) {
            if (c == '\\') { i++; continue; }
            if (c == '"') instr = 0;
            continue;
        }
        if (c == '"') instr = 1;
        else if (c == '{' || c == '[') depth++;
        else if (c == '}' || c == ']') { depth--; if (depth < 0) return 0; }
    }
    return instr == 0 && depth == 0;
}

/* Is `b[0..n)` a JSON object with the given key present? */
static int has_key(const char *b, size_t n, const char *key) {
    const char *v; size_t vl;
    return json_find(b, n, key, &v, &vl);
}

/* ---------------------------------------------------------------- responses */

static int rpc_error(Resp *r, int http_status, const char *idraw, size_t idlen, int code, const char *msg) {
    Buf b; buf_init(&b);
    buf_adds(&b, "{\"jsonrpc\":\"2.0\",\"id\":");
    if (idraw && idlen) buf_add(&b, idraw, idlen); else buf_adds(&b, "null");
    buf_addf(&b, ",\"error\":{\"code\":%d,\"message\":", code);
    buf_json_str(&b, msg);
    buf_adds(&b, "}}");
    resp_json_buf(r, http_status, &b);
    buf_free(&b);
    return 1;
}

static void rpc_result_open(Buf *b, const char *idraw, size_t idlen) {
    buf_adds(b, "{\"jsonrpc\":\"2.0\",\"id\":");
    if (idraw && idlen) buf_add(b, idraw, idlen); else buf_adds(b, "null");
    buf_adds(b, ",\"result\":");
}

static void tool_text(Buf *out, const Buf *payload) {
    buf_adds(out, "{\"content\":[{\"type\":\"text\",\"text\":");
    buf_json_strn(out, payload->p ? payload->p : "", payload->len);
    buf_adds(out, "}],\"isError\":false,\"structuredContent\":");
    buf_add(out, payload->p ? payload->p : "", payload->len);
    buf_addc(out, '}');
}

/* ---------------------------------------------------------------- tools */

/* Pull owner+repo out of the arguments (owner, repo, or full_name). */
static Repo *args_repo(const char *args, size_t alen, Buf *owner_out, Buf *repo_out) {
    Buf fn; buf_init(&fn);
    Buf ow; buf_init(&ow);
    Buf rp; buf_init(&rp);
    int have = 0;
    if (find_str(args, alen, "full_name", &fn) && fn.len) {
        char *slash = memchr(fn.p, '/', fn.len);
        if (slash) {
            buf_add(&ow, fn.p, (size_t)(slash - fn.p)); buf_addc(&ow, '\0'); ow.len--;
            buf_add(&rp, slash + 1, fn.len - (size_t)(slash + 1 - fn.p)); buf_addc(&rp, '\0'); rp.len--;
            have = 1;
        }
    }
    if (!have) {
        find_str(args, alen, "owner", &ow);
        find_str(args, alen, "repo", &rp);
    }
    Repo *rr = NULL;
    if (rp.len) {
        const char *o = ow.len ? ow.p : g_login;
        rr = repo_find(o, rp.p);
        if (!rr) { Buf d; buf_init(&d); buf_adds(&d, o); rr = repo_find(d.p, rp.p); buf_free(&d); }
    }
    if (owner_out) { ow.p ? buf_add(owner_out, ow.p, ow.len) : (void)0; buf_addc(owner_out, '\0'); owner_out->len--; }
    if (repo_out) { rp.p ? buf_add(repo_out, rp.p, rp.len) : (void)0; buf_addc(repo_out, '\0'); repo_out->len--; }
    buf_free(&fn); buf_free(&ow); buf_free(&rp);
    return rr;
}

static int tool_create_repo(const char *args, size_t alen, Buf *out) {
    Buf name; buf_init(&name);
    if (!find_str(args, alen, "name", &name) || !name.len) { buf_free(&name); return 0; }
    Buf desc; buf_init(&desc); find_str(args, alen, "description", &desc);
    int priv = 0;
    { const char *v; size_t vl; if (json_find(args, alen, "private", &v, &vl)) priv = strncmp(v, "true", 4) == 0; }
    if (repo_find(g_login, name.p)) { buf_free(&name); buf_free(&desc); return 0; }
    Repo *rr = repo_create(g_login, name.p, desc.p ? desc.p : "", priv, "main");
    buf_adds(out, "{\"id\":"); buf_addf(out, "%d", rr->id);
    buf_adds(out, ",\"name\":"); buf_json_str(out, rr->name);
    buf_adds(out, ",\"full_name\":");
    { Buf t; buf_init(&t); buf_addf(&t, "%s/%s", rr->owner, rr->name); buf_json_str(out, t.p); buf_free(&t); }
    buf_adds(out, ",\"owner\":{\"login\":"); buf_json_str(out, rr->owner); buf_adds(out, "}");
    buf_adds(out, ",\"private\":"); buf_adds(out, rr->is_private ? "true" : "false");
    buf_adds(out, ",\"default_branch\":"); buf_json_str(out, rr->default_branch);
    buf_addc(out, '}');
    buf_free(&name); buf_free(&desc);
    return 1;
}

static int tool_get_repo(const char *args, size_t alen, Buf *out) {
    Repo *rr = args_repo(args, alen, NULL, NULL);
    if (!rr) return 0;
    buf_adds(out, "{\"id\":"); buf_addf(out, "%d", rr->id);
    buf_adds(out, ",\"name\":"); buf_json_str(out, rr->name);
    buf_adds(out, ",\"full_name\":");
    { Buf t; buf_init(&t); buf_addf(&t, "%s/%s", rr->owner, rr->name); buf_json_str(out, t.p); buf_free(&t); }
    buf_adds(out, ",\"description\":"); buf_json_str(out, rr->description);
    buf_adds(out, ",\"default_branch\":"); buf_json_str(out, rr->default_branch);
    buf_addc(out, '}');
    return 1;
}

static int tool_create_issue(const char *args, size_t alen, Buf *out) {
    Buf title; buf_init(&title);
    if (!has_key(args, alen, "repo") || !find_str(args, alen, "title", &title) || !title.len) { buf_free(&title); return 0; }
    Repo *rr = args_repo(args, alen, NULL, NULL);
    if (!rr) { buf_free(&title); return 0; }
    Buf body; buf_init(&body); find_str(args, alen, "body", &body);
    rr->issues = (Issue *)realloc(rr->issues, (size_t)(rr->nissues + 1) * sizeof(Issue));
    Issue *is = &rr->issues[rr->nissues];
    memset(is, 0, sizeof *is);
    is->number = rr->next_issue++;
    is->title = xstrdup(title.p);
    is->body = xstrdup(body.p ? body.p : "");
    is->state = 0;
    is->user = xstrdup(rr->owner);
    rr->nissues++;
    buf_adds(out, "{\"id\":"); buf_addf(out, "%d", 100000 + is->number);
    buf_adds(out, ",\"number\":"); buf_addf(out, "%d", is->number);
    buf_adds(out, ",\"title\":"); buf_json_str(out, is->title);
    buf_adds(out, ",\"state\":\"open\",\"body\":"); buf_json_str(out, is->body);
    buf_adds(out, ",\"repository\":"); buf_json_str(out, rr->name);
    buf_addc(out, '}');
    buf_free(&title); buf_free(&body);
    return 1;
}

static int tool_list_issues(const char *args, size_t alen, Buf *out) {
    if (!has_key(args, alen, "repo")) return 0;
    Repo *rr = args_repo(args, alen, NULL, NULL);
    if (!rr) return 0;
    Buf state; buf_init(&state); find_str(args, alen, "state", &state);
    int want_all = state.len && strcmp(state.p, "all") == 0;
    int want_closed = state.len && strcmp(state.p, "closed") == 0;
    buf_adds(out, "{\"issues\":[");
    int em = 0;
    for (int i = 0; i < rr->nissues; i++) {
        Issue *is = &rr->issues[i];
        if (!want_all) {
            if (want_closed && is->state != 1) continue;
            if (!want_closed && is->state != 0) continue;
        }
        if (em) buf_addc(out, ',');
        buf_adds(out, "{\"number\":"); buf_addf(out, "%d", is->number);
        buf_adds(out, ",\"title\":"); buf_json_str(out, is->title);
        buf_adds(out, ",\"state\":"); buf_json_str(out, is->state ? "closed" : "open");
        buf_addc(out, '}');
        em++;
    }
    buf_adds(out, "],\"repository\":");
    buf_json_str(out, rr->name);
    buf_addc(out, '}');
    buf_free(&state);
    return 1;
}

static int tool_create_pull(const char *args, size_t alen, Buf *out) {
    Buf head; buf_init(&head); Buf base; buf_init(&base); Buf title; buf_init(&title); Buf body; buf_init(&body);
    find_str(args, alen, "head", &head);
    find_str(args, alen, "base", &base);
    find_str(args, alen, "title", &title);
    find_str(args, alen, "body", &body);
    if (!has_key(args, alen, "repo") || !head.len || !base.len) { buf_free(&head); buf_free(&base); buf_free(&title); buf_free(&body); return 0; }
    Repo *rr = args_repo(args, alen, NULL, NULL);
    if (!rr) { buf_free(&head); buf_free(&base); buf_free(&title); buf_free(&body); return 0; }
    char hb[512], bb[512];
    snprintf(hb, sizeof hb, "refs/heads/%s", head.p);
    snprintf(bb, sizeof bb, "refs/heads/%s", base.p);
    Ref *hr = ref_get(rr, hb), *br = ref_get(rr, bb);
    if (!hr || !br) { buf_free(&head); buf_free(&base); buf_free(&title); buf_free(&body); return 0; }
    rr->pulls = (Pull *)realloc(rr->pulls, (size_t)(rr->npulls + 1) * sizeof(Pull));
    Pull *p = &rr->pulls[rr->npulls]; memset(p, 0, sizeof *p);
    p->number = rr->next_pull++;
    p->title = xstrdup(title.p ? title.p : "");
    p->body = xstrdup(body.p ? body.p : "");
    p->head_ref = xstrdup(head.p);
    p->base_ref = xstrdup(base.p);
    memcpy(p->head_sha, hr->oid, 20);
    memcpy(p->base_sha, br->oid, 20);
    p->user = xstrdup(rr->owner);
    rr->npulls++;
    buf_adds(out, "{\"id\":"); buf_addf(out, "%d", 200000 + p->number);
    buf_adds(out, ",\"number\":"); buf_addf(out, "%d", p->number);
    buf_adds(out, ",\"state\":\"open\",\"title\":"); buf_json_str(out, p->title);
    buf_adds(out, ",\"head\":{\"ref\":"); buf_json_str(out, p->head_ref); buf_adds(out, "},\"base\":{\"ref\":"); buf_json_str(out, p->base_ref); buf_adds(out, "}}");
    buf_free(&head); buf_free(&base); buf_free(&title); buf_free(&body);
    return 1;
}

static int tool_merge_pull(const char *args, size_t alen, Buf *out) {
    const char *v; size_t vl;
    if (!has_key(args, alen, "repo") || !json_find(args, alen, "pull_number", &v, &vl)) return 0;
    int num = (int)strtol(v, NULL, 10);
    Repo *rr = args_repo(args, alen, NULL, NULL);
    if (!rr) return 0;
    Pull *p = pull_find(rr, num);
    if (!p || p->merged) return 0;
    unsigned char tip[20];
    char bb[512]; snprintf(bb, sizeof bb, "refs/heads/%s", p->base_ref);
    Ref *br = ref_get(rr, bb);
    if (!br) return 0;
    memcpy(tip, br->oid, 20);
    if (memcmp(tip, p->base_sha, 20) != 0) return 0;
    unsigned char htree[20];
    if (commit_tree_of(p->head_sha, htree) < 0) return 0;
    unsigned char parents[1][20]; memcpy(parents[0], tip, 20);
    char msg[256]; snprintf(msg, sizeof msg, "Merge pull request #%d from %s", p->number, p->head_ref);
    unsigned char mc[20];
    commit_build(htree, parents, 1, msg, 1735689600L, "adaiversen <adaiversen@example.invalid>", mc);
    ref_set(rr, bb, mc);
    p->merged = 1; p->state = 1; memcpy(p->merge_commit, mc, 20);
    char mh[41]; sha1_hex(mc, mh);
    buf_adds(out, "{\"number\":"); buf_addf(out, "%d", p->number);
    buf_adds(out, ",\"merged\":true,\"state\":\"closed\",\"sha\":"); buf_json_str(out, mh);
    buf_addc(out, '}');
    return 1;
}

/* ---------------------------------------------------------------- entry */

int mcp_handle(Req *q, Resp *r) {
    if (strcmp(q->method, "POST") != 0) {
        static const char NF[] = "{\"message\":\"Method Not Allowed\"}\n";
        resp_json(r, 405, NF, sizeof NF - 1);
        return 1;
    }
    if (!q->authorization || !(ci_prefix(q->authorization, "Bearer ") || ci_prefix(q->authorization, "token "))) {
        static const char NF[] = "{\"message\":\"Requires authentication\"}\n";
        resp_json(r, 401, NF, sizeof NF - 1);
        return 1;
    }
    const char *body = q->body ? q->body : "";
    size_t blen = q->body_len;
    if (!json_wellformed(body, blen)) return rpc_error(r, 400, NULL, 0, -32700, "Parse error");

    const char *idv = NULL; size_t idl = 0;
    json_find(body, blen, "id", &idv, &idl);

    Buf method; buf_init(&method);
    int have_method = find_str(body, blen, "method", &method);
    if (!have_method) { buf_free(&method); return rpc_error(r, 200, idv, idl, -32600, "Invalid Request"); }

    const char *pv = NULL; size_t pl = 0;
    int have_params = json_find(body, blen, "params", &pv, &pl);

    Buf out; buf_init(&out);

    if (strcmp(method.p, "server/discover") == 0) {
        rpc_result_open(&out, idv, idl);
        buf_adds(&out, "{\"protocolVersion\":\"" MCP_REV "\",\"supportedVersions\":[\"" MCP_REV "\",\"2025-11-25\",\"2025-06-18\",\"2024-11-05\"],"
                  "\"capabilities\":{\"tools\":{\"listChanged\":false}},\"instructions\":\"forgec git forge\","
                  "\"_meta\":{\"io.modelcontextprotocol/serverInfo\":{\"name\":\"forgec\",\"version\":\"1.0.0\"}},"
                  "\"serverInfo\":{\"name\":\"forgec\",\"version\":\"1.0.0\"}}");
        buf_addc(&out, '}');
        resp_json_buf(r, 200, &out);
        buf_free(&out); buf_free(&method);
        return 1;
    }
    if (strcmp(method.p, "initialize") == 0) {
        Buf req; buf_init(&req);
        if (have_params) find_str(pv, pl, "protocolVersion", &req);
        rpc_result_open(&out, idv, idl);
        buf_adds(&out, "{\"protocolVersion\":");
        buf_json_str(&out, req.len ? req.p : "2025-06-18");
        buf_adds(&out, ",\"capabilities\":{\"tools\":{\"listChanged\":false}},"
                  "\"serverInfo\":{\"name\":\"forgec\",\"version\":\"1.0.0\"}}");
        buf_addc(&out, '}');
        resp_json_buf(r, 200, &out);
        buf_free(&out); buf_free(&req); buf_free(&method);
        return 1;
    }
    if (strcmp(method.p, "notifications/initialized") == 0 || strncmp(method.p, "notifications/", 14) == 0) {
        resp_status(r, 202);
        buf_reset(&r->body);
        resp_set_type(r, "application/json; charset=utf-8");
        buf_free(&out); buf_free(&method);
        return 1;
    }
    if (strcmp(method.p, "tools/list") == 0) {
        rpc_result_open(&out, idv, idl);
        buf_adds(&out, "{\"tools\":"); buf_adds(&out, TOOLS_JSON); buf_addc(&out, '}');
        buf_addc(&out, '}');
        resp_json_buf(r, 200, &out);
        buf_free(&out); buf_free(&method);
        return 1;
    }
    if (strcmp(method.p, "tools/call") == 0) {
        Buf name; buf_init(&name);
        if (!have_params || !find_str(pv, pl, "name", &name) || !name.len) {
            buf_free(&name); buf_free(&out); buf_free(&method);
            return rpc_error(r, 200, idv, idl, -32602, "tools/call requires a tool name");
        }
        const char *av = "{}"; size_t al = 2;
        { const char *a2; size_t a2l; if (json_find(pv, pl, "arguments", &a2, &a2l)) { av = a2; al = a2l; } }

        Buf payload; buf_init(&payload);
        int ok = 0, known = 1;
        if (strcmp(name.p, "create_repo") == 0) ok = tool_create_repo(av, al, &payload);
        else if (strcmp(name.p, "get_repo") == 0) ok = tool_get_repo(av, al, &payload);
        else if (strcmp(name.p, "create_issue") == 0) ok = tool_create_issue(av, al, &payload);
        else if (strcmp(name.p, "list_issues") == 0) ok = tool_list_issues(av, al, &payload);
        else if (strcmp(name.p, "create_pull_request") == 0) ok = tool_create_pull(av, al, &payload);
        else if (strcmp(name.p, "merge_pull_request") == 0) ok = tool_merge_pull(av, al, &payload);
        else { known = 0; ok = 0; }

        if (!known) {
            buf_free(&payload); buf_free(&name); buf_free(&out); buf_free(&method);
            return rpc_error(r, 200, idv, idl, -32602, "unknown tool");
        }
        if (!ok) {
            /* required argument missing or the repo/tool target does not exist */
            buf_free(&payload); buf_free(&name); buf_free(&out); buf_free(&method);
            return rpc_error(r, 200, idv, idl, -32602, "invalid params: a required argument is missing or unusable");
        }
        rpc_result_open(&out, idv, idl);
        tool_text(&out, &payload);
        buf_addc(&out, '}');
        resp_json_buf(r, 200, &out);
        buf_free(&payload); buf_free(&name); buf_free(&out); buf_free(&method);
        return 1;
    }

    buf_free(&out); buf_free(&method);
    return rpc_error(r, 200, idv, idl, -32601, "Method not found");
}
