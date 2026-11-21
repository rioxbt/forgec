/* SPDX-License-Identifier: MIT */
#ifndef FORGE_H
#define FORGE_H
#include <stddef.h>
#include <stdint.h>
#include "util.h"

/* ---------------------------------------------------------------- objects */

typedef struct {
    unsigned char id[20];
    char type;          /* 'b' blob, 't' tree, 'c' commit, 'g' tag */
    char *data;
    size_t len;
} Obj;

void  obj_init(void);
Obj  *obj_get(const unsigned char id[20]);
int   obj_exists(const unsigned char id[20]);
/* Store (idempotent) an object; writes its id to out. */
void  obj_put(char type, const char *data, size_t len, unsigned char out[20]);
/* Compute an id without storing. */
void  obj_id_of(char type, const char *data, size_t len, unsigned char out[20]);

/* ---------------------------------------------------------------- git helpers */

typedef struct { char mode[8]; char name[256]; unsigned char oid[20]; } TreeEnt;

/* Parse a tree object into entries; returns count (<= max). */
int   tree_parse(const unsigned char id[20], TreeEnt *out, int max);
/* Serialize entries into a tree object, store it, return its id. */
void  tree_build(const TreeEnt *ents, int n, unsigned char out[20]);

/* Look up `path` (slash separated) in a commit's tree; returns 1 and oid on success.
   `is_tree` (optional) set to 1 when the result is a tree. */
int   commit_lookup_path(const unsigned char commit_id[20], const char *path,
                         unsigned char out[20], int *is_tree);
/* Replace/create `path` with blob/any object `new_id`; returns the new commit's tree id. */
void  tree_set_path(const unsigned char tree_id[20], const char *path,
                    const unsigned char new_id[20], int is_tree, unsigned char out[20]);
/* Remove `path`; returns new tree id. */
void  tree_del_path(const unsigned char tree_id[20], const char *path, unsigned char out[20]);

/* Build a commit object; returns its id. parents may be NULL/0. */
void  commit_build(const unsigned char tree_id[20],
                   const unsigned char (*parents)[20], int nparents,
                   const char *message, long epoch, const char *author_line,
                   unsigned char out[20]);

int   commit_tree_of(const unsigned char commit_id[20], unsigned char out[20]);
int   commit_first_parent(const unsigned char commit_id[20], unsigned char out[20]);
int   commit_message(const unsigned char commit_id[20], const char **msg, size_t *len);
long  commit_time(const unsigned char commit_id[20]);

/* ---------------------------------------------------------------- store model */

typedef struct { char *name; char *color; } Label;
typedef struct {
    uint64_t id;
    char *body;
    char *user;
    long created;
} Comment;
typedef struct {
    int number;
    char *title;
    char *body;
    int state;               /* 0 open, 1 closed */
    char **labels; int nlabels;
    Comment *comments; int ncomments;
    char *user;
    long created;
} Issue;
typedef struct {
    int number;
    char *title;
    char *body;
    int state;               /* 0 open, 1 closed */
    int merged;
    char *head_ref; char *base_ref;
    unsigned char head_sha[20], base_sha[20];
    unsigned char merge_commit[20];
    int has_merge;
    char *merged_at;
    char *user;
    long created;
} Pull;
typedef struct { char *name; unsigned char oid[20]; } Ref;

typedef struct {
    int id;
    char *owner;
    char *name;
    char *description;
    int is_private;
    char *default_branch;
    Ref *refs; int nrefs;
    Label *labels; int nlabels;
    Issue *issues; int nissues;
    Pull *pulls; int npulls;
    int next_issue;
    int next_pull;
} Repo;

void  store_init(void);
int   repo_count_all(void);
Repo *repo_find(const char *owner, const char *name);
Repo *repo_create(const char *owner, const char *name, const char *desc, int priv, const char *dflt);
void  repo_delete(Repo *r);

Ref  *ref_get(Repo *r, const char *name);
void  ref_set(Repo *r, const char *name, const unsigned char oid[20]);
void  ref_del(Repo *r, const char *name);
int   refs_list(Repo *r, char ***out_names, unsigned char **out_oids); /* caller frees */

Issue *issue_find(Repo *r, int number);
Pull  *pull_find(Repo *r, int number);
int   label_exists(Repo *r, const char *name);

/* every repo, in creation order (for pagination) */
Repo *repo_at(int index);

#endif
