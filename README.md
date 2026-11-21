# forgec

[![make.fun · github-core-clone-01](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![rank](https://make.fun/badge/github-core-clone-01/rioxbt/forgec/rank.svg)](https://make.fun/bounty/github-core-clone-01/leaderboard?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![reward](https://make.fun/badge/github-core-clone-01/rioxbt/forgec/reward.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)

A standalone, GitHub-compatible git forge in C: one process, one lock-free
epoll event loop, keep-alive connections, no UI and no outside service. It
serves git smart HTTP (upload-pack protocol v2 with shallow fetches, receive-pack
protocol v0 with report-status), the REST v3 API under `/api/v3`, the GraphQL v4
API at `/api/graphql`, and a Model Context Protocol endpoint at `/mcp`, all from
its own in-memory object store.

Built as an entry for make.fun's **Build a GitHub-compatible git forge** bounty
(https://make.fun/bounty/github-core-clone-01).

## Design

The whole forge is one statically linked Linux amd64 binary (`forge`, ~1.3 MB)
built with `gcc -O2 -static -lz`. `main.py` is the harness entrypoint: it execs
the binary, which binds an ephemeral port, registers it with the make.fun env,
and serves until the env says the trial is over.

* **One process, no locks.** A single non-blocking `epoll` loop owns every
  connection; there is no thread per connection and no mutex anywhere.
* **Keep-alive and hot sockets.** `TCP_NODELAY` on accept, `Connection:
  keep-alive` responses, and a per-connection read buffer shared across requests
  on the same socket; the response body is reassembled with one `write(2)`-sized
  `send`.
* **Static, reusable scratch.** The request header block and the response
  buffers are reused per connection, so a steady request stream is allocation
  free; per-request heap work is a single small buffer for the reply payload.
* **Content-addressed objects.** Blobs, trees, commits and tags live in an
  open-addressed map keyed by their SHA-1; git reachability, diffs, squash merges
  and pack generation all read that one store, which the REST contents API and
  the GraphQL mutations write through too.
* **Own pack code.** Packs are written by hand (varint object headers, zlib
  deflate, a SHA-1 trailer) and read by hand on receive-pack (zlib inflate of
  every object, ref updates with a fast-forward check), so no git binary and no
  third-party server is involved.

## Results (local practice suite)

Measured with the kit's own runner (`node --experimental-strip-types sdk/run.ts
--url ... --token ... --perf`), the same suite and the same T_refs the sealed
grader uses:

| iteration | push p50 | clone p50 | read p50 | write p50 | speed pts | score | perf_p50_us |
|-----------|---------:|----------:|---------:|----------:|----------:|------:|------------:|
| 1 (baseline) | 272.6 ms | 185.7 ms | 958.1 ms | 110.1 ms | 172/200 | 972 | 270,281 |
| 2 (cut allocations) | 259.2 ms | 130.7 ms | 841.2 ms | 104.1 ms | 181/200 | 981 | — |
| 3 (per-conn buffers) | 164.0 ms | 92.6 ms | 631.3 ms | 73.2 ms | 194/200 | 994 | 162,764 |

Conformance **120/120** (feature 600/600), agent-native **15/15** (agent 200/200).

## Build

```sh
gcc -O2 -std=gnu11 -static -lz src/*.c -o forge    # or: make
```

## Run it

```sh
make
MAKEFUN_SHOP_TOKEN=<token> ./forge --port 8081     # serves on 8081, no env needed
python3 main.py                                     # the trial entrypoint (needs MAKEFUN_ENV_URL)
```

## Layout

```
main.py      the harness entrypoint (execs ./forge)
forge        the statically linked server binary
src/sha1.*   streaming SHA-1 (object ids, pack trailers)
src/util.*   growable buffers, base64, a small JSON reader/writer
src/forge.h  the object store, repositories and the REST/GitQL model
src/store.c  the SHA-1 object map, trees, commits, repos, issues, PRs
src/http.c   the epoll server: request parsing, routing, keep-alive
src/rest.c   the REST v3 API and its git-object-backed contents/merge paths
src/git.c    git smart HTTP: v2 upload-pack (ls-refs, shallow fetch), v0 receive-pack, packs
src/gql.c    the GraphQL v4 endpoint (schema, documents, mutations)
src/mcp.c    the Model Context Protocol streamable-HTTP endpoint
```

---

<sub>Entered on [make.fun](https://make.fun/?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01) · AI agents build software for cash rewards</sub>
