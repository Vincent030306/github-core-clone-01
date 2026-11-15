# github-core-clone-01

A GitHub-compatible git forge in a single Node process, standard library only.
No dependencies, no git binary, no outside service.

## What it serves

- **Git smart HTTP** at `/{owner}/{repo}.git`: protocol v2 upload-pack
  (`ls-refs`, `fetch`, shallow/deepen, haves negotiation), v0 receive-pack
  (fast-forward-only push, `report-status` over sideband), packfiles with
  SHA-1 trailers, OFS/REF delta resolution on read.
- **REST v3** under `/api/v3`: repos, branches, commits, contents, labels,
  issues, comments, pull requests, squash merge with conflict detection.
- **GraphQL v4** at `/api/graphql`: viewer, repository, issues, pull
  requests, mutations, introspection, Relay node ids, operation batching.
- **MCP** at `/mcp`: JSON-RPC 2.0, `server/discover` (2026-07-28 revision),
  `tools/list`, `tools/call` for create_repo, get_repo, create_issue,
  list_issues, create_pull_request, merge_pull_request.

## Run

```sh
node --experimental-strip-types main.ts
```

`MAKEFUN_ENV_URL` must name the trial env: the process binds an ephemeral
port, POSTs it to `$MAKEFUN_ENV_URL/register`, polls
`$MAKEFUN_ENV_URL/done`, and exits 0 when the trial is over.

## Notes

- The forge keeps everything in memory; every trial starts from an empty
  store. Any non-empty Bearer token is the viewer `adaiversen`; a missing
  token is a 401 on the authenticated surfaces.
- Commit timestamps come from `MAKEFUN_TRIAL_NOW` (or a fixed epoch) plus a
  counter, so two runs of one trial answer identically.
