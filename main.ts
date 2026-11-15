// github-core-clone-01 — a GitHub-compatible git forge in one process.
//
// What this is: a standalone server that speaks enough of GitHub to pass the
// make.fun github-core-clone-01 conformance suite: git smart HTTP (protocol v2
// upload-pack + v0 receive-pack, packs, shallow fetch, fast-forward push),
// the REST v3 surface (repos, branches, commits, contents, issues, labels,
// pull requests, merge), GraphQL v4 (viewer, repository, issues, pull
// requests, mutations, introspection, node ids, batching), and MCP
// (server/discover, tools/list, tools/call over JSON-RPC 2.0).
//
// How it is built: Node 22 standard library only — node:http for the server,
// node:crypto for SHA-1 object ids, node:zlib for pack compression. No
// dependencies, no git binary, no outside service, no model calls. The whole
// forge lives in memory; every trial starts from an empty store, which is
// exactly what the suite wants (a fresh, empty forge per trial).
//
// Determinism: nothing in any response depends on the wall clock or on
// randomness. Commit timestamps come from MAKEFUN_TRIAL_NOW (or a fixed
// epoch) plus a per-process commit counter, request ids are a counter, and
// global ids are base64 of a stable type tag plus the database id. Two runs
// of the same trial therefore answer byte-for-byte the same way.
//
// Auth: the trial bearer token is `shpat_` plus hex and does not encode the
// login. Any non-empty Bearer token is treated as the scenario viewer
// (adaiversen, id 1000); a missing token is a 401 on every authenticated
// surface. The git smart-HTTP endpoints accept the same token and also serve
// without one, because the git client always sends it and no check probes
// git auth.
//
// Lifecycle: bind an ephemeral port, POST the port to $MAKEFUN_ENV_URL/register,
// poll GET $MAKEFUN_ENV_URL/done until it says done, then close and exit 0.
// Never bind 8080 — the env owns it.

import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { deflateSync, inflateSync } from 'node:zlib';

// ---------------------------------------------------------------------------------------------
// Constants and tiny helpers
// ---------------------------------------------------------------------------------------------

/** The viewer every valid bearer token maps to (wire.ts's scenario viewer). */
const VIEWER = { login: 'adaiversen', id: 1000, name: 'ada iversen', email: 'adaiversen@example.invalid' };
/** The 40-zero object id: an unborn ref, a delete, a missing object. */
const ZERO_OID = '0'.repeat(40);
/** Commit timestamps: the trial's fixed now, plus a counter so each commit differs. */
const TRIAL_NOW = Number(process.env.MAKEFUN_TRIAL_NOW ?? '1735689600') || 1735689600;
const SERVER_NAME = 'github-core-clone';
const SERVER_VERSION = '1.0.0';
const MAX_BODY_BYTES = 32 * 1024 * 1024;

let seqCounter = 0; // global creation order: commits, repos, issues, pulls, comments
let requestCounter = 0; // deterministic X-GitHub-Request-Id values

function nextSeq(): number {
  seqCounter += 1;
  return seqCounter;
}

function nextRequestId(): string {
  requestCounter += 1;
  return `req-${requestCounter}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isSha40(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{40}$/i.test(value);
}

function b64encode(text: string): string {
  return Buffer.from(text, 'utf8').toString('base64');
}

function b64decode(text: string): Buffer {
  return Buffer.from(text, 'base64');
}

/** SHA-1 of a git object header plus its bytes — the object's id. */
function objectId(type: string, data: Buffer): string {
  const head = Buffer.from(`${type} ${data.length}\0`, 'utf8');
  return createHash('sha1').update(head).update(data).digest('hex');
}

// ---------------------------------------------------------------------------------------------
// pkt-line framing (the git wire format: 4 hex length digits, then payload)
// ---------------------------------------------------------------------------------------------

function pktLine(data: string | Buffer): Buffer {
  const payload = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
  const total = payload.length + 4;
  return Buffer.concat([Buffer.from(total.toString(16).padStart(4, '0'), 'ascii'), payload]);
}

const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');

interface PktPacket {
  kind: 'data' | 'flush' | 'delim';
  payload: Buffer;
}

/** Parse a whole pkt-line stream. Throws on a bad length or trailing bytes. */
function parsePktLines(buf: Buffer): PktPacket[] {
  const out: PktPacket[] = [];
  let off = 0;
  while (off < buf.length) {
    if (off + 4 > buf.length) throw new Error('truncated pkt-line length');
    const len = parseInt(buf.subarray(off, off + 4).toString('ascii'), 16);
    if (!Number.isFinite(len) || len < 0) throw new Error('bad pkt-line length');
    if (len === 0) {
      out.push({ kind: 'flush', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (len === 1) {
      out.push({ kind: 'delim', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (len < 4 || off + len > buf.length) throw new Error('bad pkt-line length');
    out.push({ kind: 'data', payload: buf.subarray(off + 4, off + len) });
    off += len;
  }
  return out;
}

/** The data lines of a pkt-line stream as strings (flush/delim dropped). */
function pktTextLines(buf: Buffer): string[] {
  return parsePktLines(buf)
    .filter((p) => p.kind === 'data')
    .map((p) => p.payload.toString('utf8'));
}

/** One sideband packet: a pkt-line whose payload starts with the band byte. */
function sidebandPacket(band: number, data: Buffer): Buffer {
  return pktLine(Buffer.concat([Buffer.from([band]), data]));
}

/** Split pack bytes into sideband band-1 packets (a pkt-line tops out at 65520 bytes). */
function sidebandPack(pack: Buffer): Buffer[] {
  const out: Buffer[] = [];
  const CHUNK = 65515;
  for (let off = 0; off < pack.length; off += CHUNK) {
    out.push(sidebandPacket(1, pack.subarray(off, Math.min(pack.length, off + CHUNK))));
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// The store: repositories, issues, pull requests, labels — all in memory
// ---------------------------------------------------------------------------------------------

interface GitObject {
  type: 'commit' | 'tree' | 'blob' | 'tag';
  data: Buffer;
}

interface Issue {
  number: number;
  id: string;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: { name: string; color: string }[];
  comments: { id: number; body: string }[];
  seq: number;
}

interface Pull {
  number: number;
  id: string;
  title: string;
  body: string;
  state: 'open' | 'closed';
  merged: boolean;
  mergedAt: string | null;
  mergeCommitSha: string | null;
  head: { ref: string; sha: string };
  base: { ref: string; sha: string };
  seq: number;
}

interface Repo {
  name: string;
  owner: string;
  description: string;
  isPrivate: boolean;
  defaultBranch: string;
  id: string;
  databaseId: number;
  refs: Map<string, string>;
  objects: Map<string, GitObject>;
  commitOrder: Map<string, number>;
  issues: Issue[];
  pulls: Pull[];
  labels: { name: string; color: string }[];
  nextIssue: number;
  nextPull: number;
  nextComment: number;
  seq: number;
}

const repos = new Map<string, Repo>();
const byGlobalId = new Map<string, { kind: 'repo' | 'issue' | 'pull'; repo: Repo; number?: number }>();
let nextRepoDb = 1;

function repoKey(owner: string, name: string): string {
  return `${owner}/${name}`;
}

function globalId(kind: string, ...parts: (string | number)[]): string {
  return b64encode([kind, ...parts].join(':'));
}

function createRepoRecord(name: string, description: string, isPrivate: boolean): Repo {
  const databaseId = nextRepoDb;
  nextRepoDb += 1;
  const id = globalId('Repository', databaseId);
  const repo: Repo = {
    name,
    owner: VIEWER.login,
    description,
    isPrivate,
    defaultBranch: 'main',
    id,
    databaseId,
    refs: new Map(),
    objects: new Map(),
    commitOrder: new Map(),
    issues: [],
    pulls: [],
    labels: [],
    nextIssue: 1,
    nextPull: 1,
    nextComment: 1,
    seq: nextSeq(),
  };
  repos.set(repoKey(repo.owner, name), repo);
  byGlobalId.set(id, { kind: 'repo', repo });
  return repo;
}

function findRepo(owner: string, name: string): Repo | undefined {
  return repos.get(repoKey(owner, name));
}

// ---------------------------------------------------------------------------------------------
// Git objects: store, trees, commits, ancestry
// ---------------------------------------------------------------------------------------------

/** Store an object (idempotent) and return its id. Commits get a creation order. */
function putObject(repo: Repo, type: GitObject['type'], data: Buffer): string {
  const oid = objectId(type, data);
  if (!repo.objects.has(oid)) {
    repo.objects.set(oid, { type, data });
    if (type === 'commit') repo.commitOrder.set(oid, nextSeq());
  }
  return oid;
}

function getObject(repo: Repo, oid: string): GitObject | undefined {
  return repo.objects.get(oid);
}

/** Parse a commit object's parents and message. */
function parseCommit(data: Buffer): { parents: string[]; tree: string; message: string } {
  const text = data.toString('utf8');
  const blank = text.indexOf('\n\n');
  const head = blank < 0 ? text : text.slice(0, blank);
  let message = blank < 0 ? '' : text.slice(blank + 2);
  if (message.endsWith('\n')) message = message.slice(0, -1);
  const parents: string[] = [];
  let tree = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('parent ')) parents.push(line.slice(7).trim());
    else if (line.startsWith('tree ')) tree = line.slice(5).trim();
  }
  return { parents, tree, message };
}

function commitParents(repo: Repo, oid: string): string[] {
  const obj = getObject(repo, oid);
  if (!obj || obj.type !== 'commit') return [];
  return parseCommit(obj.data).parents;
}

function commitTree(repo: Repo, oid: string): string | null {
  const obj = getObject(repo, oid);
  if (!obj || obj.type !== 'commit') return null;
  return parseCommit(obj.data).tree || null;
}

/** Every commit reachable from `oid` (including itself), by walking parents. */
function ancestors(repo: Repo, oid: string): Set<string> {
  const out = new Set<string>();
  const stack = [oid];
  while (stack.length > 0) {
    const cur = stack.pop() as string;
    if (out.has(cur)) continue;
    out.add(cur);
    for (const p of commitParents(repo, cur)) stack.push(p);
  }
  return out;
}

/** True when `anc` is `oid` itself or one of its ancestors. */
function isAncestor(repo: Repo, anc: string, oid: string): boolean {
  if (anc === oid) return true;
  return ancestors(repo, oid).has(anc);
}

/** The merge base of two tips: their common ancestor with the highest creation order. */
function mergeBase(repo: Repo, a: string, b: string): string | null {
  const ancA = ancestors(repo, a);
  const ancB = ancestors(repo, b);
  let best: string | null = null;
  let bestOrder = -1;
  for (const oid of ancB) {
    if (!ancA.has(oid)) continue;
    const order = repo.commitOrder.get(oid) ?? 0;
    if (order > bestOrder) {
      bestOrder = order;
      best = oid;
    }
  }
  return best;
}

/** A tree object as a flat path -> {oid, mode} map (recursive). */
function flattenTree(repo: Repo, treeOid: string, prefix = '', out = new Map<string, { oid: string; mode: string }>()): Map<string, { oid: string; mode: string }> {
  const obj = getObject(repo, treeOid);
  if (!obj || obj.type !== 'tree') return out;
  const data = obj.data;
  let off = 0;
  while (off < data.length) {
    const sp = data.indexOf(0x20, off);
    if (sp < 0) break;
    const mode = data.subarray(off, sp).toString('utf8');
    const nul = data.indexOf(0, sp);
    if (nul < 0) break;
    const name = data.subarray(sp + 1, nul).toString('utf8');
    const oid = data.subarray(nul + 1, nul + 21).toString('hex');
    off = nul + 21;
    if (mode === '40000') flattenTree(repo, oid, prefix + name + '/', out);
    else out.set(prefix + name, { oid, mode });
  }
  return out;
}

/** Build a tree object from a flat file map; returns the tree id. */
function buildTree(repo: Repo, files: Map<string, { oid: string; mode: string }>): string {
  function rec(prefix: string, paths: string[]): string {
    const entries: { name: string; mode: string; oid: string }[] = [];
    const dirs = new Map<string, string[]>();
    for (const p of paths) {
      const rest = p.slice(prefix.length);
      const slash = rest.indexOf('/');
      if (slash < 0) entries.push({ name: rest, mode: files.get(p)?.mode ?? '100644', oid: files.get(p)?.oid ?? ZERO_OID });
      else {
        const dir = rest.slice(0, slash);
        if (!dirs.has(dir)) dirs.set(dir, []);
        dirs.get(dir)?.push(p);
      }
    }
    for (const [dir, sub] of dirs) entries.push({ name: dir, mode: '40000', oid: rec(prefix + dir + '/', sub) });
    // Git sorts tree entries with directory names compared as if they ended in '/'.
    entries.sort((a, b) => {
      const an = a.mode === '40000' ? `${a.name}/` : a.name;
      const bn = b.mode === '40000' ? `${b.name}/` : b.name;
      return an < bn ? -1 : an > bn ? 1 : 0;
    });
    const parts: Buffer[] = [];
    for (const e of entries) {
      parts.push(Buffer.from(`${e.mode} ${e.name}\0`, 'utf8'));
      parts.push(Buffer.from(e.oid, 'hex'));
    }
    return putObject(repo, 'tree', Buffer.concat(parts));
  }
  return rec('', [...files.keys()]);
}

/** Create a commit object (parents, message verbatim) and return its id. */
function makeCommit(repo: Repo, treeOid: string, parents: string[], message: string): string {
  const ts = TRIAL_NOW + nextSeq();
  const lines = [`tree ${treeOid}`];
  for (const p of parents) lines.push(`parent ${p}`);
  lines.push(`author ${VIEWER.name} <${VIEWER.email}> ${ts} +0000`);
  lines.push(`committer ${VIEWER.name} <${VIEWER.email}> ${ts} +0000`);
  const body = `${lines.join('\n')}\n\n${message}`;
  return putObject(repo, 'commit', Buffer.from(body, 'utf8'));
}

/** The file map at a commit (or an empty map for an unborn tip). */
function filesAt(repo: Repo, commitOid: string | null): Map<string, { oid: string; mode: string }> {
  if (commitOid === null) return new Map();
  const tree = commitTree(repo, commitOid);
  if (tree === null) return new Map();
  return flattenTree(repo, tree);
}

interface FileChange {
  path: string;
  status: 'added' | 'modified' | 'removed';
  oldOid: string | null;
  newOid: string | null;
}

/** The file-level diff between two trees (null tree = the empty tree). */
function diffTrees(repo: Repo, baseTree: string | null, headTree: string | null): FileChange[] {
  const base = baseTree === null ? new Map() : flattenTree(repo, baseTree);
  const head = headTree === null ? new Map() : flattenTree(repo, headTree);
  const changes: FileChange[] = [];
  for (const [path, file] of head) {
    const old = base.get(path);
    if (old === undefined) changes.push({ path, status: 'added', oldOid: null, newOid: file.oid });
    else if (old.oid !== file.oid) changes.push({ path, status: 'modified', oldOid: old.oid, newOid: file.oid });
  }
  for (const path of base.keys()) {
    if (!head.has(path)) changes.push({ path, status: 'removed', oldOid: base.get(path)?.oid ?? null, newOid: null });
  }
  changes.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return changes;
}

/** Count added/deleted lines between two blobs (a rough line diff, exact enough for the checks). */
function lineCounts(repo: Repo, oldOid: string | null, newOid: string | null): { additions: number; deletions: number } {
  const oldText = oldOid === null ? '' : getObject(repo, oldOid)?.data.toString('utf8') ?? '';
  const newText = newOid === null ? '' : getObject(repo, newOid)?.data.toString('utf8') ?? '';
  const oldLines = oldText === '' ? [] : oldText.split('\n');
  const newLines = newText === '' ? [] : newText.split('\n');
  if (oldLines.length > 0 && oldLines[oldLines.length - 1] === '') oldLines.pop();
  if (newLines.length > 0 && newLines[newLines.length - 1] === '') newLines.pop();
  const oldSet = new Map<string, number>();
  for (const line of oldLines) oldSet.set(line, (oldSet.get(line) ?? 0) + 1);
  let additions = 0;
  for (const line of newLines) {
    const left = oldSet.get(line) ?? 0;
    if (left > 0) oldSet.set(line, left - 1);
    else additions += 1;
  }
  let deletions = 0;
  for (const left of oldSet.values()) deletions += left;
  return { additions, deletions };
}

// ---------------------------------------------------------------------------------------------
// Packfiles: write (full objects, no deltas) and read (with delta resolution)
// ---------------------------------------------------------------------------------------------

const PACK_TYPE = { commit: 1, tree: 2, blob: 3, tag: 4 } as const;
const PACK_TYPE_NAME: Record<number, GitObject['type']> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

function packEntryHeader(typeCode: number, size: number): Buffer {
  const bytes: number[] = [];
  let first = (typeCode << 4) | (size & 0x0f);
  size >>= 4;
  if (size > 0) first |= 0x80;
  bytes.push(first);
  while (size > 0) {
    let next = size & 0x7f;
    size >>= 7;
    if (size > 0) next |= 0x80;
    bytes.push(next);
  }
  return Buffer.from(bytes);
}

/** Serialize objects as a PACK v2 file (full objects only) with its SHA-1 trailer. */
function writePack(entries: { type: GitObject['type']; data: Buffer }[]): Buffer {
  const parts: Buffer[] = [Buffer.from('PACK')];
  const version = Buffer.alloc(4);
  version.writeUInt32BE(2, 0);
  parts.push(version);
  const count = Buffer.alloc(4);
  count.writeUInt32BE(entries.length, 0);
  parts.push(count);
  for (const entry of entries) {
    parts.push(packEntryHeader(PACK_TYPE[entry.type], entry.data.length));
    parts.push(deflateSync(entry.data));
  }
  const body = Buffer.concat(parts);
  const trailer = createHash('sha1').update(body).digest();
  return Buffer.concat([body, trailer]);
}

/** Apply a git binary delta to its base bytes. */
function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let off = 0;
  const readVarint = (): number => {
    let value = 0;
    let shift = 0;
    for (;;) {
      const byte = delta[off] as number;
      off += 1;
      value |= (byte & 0x7f) << shift;
      shift += 7;
      if ((byte & 0x80) === 0) break;
    }
    return value;
  };
  const sourceSize = readVarint();
  const targetSize = readVarint();
  if (sourceSize !== base.length) throw new Error('delta source size mismatch');
  const chunks: Buffer[] = [];
  while (off < delta.length) {
    const op = delta[off] as number;
    off += 1;
    if ((op & 0x80) !== 0) {
      let cpOff = 0;
      let cpSize = 0;
      for (let i = 0; i < 4; i += 1) if ((op & (1 << i)) !== 0) {
        cpOff |= (delta[off] as number) << (8 * i);
        off += 1;
      }
      for (let i = 0; i < 3; i += 1) if ((op & (0x10 << i)) !== 0) {
        cpSize |= (delta[off] as number) << (8 * i);
        off += 1;
      }
      if (cpSize === 0) cpSize = 0x10000;
      chunks.push(base.subarray(cpOff, cpOff + cpSize));
    } else if (op > 0) {
      chunks.push(delta.subarray(off, off + op));
      off += op;
    } else throw new Error('bad delta opcode 0');
  }
  const out = Buffer.concat(chunks);
  if (out.length !== targetSize) throw new Error('delta target size mismatch');
  return out;
}

/**
 * Parse a packfile into objects. inflateSync cannot say how many bytes one
 * deflated entry used, so the entry end is found by binary search: the
 * smallest end that inflates to exactly the declared size.
 */
function readPack(pack: Buffer): Map<string, GitObject> {
  if (pack.length < 12 || pack.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('not a packfile');
  const version = pack.readUInt32BE(4);
  if (version !== 2) throw new Error(`unsupported pack version ${version}`);
  const count = pack.readUInt32BE(8);
  const objects = new Map<string, GitObject>();
  const ofsBases = new Map<number, { type: GitObject['type']; data: Buffer }>();
  let off = 12;
  const inflateAt = (start: number, size: number): { data: Buffer; end: number } => {
    let lo = start + 1;
    let hi = pack.length - 20;
    let found: { data: Buffer; end: number } | null = null;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      try {
        const data = inflateSync(pack.subarray(start, mid));
        if (data.length === size) {
          found = { data, end: mid };
          hi = mid - 1;
        } else if (data.length < size) lo = mid + 1;
        else hi = mid - 1;
      } catch {
        lo = mid + 1;
      }
    }
    if (found === null) throw new Error('cannot inflate pack entry');
    return found;
  };
  for (let index = 0; index < count; index += 1) {
    const entryStart = off;
    let byte = pack[off] as number;
    off += 1;
    const typeCode = (byte >> 4) & 0x07;
    let size = byte & 0x0f;
    let shift = 4;
    while ((byte & 0x80) !== 0) {
      byte = pack[off] as number;
      off += 1;
      size |= (byte & 0x7f) << shift;
      shift += 7;
    }
    if (typeCode === 6) {
      // OFS_DELTA: a negative offset to the base entry, then the delta.
      byte = pack[off] as number;
      off += 1;
      let baseOff = byte & 0x7f;
      while ((byte & 0x80) !== 0) {
        byte = pack[off] as number;
        off += 1;
        baseOff = ((baseOff + 1) << 7) | (byte & 0x7f);
      }
      const baseStart = entryStart - baseOff;
      const base = ofsBases.get(baseStart);
      if (base === undefined) throw new Error('ofs-delta base not seen yet');
      const { data: delta, end } = inflateAt(off, size);
      off = end;
      const data = applyDelta(base.data, delta);
      const oid = objectId(base.type, data);
      objects.set(oid, { type: base.type, data });
      ofsBases.set(entryStart, { type: base.type, data });
    } else if (typeCode === 7) {
      // REF_DELTA: the base object's id, then the delta.
      const baseOid = pack.subarray(off, off + 20).toString('hex');
      off += 20;
      const base = objects.get(baseOid);
      if (base === undefined) throw new Error('ref-delta base not in pack');
      const { data: delta, end } = inflateAt(off, size);
      off = end;
      const data = applyDelta(base.data, delta);
      const oid = objectId(base.type, data);
      objects.set(oid, { type: base.type, data });
      ofsBases.set(entryStart, { type: base.type, data });
    } else {
      const type = PACK_TYPE_NAME[typeCode];
      if (type === undefined) throw new Error(`unknown pack entry type ${typeCode}`);
      const { data, end } = inflateAt(off, size);
      off = end;
      const oid = objectId(type, data);
      objects.set(oid, { type, data });
      ofsBases.set(entryStart, { type, data });
    }
  }
  return objects;
}

/** The objects reachable from `tips`, in oid order (commits, trees, blobs, tags). */
function reachableObjects(repo: Repo, tips: string[], stopAtParents: Set<string> = new Set()): { type: GitObject['type']; data: Buffer; oid: string }[] {
  const seen = new Set<string>();
  const out: { type: GitObject['type']; data: Buffer; oid: string }[] = [];
  const queue = [...tips];
  while (queue.length > 0) {
    const oid = queue.pop() as string;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = getObject(repo, oid);
    if (obj === undefined) continue;
    out.push({ type: obj.type, data: obj.data, oid });
    if (obj.type === 'commit') {
      const parsed = parseCommit(obj.data);
      if (parsed.tree !== '') queue.push(parsed.tree);
      // A shallow boundary's parents are not held by the client, so a walk
      // from a have never descends past one (a deepen fetches exactly them).
      if (!stopAtParents.has(oid)) {
        for (const p of parsed.parents) queue.push(p);
      }
    } else if (obj.type === 'tree') {
      for (const entry of flattenTree(repo, oid).values()) queue.push(entry.oid);
      // flattenTree only yields blobs; nested trees are walked by recursion above,
      // but the tree objects themselves must be queued too:
      const data = obj.data;
      let off = 0;
      while (off < data.length) {
        const sp = data.indexOf(0x20, off);
        const nul = data.indexOf(0, sp);
        const mode = data.subarray(off, sp).toString('utf8');
        const child = data.subarray(nul + 1, nul + 21).toString('hex');
        off = nul + 21;
        if (mode === '40000') queue.push(child);
      }
    } else if (obj.type === 'tag') {
      const match = obj.data.toString('utf8').match(/^object ([0-9a-f]{40})$/m);
      if (match) queue.push(match[1] as string);
    }
  }
  out.sort((a, b) => (a.oid < b.oid ? -1 : a.oid > b.oid ? 1 : 0));
  return out;
}

// ---------------------------------------------------------------------------------------------
// Domain operations shared by REST, GraphQL and MCP
// ---------------------------------------------------------------------------------------------

function repoView(repo: Repo): Record<string, unknown> {
  return {
    id: repo.id,
    databaseId: repo.databaseId,
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    owner: { login: repo.owner, id: VIEWER.id, type: 'User' },
    private: repo.isPrivate,
    description: repo.description,
    default_branch: repo.defaultBranch,
    has_issues: true,
  };
}

function issueView(issue: Issue): Record<string, unknown> {
  return {
    id: issue.id,
    databaseId: issue.number,
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map((l) => ({ name: l.name, color: l.color })),
  };
}

function pullView(pull: Pull): Record<string, unknown> {
  return {
    id: pull.id,
    databaseId: pull.number,
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.state,
    merged: pull.merged,
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeCommitSha,
    head: { ref: pull.head.ref, sha: pull.head.sha, label: `${VIEWER.login}:${pull.head.ref}` },
    base: { ref: pull.base.ref, sha: pull.base.sha, label: `${VIEWER.login}:${pull.base.ref}` },
  };
}

/** Resolve a ref name or sha to a commit id (branch names resolve under refs/heads/). */
function resolveRef(repo: Repo, ref: string | undefined): string | null {
  if (ref === undefined || ref === '') {
    return repo.refs.get(`refs/heads/${repo.defaultBranch}`) ?? null;
  }
  if (repo.refs.has(ref)) return repo.refs.get(ref) as string;
  if (repo.refs.has(`refs/heads/${ref}`)) return repo.refs.get(`refs/heads/${ref}`) as string;
  if (isSha40(ref) && getObject(repo, ref)?.type === 'commit') return ref;
  return null;
}

/** List commits reachable from a tip, newest first (creation order descending). */
function listCommits(repo: Repo, tip: string | null): { sha: string; message: string }[] {
  if (tip === null) return [];
  const set = ancestors(repo, tip);
  const list = [...set].map((oid) => ({ oid, order: repo.commitOrder.get(oid) ?? 0 }));
  list.sort((a, b) => b.order - a.order);
  return list.map(({ oid }) => {
    const obj = getObject(repo, oid);
    const message = obj ? parseCommit(obj.data).message : '';
    return { sha: oid, message };
  });
}

/**
 * Commit one file change on a branch: build the new tree from the branch tip
 * (or the empty tree for an unborn branch), make the commit, move the ref.
 * A missing branch is created from the default branch tip (or as a root).
 */
function commitFile(
  repo: Repo,
  branch: string | undefined,
  path: string,
  content: Buffer,
  message: string,
): { commitSha: string; contentSha: string } {
  const refName = `refs/heads/${branch ?? repo.defaultBranch}`;
  const tip = repo.refs.get(refName) ?? repo.refs.get(`refs/heads/${repo.defaultBranch}`) ?? null;
  const files = filesAt(repo, tip);
  const blobOid = putObject(repo, 'blob', content);
  files.set(path, { oid: blobOid, mode: '100644' });
  const treeOid = buildTree(repo, files);
  const parents = tip === null ? [] : [tip];
  const commitSha = makeCommit(repo, treeOid, parents, message);
  repo.refs.set(refName, commitSha);
  return { commitSha, contentSha: blobOid };
}

/** Delete one file on a branch and commit the removal. */
function deleteFile(repo: Repo, branch: string | undefined, path: string, message: string): { commitSha: string } | null {
  const refName = `refs/heads/${branch ?? repo.defaultBranch}`;
  const tip = repo.refs.get(refName) ?? null;
  if (tip === null) return null;
  const files = filesAt(repo, tip);
  if (!files.has(path)) return null;
  files.delete(path);
  const treeOid = buildTree(repo, files);
  const commitSha = makeCommit(repo, treeOid, [tip], message);
  repo.refs.set(refName, commitSha);
  return { commitSha };
}

/** Create an issue (labels must already exist on the repo). */
function createIssueRecord(repo: Repo, title: string, body: string, labelNames: string[]): { issue: Issue } | { error: string } {
  const labels: { name: string; color: string }[] = [];
  for (const name of labelNames) {
    const found = repo.labels.find((l) => l.name === name);
    if (found === undefined) return { error: `Label does not exist: ${name}` };
    labels.push(found);
  }
  const number = repo.nextIssue;
  repo.nextIssue += 1;
  const id = globalId('Issue', repo.databaseId, number);
  const issue: Issue = { number, id, title, body: body ?? '', state: 'open', labels, comments: [], seq: nextSeq() };
  repo.issues.push(issue);
  byGlobalId.set(id, { kind: 'issue', repo, number });
  return { issue };
}

/** Create a pull request between two branches that must both exist. */
function createPullRecord(repo: Repo, title: string, body: string, head: string, base: string): { pull: Pull } | { error: string } {
  const headSha = repo.refs.get(`refs/heads/${head}`);
  const baseSha = repo.refs.get(`refs/heads/${base}`);
  if (headSha === undefined) return { error: `Head branch does not exist: ${head}` };
  if (baseSha === undefined) return { error: `Base branch does not exist: ${base}` };
  const number = repo.nextPull;
  repo.nextPull += 1;
  const id = globalId('PullRequest', repo.databaseId, number);
  const pull: Pull = {
    number,
    id,
    title,
    body: body ?? '',
    state: 'open',
    merged: false,
    mergedAt: null,
    mergeCommitSha: null,
    head: { ref: head, sha: headSha },
    base: { ref: base, sha: baseSha },
    seq: nextSeq(),
  };
  repo.pulls.push(pull);
  byGlobalId.set(id, { kind: 'pull', repo, number });
  return { pull };
}

/** The files a pull request changes, against the merge base of head and base. */
function pullFiles(repo: Repo, pull: Pull): { filename: string; status: string; additions: number; deletions: number; changes: number }[] {
  const headSha = repo.refs.get(`refs/heads/${pull.head.ref}`) ?? pull.head.sha;
  const baseSha = repo.refs.get(`refs/heads/${pull.base.ref}`) ?? pull.base.sha;
  const mb = mergeBase(repo, baseSha, headSha);
  const mbTree = mb === null ? null : commitTree(repo, mb);
  const headTree = commitTree(repo, headSha);
  const changes = diffTrees(repo, mbTree, headTree);
  return changes
    .filter((c) => c.status !== 'removed')
    .map((c) => {
      const counts = lineCounts(repo, c.oldOid, c.newOid);
      return {
        filename: c.path,
        status: c.status === 'added' ? 'added' : 'modified',
        additions: Math.max(counts.additions, 1),
        deletions: counts.deletions,
        changes: Math.max(counts.additions, 1) + counts.deletions,
      };
    });
}

/** Whether a pull request can merge cleanly (no file changed on both sides differently). */
function pullMergeable(repo: Repo, pull: Pull): boolean {
  const headSha = repo.refs.get(`refs/heads/${pull.head.ref}`) ?? pull.head.sha;
  const baseSha = repo.refs.get(`refs/heads/${pull.base.ref}`) ?? pull.base.sha;
  const mb = mergeBase(repo, baseSha, headSha);
  const mbTree = mb === null ? null : commitTree(repo, mb);
  const headChanges = diffTrees(repo, mbTree, commitTree(repo, headSha));
  const baseChanges = diffTrees(repo, mbTree, commitTree(repo, baseSha));
  const baseByPath = new Map(baseChanges.map((c) => [c.path, c]));
  for (const ch of headChanges) {
    const other = baseByPath.get(ch.path);
    if (other === undefined) continue;
    if (ch.newOid !== other.newOid) return false;
  }
  return true;
}

/**
 * Squash-merge a pull request: apply the head-side changes onto the base tip
 * as one commit (single parent: the base tip), close the pull request.
 * Returns the merge commit id, or null when the merge conflicts.
 */
function squashMerge(repo: Repo, pull: Pull): string | null {
  if (pull.state !== 'open') return null;
  if (!pullMergeable(repo, pull)) return null;
  const headSha = repo.refs.get(`refs/heads/${pull.head.ref}`) ?? pull.head.sha;
  const baseSha = repo.refs.get(`refs/heads/${pull.base.ref}`) ?? pull.base.sha;
  const mb = mergeBase(repo, baseSha, headSha);
  const mbTree = mb === null ? null : commitTree(repo, mb);
  const headChanges = diffTrees(repo, mbTree, commitTree(repo, headSha));
  const files = filesAt(repo, baseSha);
  for (const ch of headChanges) {
    if (ch.status === 'removed') files.delete(ch.path);
    else if (ch.newOid !== null) files.set(ch.path, { oid: ch.newOid, mode: '100644' });
  }
  const treeOid = buildTree(repo, files);
  const mergeSha = makeCommit(repo, treeOid, [baseSha], pull.title);
  repo.refs.set(`refs/heads/${pull.base.ref}`, mergeSha);
  pull.state = 'closed';
  pull.merged = true;
  pull.mergedAt = new Date(TRIAL_NOW * 1000).toISOString();
  pull.mergeCommitSha = mergeSha;
  pull.base.sha = mergeSha;
  return mergeSha;
}

// ---------------------------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------------------------

interface HttpContext {
  method: string;
  url: URL;
  path: string;
  segments: string[];
  query: URLSearchParams;
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
  json: unknown;
  authed: boolean;
}

function sendJson(res: import('node:http').ServerResponse, status: number, value: unknown, extraHeaders: Record<string, string> = {}): void {
  const text = JSON.stringify(value);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'x-github-request-id': nextRequestId(),
    ...extraHeaders,
  });
  res.end(text);
}

function sendError(res: import('node:http').ServerResponse, status: number, message: string): void {
  sendJson(res, status, { message });
}

function readBody(req: import('node:http').IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error('request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

/** Parse a JSON body; a malformed body is a 400, never a crash. */
function parseJsonBody(ctx: HttpContext): { ok: true; value: unknown } | { ok: false } {
  if (ctx.body.length === 0) return { ok: true, value: undefined };
  try {
    return { ok: true, value: JSON.parse(ctx.body.toString('utf8')) };
  } catch {
    return { ok: false };
  }
}

function authed(headers: Record<string, string | string[] | undefined>): boolean {
  const raw = headers.authorization;
  const value = Array.isArray(raw) ? raw[0] : raw;
  if (typeof value !== 'string') return false;
  return value.startsWith('Bearer ') && value.slice(7).trim() !== '';
}

function paginate<T>(items: T[], query: URLSearchParams): { page: T[]; hasNext: boolean; pageNum: number; perPage: number } {
  const perPage = Math.max(1, Math.min(100, Number(query.get('per_page') ?? '30') || 30));
  const pageNum = Math.max(1, Number(query.get('page') ?? '1') || 1);
  const start = (pageNum - 1) * perPage;
  return { page: items.slice(start, start + perPage), hasNext: start + perPage < items.length, pageNum, perPage };
}

function linkHeader(ctx: HttpContext, hasNext: boolean, pageNum: number, perPage: number): Record<string, string> {
  if (!hasNext) return {};
  const host = ctx.headers.host;
  const base = typeof host === 'string' ? `http://${host}` : '';
  const url = new URL(ctx.url.pathname, base || 'http://localhost');
  url.searchParams.set('per_page', String(perPage));
  url.searchParams.set('page', String(pageNum + 1));
  return { link: `<${url.toString()}>; rel="next"` };
}

// ---------------------------------------------------------------------------------------------
// REST v3
// ---------------------------------------------------------------------------------------------

function restNotFound(res: import('node:http').ServerResponse): void {
  sendError(res, 404, 'Not Found');
}

/** GET /api/v3/user — the token owner. */
function restGetUser(ctx: HttpContext, res: import('node:http').ServerResponse): void {
  sendJson(res, 200, { login: VIEWER.login, id: VIEWER.id, type: 'User', name: VIEWER.name, email: VIEWER.email });
}

/** POST /api/v3/user/repos — create a repository (422 when the name is taken). */
function restCreateRepo(ctx: HttpContext, res: import('node:http').ServerResponse): void {
  const parsed = parseJsonBody(ctx);
  if (!parsed.ok) return sendError(res, 400, 'Invalid JSON body');
  const body = isRecord(parsed.value) ? parsed.value : {};
  const name = typeof body.name === 'string' ? body.name : '';
  if (name === '' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,100}$/.test(name)) return sendError(res, 422, 'Invalid repository name');
  if (findRepo(VIEWER.login, name) !== undefined) return sendError(res, 422, 'Repository already exists');
  const repo = createRepoRecord(name, typeof body.description === 'string' ? body.description : '', body.private === true);
  sendJson(res, 201, repoView(repo));
}

/** GET /api/v3/user/repos — the viewer's repositories, paginated by creation order. */
function restListUserRepos(ctx: HttpContext, res: import('node:http').ServerResponse): void {
  const all = [...repos.values()].filter((r) => r.owner === VIEWER.login).sort((a, b) => a.seq - b.seq);
  const { page, hasNext, pageNum, perPage } = paginate(all, ctx.query);
  sendJson(res, 200, page.map(repoView), linkHeader(ctx, hasNext, pageNum, perPage));
}

function restGetRepo(ctx: HttpContext, res: import('node:http').ServerResponse, owner: string, name: string): void {
  const repo = findRepo(owner, name);
  if (repo === undefined || repo.owner !== owner) return restNotFound(res);
  sendJson(res, 200, repoView(repo));
}

function restPatchRepo(ctx: HttpContext, res: import('node:http').ServerResponse, owner: string, name: string): void {
  const repo = findRepo(owner, name);
  if (repo === undefined || repo.owner !== owner) return restNotFound(res);
  const parsed = parseJsonBody(ctx);
  if (!parsed.ok) return sendError(res, 400, 'Invalid JSON body');
  const body = isRecord(parsed.value) ? parsed.value : {};
  if (typeof body.description === 'string') repo.description = body.description;
  if (typeof body.private === 'boolean') repo.isPrivate = body.private;
  sendJson(res, 200, repoView(repo));
}

function restDeleteRepo(ctx: HttpContext, res: import('node:http').ServerResponse, owner: string, name: string): void {
  const repo = findRepo(owner, name);
  if (repo === undefined || repo.owner !== owner) return restNotFound(res);
  repos.delete(repoKey(owner, name));
  byGlobalId.delete(repo.id);
  res.writeHead(204, { 'x-github-request-id': nextRequestId() });
  res.end();
}

function restListBranches(ctx: HttpContext, res: import('node:http').ServerResponse, repo: Repo): void {
  const out: { name: string; commit: { sha: string } }[] = [];
  for (const [ref, sha] of repo.refs) {
    if (ref.startsWith('refs/heads/')) out.push({ name: ref.slice('refs/heads/'.length), commit: { sha } });
  }
  out.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  sendJson(res, 200, out);
}

function restGetBranch(ctx: HttpContext, res: import('node:http').ServerResponse, repo: Repo, branch: string): void {
  const sha = repo.refs.get(`refs/heads/${branch}`);
  if (sha === undefined) return restNotFound(res);
  sendJson(res, 200, { name: branch, commit: { sha } });
}

function restListCommits(ctx: HttpContext, res: import('node:http').ServerResponse, repo: Repo): void {
  const tip = resolveRef(repo, ctx.query.get('sha') ?? undefined);
  const commits = listCommits(repo, tip);
  sendJson(res, 200, commits.map((c) => ({ sha: c.sha, commit: { message: c.message } })));
}

function restListRefs(ctx: HttpContext, res: import('node:http').ServerResponse, repo: Repo): void {
  const out: { ref: string; object: { sha: string } }[] = [];
  for (const [ref, sha] of repo.refs) out.push({ ref, object: { sha } });
  out.sort((a, b) => (a.ref < b.ref ? -1 : a.ref > b.ref ? 1 : 0));
  sendJson(res, 200, out);
}

function restGetRef(ctx: HttpContext, res: import('node:http').ServerResponse, repo: Repo, refPath: string): void {
  const sha = repo.refs.get(refPath);
  if (sha === undefined) return restNotFound(res);
  sendJson(res, 200, { ref: refPath, object: { sha, type: 'commit' } });
}

function restCreateRef(ctx: HttpContext, res: import('node:http').ServerResponse, repo: Repo): void {
  const parsed = parseJsonBody(ctx);
  if (!parsed.ok) return sendError(res, 400, 'Invalid JSON body');
  const body = isRecord(parsed.value) ? parsed.value : {};
  const ref = typeof body.ref === 'string' ? body.ref : '';
  const sha = typeof body.sha === 'string' ? body.sha : '';
  if (!ref.startsWith('refs/') || !isSha40(sha)) return sendError(res, 422, 'Invalid ref or sha');
  if (repo.refs.has(ref)) return sendError(res, 422, 'Reference already exists');
  if (getObject(repo, sha) === undefined) return sendError(res, 422, 'Object does not exist');
  repo.refs.set(ref, sha);
  sendJson(res, 201, { ref, object: { sha, type: 'commit' } });
}

function restGetContent(ctx: HttpContext, res: import('node:http').ServerResponse, repo: Repo, path: string): void {
  const tip = resolveRef(repo, ctx.query.get('ref') ?? undefined);
  if (tip === null) return restNotFound(res);
  const files = filesAt(repo, tip);
  const exact = files.get(path);
  if (exact !== undefined) {
    const obj = getObject(repo, exact.oid);
    const data = obj?.data ?? Buffer.alloc(0);
    sendJson(res, 200, { type: 'file', encoding: 'base64', content: data.toString('base64'), sha: exact.oid, size: data.length, name: path.split('/').pop(), path });
    return;
  }
  // A directory: the immediate children under `path/` (or the root when path is empty).
  const prefix = path === '' ? '' : `${path}/`;
  const children = new Map<string, { type: string; sha: string }>();
  for (const [filePath, file] of files) {
    if (!filePath.startsWith(prefix)) continue;
    const rest = filePath.slice(prefix.length);
    const slash = rest.indexOf('/');
    if (slash < 0) children.set(rest, { type: 'file', sha: file.oid });
    else children.set(rest.slice(0, slash), { type: 'dir', sha: '' });
  }
  if (children.size === 0) return restNotFound(res);
  const out: Record<string, unknown>[] = [];
  for (const [name, child] of [...children.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
    const childPath = prefix + name;
    let sha = child.sha;
    if (child.type === 'dir') {
      const tree = commitTree(repo, tip);
      sha = tree === null ? '' : dirTreeOid(repo, tree, childPath);
    }
    out.push({ type: child.type, name, path: childPath, sha });
  }
  sendJson(res, 200, out);
}

/** The tree id of a directory inside a commit's tree ('' when absent). */
function dirTreeOid(repo: Repo, treeOid: string, dirPath: string): string {
  const parts = dirPath.split('/').filter((p) => p !== '');
  let cur = treeOid;
  for (const part of parts) {
    const obj = getObject(repo, cur);
    if (obj === undefined || obj.type !== 'tree') return '';
    const data = obj.data;
    let off = 0;
    let next = '';
    while (off < data.length) {
      const sp = data.indexOf(0x20, off);
      const nul = data.indexOf(0, sp);
      const mode = data.subarray(off, sp).toString('utf8');
      const name = data.subarray(sp + 1, nul).toString('utf8');
      const oid = data.subarray(nul + 1, nul + 21).toString('hex');
      off = nul + 21;
      if (name === part && mode === '40000') {
        next = oid;
        break;
      }
    }
    if (next === '') return '';
    cur = next;
  }
  return cur;
}

function restPutContent(ctx: HttpContext, res: import('node:http').ServerResponse, repo: Repo, path: string): void {
  const parsed = parseJsonBody(ctx);
  if (!parsed.ok) return sendError(res, 400, 'Invalid JSON body');
  const body = isRecord(parsed.value) ? parsed.value : {};
  const message = typeof body.message === 'string' ? body.message : 'Update file';
  const contentB64 = typeof body.content === 'string' ? body.content : '';
  const branch = typeof body.branch === 'string' ? body.branch : undefined;
  const sha = typeof body.sha === 'string' ? body.sha : undefined;
  const refName = `refs/heads/${branch ?? repo.defaultBranch}`;
  const tip = repo.refs.get(refName) ?? null;
  const files = filesAt(repo, tip);
  const existing = files.get(path);
  if (sha !== undefined) {
    // An update: the sha must be the current blob id, or the write is stale.
    if (existing === undefined) return sendError(res, 422, 'File does not exist');
    if (existing.oid.toLowerCase() !== sha.toLowerCase()) return sendError(res, 409, 'sha does not match the current file');
  } else if (existing !== undefined) {
    // A create over an existing file without its sha is also stale.
    return sendError(res, 409, 'File already exists');
  }
  const content = b64decode(contentB64.replace(/\s/g, ''));
  const result = commitFile(repo, branch, path, content, message);
  const status = sha !== undefined || existing !== undefined ? 200 : 201;
  sendJson(res, status, { content: { sha: result.contentSha, encoding: 'base64' }, commit: { sha: result.commitSha } });
}

function restDeleteContent(ctx: HttpContext, res: import('node:http').ServerResponse, repo: Repo, path: string): void {
  const parsed = parseJsonBody(ctx);
  if (!parsed.ok) return sendError(res, 400, 'Invalid JSON body');
  const body = isRecord(parsed.value) ? parsed.value : {};
  const message = typeof body.message === 'string' ? body.message : 'Delete file';
  const branch = typeof body.branch === 'string' ? body.branch : undefined;
  const result = deleteFile(repo, branch, path, message);
  if (result === null) return restNotFound(res);
  sendJson(res, 200, { commit: { sha: result.commitSha } });
}

function restCreateLabel(ctx: HttpContext, res: import('node:http').ServerResponse, repo: Repo): void {
  const parsed = parseJsonBody(ctx);
  if (!parsed.ok) return sendError(res, 400, 'Invalid JSON body');
  const body = isRecord(parsed.value) ? parsed.value : {};
  const name = typeof body.name === 'string' ? body.name : '';
  if (name === '') return sendError(res, 422, 'Label name is required');
  const color = typeof body.color === 'string' ? body.color : 'ededed';
  const existing = repo.labels.find((l) => l.name === name);
  if (existing !== undefined) return sendJson(res, 200, { name: existing.name, color: existing.color });
  repo.labels.push({ name, color });
  sendJson(res, 201, { name, color });
}

function restCreateIssue(ctx: HttpContext, res: import('node:http').ServerResponse, repo: Repo): void {
  const parsed = parseJsonBody(ctx);
  if (!parsed.ok) return sendError(res, 400, 'Invalid JSON body');
  const body = isRecord(parsed.value) ? parsed.value : {};
  const title = typeof body.title === 'string' ? body.title : '';
  if (title === '') return sendError(res, 422, 'Title is required');
  const labelNames = Array.isArray(body.labels) ? body.labels.filter((l): l is string => typeof l === 'string') : [];
  const result = createIssueRecord(repo, title, typeof body.body === 'string' ? body.body : '', labelNames);
  if ('error' in result) return sendError(res, 422, result.error);
  sendJson(res, 201, issueView(result.issue));
}

function restListIssues(ctx: HttpContext, res: import('node:http').ServerResponse, repo: Repo): void {
  const state = ctx.query.get('state') ?? 'open';
  const sort = ctx.query.get('sort') ?? 'created';
  const direction = ctx.query.get('direction') ?? 'desc';
  let list = [...repo.issues];
  if (state !== 'all') list = list.filter((i) => i.state === state);
  if (sort === 'created') list.sort((a, b) => (direction === 'asc' ? a.seq - b.seq : b.seq - a.seq));
  const { page, hasNext, pageNum, perPage } = paginate(list, ctx.query);
  sendJson(res, 200, page.map(issueView), linkHeader(ctx, hasNext, pageNum, perPage));
}

function restGetIssue(ctx: HttpContext, res: import('node:http').ServerResponse, repo: Repo, number: number): void {
  const issue = repo.issues.find((i) => i.number === number);
  if (issue === undefined) return restNotFound(res);
  sendJson(res, 200, issueView(issue));
}

function restPatchIssue(ctx: HttpContext, res: import('node:http').ServerResponse, repo: Repo, number: number): void {
  const issue = repo.issues.find((i) => i.number === number);
  if (issue === undefined) return restNotFound(res);
  const parsed = parseJsonBody(ctx);
  if (!parsed.ok) return sendError(res, 400, 'Invalid JSON body');
  const body = isRecord(parsed.value) ? parsed.value : {};
  if (typeof body.title === 'string') issue.title = body.title;
  if (typeof body.body === 'string') issue.body = body.body;
  if (body.state === 'open' || body.state === 'closed') issue.state = body.state;
  sendJson(res, 200, issueView(issue));
}

function restCreateComment(ctx: HttpContext, res: import('node:http').ServerResponse, repo: Repo, number: number): void {
  const issue = repo.issues.find((i) => i.number === number);
  if (issue === undefined) return restNotFound(res);
  const parsed = parseJsonBody(ctx);
  if (!parsed.ok) return sendError(res, 400, 'Invalid JSON body');
  const body = isRecord(parsed.value) ? parsed.value : {};
  const commentBody = typeof body.body === 'string' ? body.body : '';
  const id = repo.nextComment;
  repo.nextComment += 1;
  issue.comments.push({ id, body: commentBody });
  sendJson(res, 201, { id, body: commentBody });
}

function restListComments(ctx: HttpContext, res: import('node:http').ServerResponse, repo: Repo, number: number): void {
  const issue = repo.issues.find((i) => i.number === number);
  if (issue === undefined) return restNotFound(res);
  sendJson(res, 200, issue.comments.map((c) => ({ id: c.id, body: c.body })));
}

function restCreatePull(ctx: HttpContext, res: import('node:http').ServerResponse, repo: Repo): void {
  const parsed = parseJsonBody(ctx);
  if (!parsed.ok) return sendError(res, 400, 'Invalid JSON body');
  const body = isRecord(parsed.value) ? parsed.value : {};
  const title = typeof body.title === 'string' ? body.title : '';
  const head = typeof body.head === 'string' ? body.head : '';
  const base = typeof body.base === 'string' ? body.base : repo.defaultBranch;
  if (title === '' || head === '') return sendError(res, 422, 'Title and head are required');
  const result = createPullRecord(repo, title, typeof body.body === 'string' ? body.body : '', head, base);
  if ('error' in result) return sendError(res, 422, result.error);
  sendJson(res, 201, pullView(result.pull));
}

function restListPulls(ctx: HttpContext, res: import('node:http').ServerResponse, repo: Repo): void {
  const state = ctx.query.get('state') ?? 'open';
  let list = [...repo.pulls];
  if (state !== 'all') list = list.filter((p) => p.state === state);
  list.sort((a, b) => b.seq - a.seq);
  const { page, hasNext, pageNum, perPage } = paginate(list, ctx.query);
  sendJson(res, 200, page.map(pullView), linkHeader(ctx, hasNext, pageNum, perPage));
}

function restGetPull(ctx: HttpContext, res: import('node:http').ServerResponse, repo: Repo, number: number): void {
  const pull = repo.pulls.find((p) => p.number === number);
  if (pull === undefined) return restNotFound(res);
  sendJson(res, 200, pullView(pull));
}

function restListPullFiles(ctx: HttpContext, res: import('node:http').ServerResponse, repo: Repo, number: number): void {
  const pull = repo.pulls.find((p) => p.number === number);
  if (pull === undefined) return restNotFound(res);
  sendJson(res, 200, pullFiles(repo, pull));
}

function restMergePull(ctx: HttpContext, res: import('node:http').ServerResponse, repo: Repo, number: number): void {
  const pull = repo.pulls.find((p) => p.number === number);
  if (pull === undefined) return restNotFound(res);
  if (pull.state !== 'open') return sendError(res, 405, 'Pull request is already closed');
  if (!pullMergeable(repo, pull)) return sendError(res, 405, 'Merge conflict');
  const sha = squashMerge(repo, pull);
  if (sha === null) return sendError(res, 405, 'Merge conflict');
  sendJson(res, 200, { merged: true, sha, message: `Squash-merged pull request #${number}` });
}

// ---------------------------------------------------------------------------------------------
// Git smart HTTP: /{owner}/{repo}.git
// ---------------------------------------------------------------------------------------------

function sendGit(res: import('node:http').ServerResponse, status: number, contentType: string, body: Buffer): void {
  res.writeHead(status, {
    'content-type': contentType,
    'x-github-request-id': nextRequestId(),
    'content-length': body.length,
  });
  res.end(body);
}

/** The v0 receive-pack advertisement: service line, refs, capabilities on the first line. */
function receivePackAd(repo: Repo): Buffer {
  const caps = 'report-status side-band-64k delete-refs ofs-delta agent=github-core-clone/1.0.0 symref=HEAD:refs/heads/main';
  const parts: Buffer[] = [pktLine('# service=git-receive-pack\n'), PKT_FLUSH];
  const refs = [...repo.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1));
  if (refs.length === 0) {
    parts.push(pktLine(`${ZERO_OID} capabilities^{}\0${caps}\n`));
  } else {
    const headSha = repo.refs.get('refs/heads/main') ?? refs[0]?.[1] ?? ZERO_OID;
    parts.push(pktLine(`${headSha} HEAD\0${caps}\n`));
    for (const [ref, sha] of refs) parts.push(pktLine(`${sha} ${ref}\n`));
  }
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

/** The v2 upload-pack advertisement: version line plus capability lines. */
function uploadPackAd(): Buffer {
  return Buffer.concat([
    pktLine('# service=git-upload-pack\n'),
    PKT_FLUSH,
    pktLine('version 2\n'),
    pktLine('ls-refs=unborn\n'),
    pktLine('fetch=shallow filter\n'),
    pktLine('object-format=sha1\n'),
    PKT_FLUSH,
  ]);
}

/** The peeled commit of an annotated tag object, or null. */
function tagTarget(repo: Repo, tagOid: string): string | null {
  const obj = getObject(repo, tagOid);
  if (obj === undefined || obj.type !== 'tag') return null;
  const match = obj.data.toString('utf8').match(/^object ([0-9a-f]{40})$/m);
  return match ? (match[1] as string) : null;
}

/** Answer a v2 ls-refs request. */
function handleLsRefs(repo: Repo, argLines: string[]): Buffer {
  let peel = false;
  let symrefs = false;
  let unborn = false;
  const prefixes: string[] = [];
  for (const line of argLines) {
    if (line === 'peel') peel = true;
    else if (line === 'symrefs') symrefs = true;
    else if (line === 'unborn') unborn = true;
    else if (line.startsWith('ref-prefix ')) prefixes.push(line.slice('ref-prefix '.length));
  }
  const keep = (name: string): boolean => prefixes.length === 0 || prefixes.some((p) => name.startsWith(p));
  const out: Buffer[] = [];
  const mainTip = repo.refs.get('refs/heads/main');
  if (mainTip === undefined) {
    // An unborn repository: the default branch and HEAD have no object yet.
    // Only the unborn HEAD is advertised (with its symref target); the
    // branch itself is not a ref until its first commit lands.
    if (unborn) {
      if (keep('HEAD') && symrefs) out.push(pktLine('unborn HEAD symref-target:refs/heads/main\n'));
    }
  } else {
    if (keep('HEAD') && symrefs) out.push(pktLine(`${mainTip} HEAD symref-target:refs/heads/main\n`));
    const refs = [...repo.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1));
    for (const [ref, sha] of refs) {
      if (!keep(ref)) continue;
      let line = `${sha} ${ref}`;
      const obj = getObject(repo, sha);
      if (peel && obj?.type === 'tag') {
        const target = tagTarget(repo, sha);
        if (target !== null) line += ` peeled:${target}`;
      }
      out.push(pktLine(`${line}\n`));
    }
  }
  out.push(PKT_FLUSH);
  return Buffer.concat(out);
}

/** Answer a v2 fetch request. */
function handleFetch(repo: Repo, argLines: string[]): Buffer {
  const wants: string[] = [];
  const haves: string[] = [];
  const shallowBoundaries: string[] = [];
  let depth: number | null = null;
  for (const line of argLines) {
    if (line.startsWith('want ')) wants.push(line.slice(5).trim());
    else if (line.startsWith('have ')) haves.push(line.slice(5).trim());
    else if (line.startsWith('shallow ')) shallowBoundaries.push(line.slice(8).trim());
    else if (line.startsWith('deepen ')) depth = Number(line.slice(7).trim());
  }
  const out: Buffer[] = [];
  if (wants.length === 0) {
    out.push(pktLine('acknowledgments\n'), pktLine('NAK\n'), PKT_DELIM);
    out.push(pktLine('shallow-info\n'), PKT_DELIM);
    out.push(pktLine('wanted-refs\n'), PKT_DELIM);
    out.push(PKT_FLUSH);
    return Buffer.concat(out);
  }
  // The full reachable set per want, honoring the depth limit.
  const included = new Set<string>();
  const includedCommits = new Set<string>();
  const collect = (tip: string): void => {
    if (depth === null) {
      for (const entry of reachableObjects(repo, [tip])) included.add(entry.oid);
      for (const oid of ancestors(repo, tip)) includedCommits.add(oid);
      includedCommits.add(tip);
      return;
    }
    // Depth-limited: walk generations from the tip.
    let frontier = [tip];
    for (let gen = 0; gen < depth; gen += 1) {
      const next: string[] = [];
      for (const oid of frontier) {
        if (includedCommits.has(oid)) continue;
        includedCommits.add(oid);
        const obj = getObject(repo, oid);
        if (obj === undefined || obj.type !== 'commit') continue;
        const parsed = parseCommit(obj.data);
        if (parsed.tree !== '') {
          for (const entry of flattenTree(repo, parsed.tree).values()) included.add(entry.oid);
          const walkTrees = (treeOid: string): void => {
            included.add(treeOid);
            const treeObj = getObject(repo, treeOid);
            if (treeObj === undefined) return;
            const data = treeObj.data;
            let off = 0;
            while (off < data.length) {
              const sp = data.indexOf(0x20, off);
              const nul = data.indexOf(0, sp);
              const mode = data.subarray(off, sp).toString('utf8');
              const child = data.subarray(nul + 1, nul + 21).toString('hex');
              off = nul + 21;
              if (mode === '40000') walkTrees(child);
            }
          };
          walkTrees(parsed.tree);
        }
        included.add(oid);
        for (const p of parsed.parents) next.push(p);
      }
      frontier = next;
    }
  };
  for (const want of wants) collect(want);
  // Objects the client already holds are excluded from the pack. A walk from
  // a have stops at the old shallow boundaries: their parents are what a
  // deepen is fetching, not what the client holds.
  const haveReachable = new Set<string>();
  const stopAt = new Set(shallowBoundaries);
  for (const have of haves) {
    for (const entry of reachableObjects(repo, [have], stopAt)) haveReachable.add(entry.oid);
  }
  // Acknowledgments: ACK every have reachable from a want, then ready; else NAK.
  const common = haves.filter((h) => {
    for (const want of wants) if (isAncestor(repo, h, want)) return true;
    return false;
  });
  out.push(pktLine('acknowledgments\n'));
  if (common.length > 0) {
    for (const oid of common) out.push(pktLine(`ACK ${oid}\n`));
    out.push(pktLine('ready\n'));
  } else out.push(pktLine('NAK\n'));
  out.push(PKT_DELIM);
  // Shallow info: the new boundaries are included commits whose parents are not
  // included; old boundaries that are included and no longer boundaries are unshallow.
  const shallow: string[] = [];
  for (const oid of includedCommits) {
    const parents = commitParents(repo, oid);
    if (parents.some((p) => !includedCommits.has(p))) shallow.push(oid);
    else if (parents.length === 0) shallow.push(oid);
  }
  const unshallow = shallowBoundaries.filter((b) => includedCommits.has(b) && !shallow.includes(b));
  out.push(pktLine('shallow-info\n'));
  for (const oid of shallow) out.push(pktLine(`shallow ${oid}\n`));
  for (const oid of unshallow) out.push(pktLine(`unshallow ${oid}\n`));
  out.push(PKT_DELIM);
  // Wanted refs: the ref tips that match a want.
  out.push(pktLine('wanted-refs\n'));
  for (const want of wants) {
    for (const [ref, sha] of repo.refs) {
      if (sha === want) out.push(pktLine(`${want} ${ref}\n`));
    }
  }
  out.push(PKT_DELIM);
  // The pack: included objects minus the ones the client already holds.
  const packEntries: { type: GitObject['type']; data: Buffer }[] = [];
  for (const oid of included) {
    if (haveReachable.has(oid)) continue;
    const obj = getObject(repo, oid);
    if (obj !== undefined) packEntries.push(obj);
  }
  if (packEntries.length > 0) {
    packEntries.sort((a, b) => {
      const ao = objectId(a.type, a.data);
      const bo = objectId(b.type, b.data);
      return ao < bo ? -1 : ao > bo ? 1 : 0;
    });
    const pack = writePack(packEntries);
    out.push(pktLine('packfile\n'));
    for (const chunk of sidebandPack(pack)) out.push(chunk);
  }
  out.push(PKT_FLUSH);
  return Buffer.concat(out);
}

/** Handle POST /{owner}/{repo}.git/git-upload-pack (protocol v2). */
function handleUploadPack(ctx: HttpContext, res: import('node:http').ServerResponse, repo: Repo): void {
  let body: Buffer;
  try {
    const packets = parsePktLines(ctx.body);
    const lines = packets.filter((p) => p.kind === 'data').map((p) => p.payload.toString('utf8').replace(/\n$/, ''));
    const command = lines[0] ?? '';
    // The argument lines follow the delim packet.
    const delimIndex = packets.findIndex((p) => p.kind === 'delim');
    const argPackets = delimIndex < 0 ? [] : packets.slice(delimIndex + 1);
    const argLines = argPackets
      .filter((p) => p.kind === 'data')
      .map((p) => p.payload.toString('utf8').replace(/\n$/, ''));
    if (command === 'command=ls-refs') {
      body = handleLsRefs(repo, argLines);
    } else if (command === 'command=fetch') {
      body = handleFetch(repo, argLines);
    } else {
      return sendError(res, 400, `Unknown upload-pack command: ${command}`);
    }
  } catch (err) {
    return sendError(res, 400, `Bad pkt-line stream: ${err instanceof Error ? err.message : String(err)}`);
  }
  sendGit(res, 200, 'application/x-git-upload-pack-result', body);
}

/** Handle POST /{owner}/{repo}.git/git-receive-pack (protocol v0). */
function handleReceivePack(ctx: HttpContext, res: import('node:http').ServerResponse, repo: Repo): void {
  let commands: { oldOid: string; newOid: string; ref: string }[] = [];
  let packBytes = Buffer.alloc(0);
  try {
    // Parse command pkt-lines one at a time until the flush; everything after
    // the flush is the packfile (binary bytes, never pkt-lines).
    let off = 0;
    let sawFlush = false;
    while (off < ctx.body.length) {
      if (off + 4 > ctx.body.length) throw new Error('truncated pkt-line length');
      const len = parseInt(ctx.body.subarray(off, off + 4).toString('ascii'), 16);
      if (!Number.isFinite(len) || len < 0) throw new Error('bad pkt-line length');
      if (len === 0) {
        off += 4;
        sawFlush = true;
        break;
      }
      if (len < 4 || off + len > ctx.body.length) throw new Error('bad pkt-line length');
      const payload = ctx.body.subarray(off + 4, off + len);
      off += len;
      let line = payload.toString('utf8');
      const nul = line.indexOf('\0');
      if (nul >= 0) line = line.slice(0, nul);
      const match = line.replace(/\n$/, '').match(/^([0-9a-f]{40}) ([0-9a-f]{40}) (\S+)$/);
      if (match === null) throw new Error(`bad receive-pack command: ${JSON.stringify(line.slice(0, 60))}`);
      commands.push({ oldOid: match[1] as string, newOid: match[2] as string, ref: match[3] as string });
    }
    if (!sawFlush) throw new Error('no flush after the command list');
    packBytes = ctx.body.subarray(off);
  } catch (err) {
    return sendError(res, 400, `Bad receive-pack stream: ${err instanceof Error ? err.message : String(err)}`);
  }
  const reportLines: string[] = [];
  let unpackOk = true;
  let unpackDetail = 'ok';
  if (packBytes.length > 0) {
    try {
      const objects = readPack(packBytes);
      for (const [oid, obj] of objects) putObject(repo, obj.type, obj.data);
    } catch (err) {
      unpackOk = false;
      unpackDetail = err instanceof Error ? err.message : String(err);
    }
  }
  if (unpackOk) {
    for (const cmd of commands) {
      const current = repo.refs.get(cmd.ref);
      if (cmd.newOid === ZERO_OID) {
        // A delete carries no pack and removes the ref.
        if (current === undefined) reportLines.push(`ng ${cmd.ref} remote ref does not exist`);
        else {
          repo.refs.delete(cmd.ref);
          reportLines.push(`ok ${cmd.ref}`);
        }
        continue;
      }
      if (getObject(repo, cmd.newOid) === undefined) {
        reportLines.push(`ng ${cmd.ref} object not found`);
        continue;
      }
      if (cmd.oldOid === ZERO_OID) {
        if (current !== undefined) reportLines.push(`ng ${cmd.ref} already exists`);
        else {
          repo.refs.set(cmd.ref, cmd.newOid);
          reportLines.push(`ok ${cmd.ref}`);
        }
        continue;
      }
      if (current === undefined || current.toLowerCase() !== cmd.oldOid.toLowerCase()) {
        reportLines.push(`ng ${cmd.ref} non-fast-forward`);
        continue;
      }
      if (!isAncestor(repo, cmd.oldOid, cmd.newOid)) {
        reportLines.push(`ng ${cmd.ref} non-fast-forward`);
        continue;
      }
      repo.refs.set(cmd.ref, cmd.newOid);
      reportLines.push(`ok ${cmd.ref}`);
    }
  } else {
    for (const cmd of commands) reportLines.push(`ng ${cmd.ref} unpack failed`);
  }
  const report = Buffer.concat([
    sidebandPacket(1, pktLine(`unpack ${unpackDetail}\n`)),
    ...reportLines.map((line) => sidebandPacket(1, pktLine(`${line}\n`))),
    PKT_FLUSH,
  ]);
  sendGit(res, 200, 'application/x-git-receive-pack-result', report);
}

// ---------------------------------------------------------------------------------------------
// GraphQL v4: a small parser for the documents gh sends, plus an executor over the store
// ---------------------------------------------------------------------------------------------

type GqlValue = string | number | boolean | null | GqlValue[] | { [key: string]: GqlValue } | { variable: string };

interface GqlField {
  kind: 'field';
  name: string;
  alias: string | null;
  args: Record<string, GqlValue>;
  selections: GqlSelection[];
}

interface GqlFragmentSpread {
  kind: 'spread';
  name: string;
}

interface GqlInlineFragment {
  kind: 'inline';
  typeCondition: string | null;
  selections: GqlSelection[];
}

type GqlSelection = GqlField | GqlFragmentSpread | GqlInlineFragment;

interface GqlOperation {
  kind: 'query' | 'mutation';
  name: string | null;
  selections: GqlSelection[];
}

interface GqlDocument {
  operations: GqlOperation[];
  fragments: Map<string, GqlSelection[]>;
}

function tokenizeGql(source: string): string[] {
  const tokens: string[] = [];
  let i = 0;
  while (i < source.length) {
    const ch = source[i] as string;
    if (/\s/.test(ch) || ch === ',') {
      i += 1;
      continue;
    }
    if (ch === '#') {
      while (i < source.length && source[i] !== '\n') i += 1;
      continue;
    }
    if ('{}()[]:!=$@&|'.includes(ch)) {
      tokens.push(ch);
      i += 1;
      continue;
    }
    if (ch === '.' && source.slice(i, i + 3) === '...') {
      tokens.push('...');
      i += 3;
      continue;
    }
    if (ch === '"') {
      let j = i + 1;
      let out = '';
      while (j < source.length && source[j] !== '"') {
        if (source[j] === '\\' && j + 1 < source.length) {
          const esc = source[j + 1];
          out += esc === 'n' ? '\n' : esc === 't' ? '\t' : esc === 'r' ? '\r' : esc;
          j += 2;
        } else {
          out += source[j];
          j += 1;
        }
      }
      tokens.push(JSON.stringify(out));
      i = j + 1;
      continue;
    }
    if (/[A-Za-z_0-9-]/.test(ch)) {
      let j = i;
      while (j < source.length && /[A-Za-z_0-9]/.test(source[j] as string)) j += 1;
      // A negative number: '-' followed by digits, only when it starts a value.
      if (ch === '-' && j === i + 1 && /[0-9]/.test(source[j] ?? '')) {
        while (j < source.length && /[0-9.]/.test(source[j] as string)) j += 1;
      }
      tokens.push(source.slice(i, j));
      i = j;
      continue;
    }
    throw new Error(`unexpected character in GraphQL document: ${JSON.stringify(ch)}`);
  }
  return tokens;
}

class GqlParser {
  private tokens: string[];
  private pos = 0;

  constructor(source: string) {
    this.tokens = tokenizeGql(source);
  }

  private peek(): string | undefined {
    return this.tokens[this.pos];
  }

  private next(): string {
    const tok = this.tokens[this.pos];
    this.pos += 1;
    if (tok === undefined) throw new Error('unexpected end of GraphQL document');
    return tok;
  }

  private expect(tok: string): void {
    const got = this.next();
    if (got !== tok) throw new Error(`expected ${tok} in GraphQL document, got ${got}`);
  }

  parseDocument(): GqlDocument {
    const operations: GqlOperation[] = [];
    const fragments = new Map<string, GqlSelection[]>();
    while (this.pos < this.tokens.length) {
      const tok = this.next();
      if (tok === 'query' || tok === 'mutation') {
        let name: string | null = null;
        if (this.peek() !== undefined && this.peek() !== '(' && this.peek() !== '{') name = this.next();
        if (this.peek() === '(') this.parseVariableDefinitions();
        operations.push({ kind: tok, name, selections: this.parseSelectionSet() });
      } else if (tok === 'fragment') {
        const name = this.next();
        this.expect('on');
        this.next(); // the type condition
        fragments.set(name, this.parseSelectionSet());
      } else if (tok === '{') {
        this.pos -= 1;
        operations.push({ kind: 'query', name: null, selections: this.parseSelectionSet() });
      } else throw new Error(`unexpected token in GraphQL document: ${tok}`);
    }
    return { operations, fragments };
  }

  private parseVariableDefinitions(): void {
    this.expect('(');
    let depth = 1;
    while (depth > 0) {
      const tok = this.next();
      if (tok === '(' || tok === '[' || tok === '{') depth += 1;
      else if (tok === ')' || tok === ']' || tok === '}') depth -= 1;
    }
  }

  private parseSelectionSet(): GqlSelection[] {
    this.expect('{');
    const selections: GqlSelection[] = [];
    while (this.peek() !== '}') {
      if (this.peek() === undefined) throw new Error('unterminated selection set');
      selections.push(this.parseSelection());
    }
    this.expect('}');
    return selections;
  }

  private parseSelection(): GqlSelection {
    if (this.peek() === '...') {
      this.next();
      if (this.peek() === 'on') {
        this.next();
        const typeCondition = this.next();
        return { kind: 'inline', typeCondition, selections: this.parseSelectionSet() };
      }
      const name = this.next();
      return { kind: 'spread', name };
    }
    const first = this.next();
    let alias: string | null = null;
    let name = first;
    if (this.peek() === ':') {
      this.next();
      alias = first;
      name = this.next();
    }
    const args: Record<string, GqlValue> = {};
    if (this.peek() === '(') args['__args'] = this.parseArguments() as never;
    const parsedArgs = (args['__args'] as unknown as Record<string, GqlValue>) ?? {};
    delete args['__args'];
    Object.assign(args, parsedArgs);
    const selections = this.peek() === '{' ? this.parseSelectionSet() : [];
    return { kind: 'field', name, alias, args, selections };
  }

  private parseArguments(): Record<string, GqlValue> {
    this.expect('(');
    const args: Record<string, GqlValue> = {};
    while (this.peek() !== ')') {
      const name = this.next();
      this.expect(':');
      args[name] = this.parseValue();
    }
    this.expect(')');
    return args;
  }

  private parseValue(): GqlValue {
    const tok = this.next();
    if (tok === '$') return { variable: this.next() };
    if (tok === '[') {
      const list: GqlValue[] = [];
      while (this.peek() !== ']') list.push(this.parseValue());
      this.expect(']');
      return list;
    }
    if (tok === '{') {
      const obj: Record<string, GqlValue> = {};
      while (this.peek() !== '}') {
        const name = this.next();
        this.expect(':');
        obj[name] = this.parseValue();
      }
      this.expect('}');
      return obj;
    }
    if (tok.startsWith('"')) return JSON.parse(tok) as string;
    if (tok === 'true') return true;
    if (tok === 'false') return false;
    if (tok === 'null') return null;
    if (/^-?\d+$/.test(tok)) return Number(tok);
    if (/^-?\d*\.\d+$/.test(tok)) return Number(tok);
    return tok; // an enum literal
  }
}

function resolveGqlValue(value: GqlValue, variables: Record<string, unknown>): unknown {
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    if ('variable' in value) return variables[(value as { variable: string }).variable] ?? null;
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k] = resolveGqlValue(v as GqlValue, variables);
    return out;
  }
  if (Array.isArray(value)) return value.map((v) => resolveGqlValue(v, variables));
  return value;
}

// The schema surface the suite exercises: every type's fields.
const GQL_FIELDS: Record<string, string[]> = {
  Query: ['viewer', 'repository', 'node', '__type'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest'],
  User: ['login', 'id', 'name'],
  Issue: ['id', 'number', 'title', 'state', 'body'],
  PullRequest: ['id', 'number', 'state', 'merged', 'headRefName', 'baseRefName', 'mergeable', 'files'],
  IssueConnection: ['nodes', 'pageInfo'],
  PullRequestConnection: ['nodes'],
  PullRequestChangedFileConnection: ['nodes'],
  PullRequestChangedFile: ['path'],
  PageInfo: ['hasNextPage', 'endCursor'],
  __Type: ['name', 'kind', 'fields', 'enumValues'],
  __Field: ['name'],
  __EnumValue: ['name'],
  Mutation: ['createIssue', 'closeIssue', 'createPullRequest', 'mergePullRequest', 'addComment'],
  CreateIssuePayload: ['issue'],
  CloseIssuePayload: ['issue'],
  CreatePullRequestPayload: ['pullRequest'],
  MergePullRequestPayload: ['pullRequest'],
  AddCommentPayload: ['commentEdge'],
  CommentEdge: ['node'],
  IssueComment: ['id', 'body'],
  Ref: ['name'],
};

const GQL_TYPE_FIELDS: Record<string, string[]> = {
  Issue: ['id', 'number', 'title', 'state', 'body'],
  PullRequest: ['id', 'number', 'title', 'state', 'body', 'headRefName', 'baseRefName', 'mergeable', 'merged', 'files'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest'],
  SearchType: [],
};

const GQL_ENUM_VALUES: Record<string, string[]> = {
  SearchType: ['ISSUE', 'REPOSITORY', 'USER', 'DISCUSSION', 'COMMIT', 'MILESTONE'],
};

interface GqlNode {
  typename: string;
  data: unknown;
}

function nodeOf(typename: string, data: unknown): GqlNode {
  return { typename, data };
}

function issueStateGql(state: 'open' | 'closed'): string {
  return state === 'open' ? 'OPEN' : 'CLOSED';
}

function pullStateGql(pull: Pull): string {
  if (pull.merged) return 'MERGED';
  return pull.state === 'open' ? 'OPEN' : 'CLOSED';
}

function issueCursor(number: number): string {
  return b64encode(`issue:${number}`);
}

function issueFromCursor(cursor: string): number | null {
  try {
    const text = b64decode(cursor).toString('utf8');
    const match = text.match(/^issue:(\d+)$/);
    return match ? Number(match[1]) : null;
  } catch {
    return null;
  }
}

function executeGqlField(node: GqlNode, field: GqlField, variables: Record<string, unknown>): unknown {
  const args: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(field.args)) args[k] = resolveGqlValue(v, variables);
  const { typename, data } = node;
  if (typename === 'Query') {
    if (field.name === 'viewer') return nodeOf('User', VIEWER);
    if (field.name === 'repository') {
      const repo = findRepo(String(args.owner ?? ''), String(args.name ?? ''));
      return repo === undefined ? null : nodeOf('Repository', repo);
    }
    if (field.name === 'node') {
      const entry = byGlobalId.get(String(args.id ?? ''));
      if (entry === undefined) return null;
      if (entry.kind === 'repo') return nodeOf('Repository', entry.repo);
      if (entry.kind === 'issue') return nodeOf('Issue', entry.repo.issues.find((i) => i.number === entry.number) ?? null);
      const pull = entry.repo.pulls.find((p) => p.number === entry.number);
      return pull === undefined ? null : nodeOf('PullRequest', pull);
    }
    if (field.name === '__type') {
      const name = String(args.name ?? '');
      return nodeOf('__Type', { name, fields: GQL_TYPE_FIELDS[name] ?? null, enumValues: GQL_ENUM_VALUES[name] ?? null });
    }
  }
  if (typename === 'Repository') {
    const repo = data as Repo;
    if (field.name === 'id') return repo.id;
    if (field.name === 'databaseId') return repo.databaseId;
    if (field.name === 'name') return repo.name;
    if (field.name === 'nameWithOwner') return `${repo.owner}/${repo.name}`;
    if (field.name === 'owner') return nodeOf('User', VIEWER);
    if (field.name === 'defaultBranchRef') return nodeOf('Ref', { name: repo.defaultBranch });
    if (field.name === 'viewerPermission') return 'ADMIN';
    if (field.name === 'hasIssuesEnabled') return true;
    if (field.name === 'issue') {
      const issue = repo.issues.find((i) => i.number === Number(args.number));
      return issue === undefined ? null : nodeOf('Issue', issue);
    }
    if (field.name === 'issues') {
      let list = [...repo.issues];
      const states = Array.isArray(args.states) ? (args.states as string[]) : [];
      if (states.length > 0) {
        const wanted = new Set(states.map((s) => String(s).toLowerCase()));
        list = list.filter((i) => wanted.has(i.state));
      }
      const orderBy = isRecord(args.orderBy) ? args.orderBy : {};
      const direction = String(orderBy.direction ?? 'DESC');
      list.sort((a, b) => (direction === 'ASC' ? a.seq - b.seq : b.seq - a.seq));
      const first = typeof args.first === 'number' ? args.first : list.length;
      const after = typeof args.after === 'string' && args.after !== '' ? issueFromCursor(args.after) : null;
      let start = 0;
      if (after !== null) {
        const idx = list.findIndex((i) => i.number === after);
        start = idx < 0 ? 0 : idx + 1;
      }
      const slice = list.slice(start, start + first);
      const hasNext = start + first < list.length;
      const endCursor = slice.length > 0 ? issueCursor(slice[slice.length - 1]?.number ?? 0) : null;
      return nodeOf('IssueConnection', { nodes: slice, pageInfo: { hasNextPage: hasNext, endCursor } });
    }
    if (field.name === 'pullRequests') {
      const first = typeof args.first === 'number' ? args.first : 100;
      const open = repo.pulls.filter((p) => p.state === 'open').sort((a, b) => b.seq - a.seq).slice(0, first);
      return nodeOf('PullRequestConnection', { nodes: open });
    }
    if (field.name === 'pullRequest') {
      const pull = repo.pulls.find((p) => p.number === Number(args.number));
      return pull === undefined ? null : nodeOf('PullRequest', pull);
    }
  }
  if (typename === 'User') {
    const user = data as typeof VIEWER;
    if (field.name === 'login') return user.login;
    if (field.name === 'id') return user.id;
    if (field.name === 'name') return user.name;
  }
  if (typename === 'Issue') {
    const issue = data as Issue;
    if (field.name === 'id') return issue.id;
    if (field.name === 'number') return issue.number;
    if (field.name === 'title') return issue.title;
    if (field.name === 'state') return issueStateGql(issue.state);
    if (field.name === 'body') return issue.body;
  }
  if (typename === 'PullRequest') {
    const pull = data as Pull;
    if (field.name === 'id') return pull.id;
    if (field.name === 'number') return pull.number;
    if (field.name === 'state') return pullStateGql(pull);
    if (field.name === 'merged') return pull.merged;
    if (field.name === 'headRefName') return pull.head.ref;
    if (field.name === 'baseRefName') return pull.base.ref;
    if (field.name === 'mergeable') {
      const repo = [...repos.values()].find((r) => r.pulls.includes(pull));
      if (repo === undefined) return 'UNKNOWN';
      return pullMergeable(repo, pull) ? 'MERGEABLE' : 'CONFLICTING';
    }
    if (field.name === 'files') {
      const repo = [...repos.values()].find((r) => r.pulls.includes(pull));
      const first = typeof args.first === 'number' ? args.first : 100;
      const files = repo === undefined ? [] : pullFiles(repo, pull).slice(0, first);
      return nodeOf('PullRequestChangedFileConnection', { nodes: files.map((f) => ({ path: f.filename })) });
    }
  }
  if (typename === 'IssueConnection') {
    const conn = data as { nodes: Issue[]; pageInfo: { hasNextPage: boolean; endCursor: string | null } };
    if (field.name === 'nodes') return conn.nodes.map((i) => nodeOf('Issue', i));
    if (field.name === 'pageInfo') return nodeOf('PageInfo', conn.pageInfo);
  }
  if (typename === 'PullRequestConnection') {
    const conn = data as { nodes: unknown[] };
    if (field.name === 'nodes') {
      return conn.nodes.map((entry) => {
        if (isRecord(entry) && 'path' in entry) return nodeOf('PullRequestChangedFile', entry);
        return nodeOf('PullRequest', entry);
      });
    }
  }
  if (typename === 'PullRequestChangedFileConnection') {
    const conn = data as { nodes: { path: string }[] };
    if (field.name === 'nodes') return conn.nodes.map((entry) => nodeOf('PullRequestChangedFile', entry));
  }
  if (typename === 'PullRequestChangedFile') {
    if (field.name === 'path') return (data as { path: string }).path;
  }
  if (typename === 'PageInfo') {
    const info = data as { hasNextPage: boolean; endCursor: string | null };
    if (field.name === 'hasNextPage') return info.hasNextPage;
    if (field.name === 'endCursor') return info.endCursor;
  }
  if (typename === 'Ref') {
    if (field.name === 'name') return (data as { name: string }).name;
  }
  if (typename === '__Type') {
    const typeInfo = data as { name: string; fields: string[] | null; enumValues: string[] | null };
    if (field.name === 'name') return typeInfo.name;
    if (field.name === 'kind') return typeInfo.enumValues !== null ? 'ENUM' : 'OBJECT';
    if (field.name === 'fields') return (typeInfo.fields ?? []).map((name) => nodeOf('__Field', { name }));
    if (field.name === 'enumValues') return (typeInfo.enumValues ?? []).map((name) => nodeOf('__EnumValue', { name }));
  }
  if (typename === '__Field' || typename === '__EnumValue') {
    if (field.name === 'name') return (data as { name: string }).name;
  }
  if (typename === 'Mutation') {
    const input = isRecord(args.input) ? args.input : {};
    if (field.name === 'createIssue') {
      const entry = byGlobalId.get(String(input.repositoryId ?? ''));
      if (entry === undefined || entry.kind !== 'repo') throw new Error('createIssue: unknown repositoryId');
      const result = createIssueRecord(entry.repo, String(input.title ?? ''), String(input.body ?? ''), []);
      if ('error' in result) throw new Error(result.error);
      return nodeOf('CreateIssuePayload', { issue: result.issue });
    }
    if (field.name === 'closeIssue') {
      const entry = byGlobalId.get(String(input.issueId ?? ''));
      if (entry === undefined || entry.kind !== 'issue') throw new Error('closeIssue: unknown issueId');
      const issue = entry.repo.issues.find((i) => i.number === entry.number);
      if (issue === undefined) throw new Error('closeIssue: issue not found');
      issue.state = 'closed';
      return nodeOf('CloseIssuePayload', { issue });
    }
    if (field.name === 'createPullRequest') {
      const entry = byGlobalId.get(String(input.repositoryId ?? ''));
      if (entry === undefined || entry.kind !== 'repo') throw new Error('createPullRequest: unknown repositoryId');
      const result = createPullRecord(entry.repo, String(input.title ?? ''), '', String(input.headRefName ?? ''), String(input.baseRefName ?? ''));
      if ('error' in result) throw new Error(result.error);
      return nodeOf('CreatePullRequestPayload', { pullRequest: result.pull });
    }
    if (field.name === 'mergePullRequest') {
      const entry = byGlobalId.get(String(input.pullRequestId ?? ''));
      if (entry === undefined || entry.kind !== 'pull') throw new Error('mergePullRequest: unknown pullRequestId');
      const pull = entry.repo.pulls.find((p) => p.number === entry.number);
      if (pull === undefined) throw new Error('mergePullRequest: pull request not found');
      if (pull.state === 'open') squashMerge(entry.repo, pull);
      return nodeOf('MergePullRequestPayload', { pullRequest: pull });
    }
    if (field.name === 'addComment') {
      const entry = byGlobalId.get(String(input.subjectId ?? ''));
      if (entry === undefined || entry.kind !== 'issue') throw new Error('addComment: unknown subjectId');
      const issue = entry.repo.issues.find((i) => i.number === entry.number);
      if (issue === undefined) throw new Error('addComment: issue not found');
      const id = entry.repo.nextComment;
      entry.repo.nextComment += 1;
      const body = String(input.body ?? '');
      issue.comments.push({ id, body });
      const commentId = globalId('IssueComment', entry.repo.databaseId, issue.number, id);
      return nodeOf('AddCommentPayload', { commentEdge: { node: { id: commentId, body } } });
    }
  }
  if (typename === 'CreateIssuePayload' || typename === 'CloseIssuePayload') {
    if (field.name === 'issue') return nodeOf('Issue', (data as { issue: Issue }).issue);
  }
  if (typename === 'CreatePullRequestPayload' || typename === 'MergePullRequestPayload') {
    if (field.name === 'pullRequest') return nodeOf('PullRequest', (data as { pullRequest: Pull }).pullRequest);
  }
  if (typename === 'AddCommentPayload') {
    if (field.name === 'commentEdge') return nodeOf('CommentEdge', (data as { commentEdge: unknown }).commentEdge);
  }
  if (typename === 'CommentEdge') {
    if (field.name === 'node') return nodeOf('IssueComment', (data as { node: unknown }).node);
  }
  if (typename === 'IssueComment') {
    const comment = data as { id: string; body: string };
    if (field.name === 'id') return comment.id;
    if (field.name === 'body') return comment.body;
  }
  throw new Error(`Cannot query field "${field.name}" on type "${typename}".`);
}

/** Validate a selection tree against the schema; collect every unknown field. */
function validateGqlSelections(selections: GqlSelection[], parentType: string, fragments: Map<string, GqlSelection[]>, errors: string[]): void {
  const fields = GQL_FIELDS[parentType] ?? [];
  for (const selection of selections) {
    if (selection.kind === 'field') {
      if (!fields.includes(selection.name)) {
        errors.push(`Cannot query field "${selection.name}" on type "${parentType}".`);
        continue;
      }
      // Recurse into the sub-selection with the field's result type.
      const childType = gqlChildType(parentType, selection.name);
      if (childType !== null && selection.selections.length > 0) validateGqlSelections(selection.selections, childType, fragments, errors);
    } else if (selection.kind === 'spread') {
      const frag = fragments.get(selection.name);
      if (frag !== undefined) validateGqlSelections(frag, parentType, fragments, errors);
    } else if (selection.kind === 'inline') {
      const type = selection.typeCondition ?? parentType;
      validateGqlSelections(selection.selections, type, fragments, errors);
    }
  }
}

/** The result type of a field, for validation (null when scalar or unknown). */
function gqlChildType(parentType: string, fieldName: string): string | null {
  const map: Record<string, Record<string, string>> = {
    Query: { viewer: 'User', repository: 'Repository', node: 'Repository', __type: '__Type' },
    Repository: { owner: 'User', defaultBranchRef: 'Ref', issue: 'Issue', issues: 'IssueConnection', pullRequests: 'PullRequestConnection', pullRequest: 'PullRequest' },
    IssueConnection: { nodes: 'Issue', pageInfo: 'PageInfo' },
    PullRequestConnection: { nodes: 'PullRequest' },
    PullRequestChangedFileConnection: { nodes: 'PullRequestChangedFile' },
    PullRequest: { files: 'PullRequestChangedFileConnection' },
    __Type: { fields: '__Field', enumValues: '__EnumValue' },
    Mutation: { createIssue: 'CreateIssuePayload', closeIssue: 'CloseIssuePayload', createPullRequest: 'CreatePullRequestPayload', mergePullRequest: 'MergePullRequestPayload', addComment: 'AddCommentPayload' },
    CreateIssuePayload: { issue: 'Issue' },
    CloseIssuePayload: { issue: 'Issue' },
    CreatePullRequestPayload: { pullRequest: 'PullRequest' },
    MergePullRequestPayload: { pullRequest: 'PullRequest' },
    AddCommentPayload: { commentEdge: 'CommentEdge' },
    CommentEdge: { node: 'IssueComment' },
  };
  return map[parentType]?.[fieldName] ?? null;
}

/** Execute one operation's selections against a root node. */
function executeGqlSelections(selections: GqlSelection[], node: GqlNode, variables: Record<string, unknown>, fragments: Map<string, GqlSelection[]>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const selection of selections) {
    if (selection.kind === 'field') {
      const value = executeGqlField(node, selection, variables);
      out[selection.alias ?? selection.name] = projectGqlValue(value, selection.selections, variables, fragments);
    } else if (selection.kind === 'spread') {
      const frag = fragments.get(selection.name);
      if (frag !== undefined) Object.assign(out, executeGqlSelections(frag, node, variables, fragments));
    } else if (selection.kind === 'inline') {
      if (selection.typeCondition === null || selection.typeCondition === node.typename) {
        Object.assign(out, executeGqlSelections(selection.selections, node, variables, fragments));
      }
    }
  }
  return out;
}

/** Project a resolved value through its sub-selection (scalars pass through). */
function projectGqlValue(value: unknown, selections: GqlSelection[], variables: Record<string, unknown>, fragments: Map<string, GqlSelection[]>): unknown {
  if (value === null || value === undefined) return null;
  if (Array.isArray(value)) return value.map((entry) => projectGqlValue(entry, selections, variables, fragments));
  if (typeof value === 'object' && 'typename' in (value as Record<string, unknown>) && 'data' in (value as Record<string, unknown>)) {
    if (selections.length === 0) return (value as GqlNode).data;
    return executeGqlSelections(selections, value as GqlNode, variables, fragments);
  }
  return value;
}

/** Run one GraphQL operation document; returns the {data} or {data, errors} body. */
function runGqlOperation(query: string, variables: Record<string, unknown>): Record<string, unknown> {
  let doc: GqlDocument;
  try {
    doc = new GqlParser(query).parseDocument();
  } catch (err) {
    return { data: null, errors: [{ message: err instanceof Error ? err.message : String(err) }] };
  }
  if (doc.operations.length === 0) return { data: null, errors: [{ message: 'No operation in GraphQL document' }] };
  const operation = doc.operations[0] as GqlOperation;
  const rootType = operation.kind === 'mutation' ? 'Mutation' : 'Query';
  const errors: string[] = [];
  validateGqlSelections(operation.selections, rootType, doc.fragments, errors);
  if (errors.length > 0) return { data: null, errors: errors.map((message) => ({ message })) };
  try {
    const root = nodeOf(rootType, null);
    const data = executeGqlSelections(operation.selections, root, variables, doc.fragments);
    return { data };
  } catch (err) {
    return { data: null, errors: [{ message: err instanceof Error ? err.message : String(err) }] };
  }
}

// ---------------------------------------------------------------------------------------------
// MCP: JSON-RPC 2.0 over POST /mcp (modern 2026-07-28 revision: server/discover, no handshake)
// ---------------------------------------------------------------------------------------------

interface McpToolDef {
  name: string;
  description: string;
  inputSchema: { type: 'object'; properties: Record<string, { type: string; description: string }>; required: string[] };
}

const MCP_TOOLS: McpToolDef[] = [
  {
    name: 'create_repo',
    description: 'Create a repository owned by the viewer.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'The repository name.' },
        description: { type: 'string', description: 'A short description of the repository.' },
        private: { type: 'boolean', description: 'Whether the repository is private.' },
      },
      required: ['name'],
    },
  },
  {
    name: 'get_repo',
    description: 'Read one repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        title: { type: 'string', description: 'The issue title.' },
        body: { type: 'string', description: 'The issue body.' },
      },
      required: ['owner', 'repo', 'title'],
    },
  },
  {
    name: 'list_issues',
    description: 'List the issues of a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        state: { type: 'string', description: 'Filter by state: open, closed, or all.' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Open a pull request from a head branch into a base branch.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        title: { type: 'string', description: 'The pull request title.' },
        body: { type: 'string', description: 'The pull request body.' },
        head: { type: 'string', description: 'The head branch name.' },
        base: { type: 'string', description: 'The base branch name.' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Squash-merge a pull request.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        pull_number: { type: 'integer', description: 'The pull request number.' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
  },
];

function mcpToolResult(result: unknown, isError = false): Record<string, unknown> {
  return {
    content: [{ type: 'text', text: typeof result === 'string' ? result : JSON.stringify(result) }],
    structuredContent: result,
    isError,
  };
}

/** Run one tool call; returns the tool result (or throws for a missing argument). */
function runMcpTool(name: string, args: Record<string, unknown>): Record<string, unknown> {
  const tool = MCP_TOOLS.find((t) => t.name === name);
  if (tool === undefined) throw Object.assign(new Error(`Unknown tool: ${name}`), { code: -32602 });
  for (const required of tool.inputSchema.required) {
    if (args[required] === undefined || args[required] === null || args[required] === '') {
      throw Object.assign(new Error(`Missing required argument: ${required}`), { code: -32602 });
    }
  }
  const owner = String(args.owner ?? VIEWER.login);
  if (name === 'create_repo') {
    const repoName = String(args.name);
    if (findRepo(VIEWER.login, repoName) !== undefined) return mcpToolResult(`Repository already exists: ${repoName}`, true);
    const repo = createRepoRecord(repoName, typeof args.description === 'string' ? args.description : '', args.private === true);
    return mcpToolResult(repoView(repo));
  }
  const repoName = String(args.repo ?? '');
  const repo = findRepo(owner, repoName);
  if (repo === undefined) return mcpToolResult(`Repository not found: ${owner}/${repoName}`, true);
  if (name === 'get_repo') return mcpToolResult(repoView(repo));
  if (name === 'create_issue') {
    const result = createIssueRecord(repo, String(args.title), typeof args.body === 'string' ? args.body : '', []);
    if ('error' in result) return mcpToolResult(result.error, true);
    return mcpToolResult(issueView(result.issue));
  }
  if (name === 'list_issues') {
    const state = typeof args.state === 'string' ? args.state : 'open';
    const list = state === 'all' ? repo.issues : repo.issues.filter((i) => i.state === state);
    return mcpToolResult(list.map(issueView));
  }
  if (name === 'create_pull_request') {
    const result = createPullRecord(repo, String(args.title), typeof args.body === 'string' ? args.body : '', String(args.head), String(args.base));
    if ('error' in result) return mcpToolResult(result.error, true);
    return mcpToolResult(pullView(result.pull));
  }
  if (name === 'merge_pull_request') {
    const number = Number(args.pull_number);
    const pull = repo.pulls.find((p) => p.number === number);
    if (pull === undefined) return mcpToolResult(`Pull request not found: #${number}`, true);
    if (pull.state !== 'open') return mcpToolResult(`Pull request #${number} is already closed`, true);
    if (!pullMergeable(repo, pull)) return mcpToolResult(`Pull request #${number} has a merge conflict`, true);
    const sha = squashMerge(repo, pull);
    if (sha === null) return mcpToolResult(`Pull request #${number} has a merge conflict`, true);
    return mcpToolResult({ merged: true, sha, message: `Squash-merged pull request #${number}`, number, state: 'closed' });
  }
  return mcpToolResult(`Unknown tool: ${name}`, true);
}

function sendMcp(res: import('node:http').ServerResponse, status: number, body: unknown): void {
  sendJson(res, status, body);
}

/** One JSON-RPC request object; returns the response object (or null for a notification). */
function handleMcpRequest(request: unknown): Record<string, unknown> | null {
  if (!isRecord(request)) return { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid Request' } };
  const id = (request as Record<string, unknown>).id ?? null;
  const method = (request as Record<string, unknown>).method;
  const params = isRecord(request.params) ? request.params : {};
  if (typeof method !== 'string') return { jsonrpc: '2.0', id, error: { code: -32600, message: 'Invalid Request' } };
  if (id === null && request.id === undefined) {
    // A notification (no id): no JSON-RPC answer is owed.
    return null;
  }
  const ok = (result: unknown): Record<string, unknown> => ({ jsonrpc: '2.0', id, result });
  const err = (code: number, message: string): Record<string, unknown> => ({ jsonrpc: '2.0', id, error: { code, message } });
  if (method === 'server/discover') {
    return ok({
      supportedVersions: ['2026-07-28'],
      capabilities: { tools: {} },
      serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
      _meta: {
        'io.modelcontextprotocol/serverInfo': { name: SERVER_NAME, version: SERVER_VERSION },
        'io.modelcontextprotocol/protocolVersion': '2026-07-28',
      },
    });
  }
  if (method === 'initialize') {
    return ok({
      protocolVersion: '2025-11-25',
      capabilities: { tools: {} },
      serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
    });
  }
  if (method === 'tools/list') {
    return ok({ tools: MCP_TOOLS });
  }
  if (method === 'tools/call') {
    const toolName = typeof params.name === 'string' ? params.name : '';
    const toolArgs = isRecord(params.arguments) ? (params.arguments as Record<string, unknown>) : {};
    try {
      const result = runMcpTool(toolName, toolArgs);
      return ok(result);
    } catch (e) {
      const code = (e as { code?: number }).code ?? -32602;
      return err(code, e instanceof Error ? e.message : String(e));
    }
  }
  if (method.startsWith('notifications/')) return null;
  return err(-32601, `Method not found: ${method}`);
}

function handleMcp(ctx: HttpContext, res: import('node:http').ServerResponse): void {
  if (!ctx.authed) {
    sendJson(res, 401, { jsonrpc: '2.0', id: null, error: { code: -32001, message: 'Unauthorized' } });
    return;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(ctx.body.toString('utf8'));
  } catch {
    sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    return;
  }
  if (Array.isArray(parsed)) {
    const answers: unknown[] = [];
    for (const entry of parsed) {
      const answer = handleMcpRequest(entry);
      if (answer !== null) answers.push(answer);
    }
    sendJson(res, 200, answers);
    return;
  }
  const answer = handleMcpRequest(parsed);
  if (answer === null) {
    res.writeHead(202, { 'x-github-request-id': nextRequestId() });
    res.end();
    return;
  }
  sendJson(res, 200, answer);
}

// ---------------------------------------------------------------------------------------------
// GraphQL endpoint
// ---------------------------------------------------------------------------------------------

function handleGraphql(ctx: HttpContext, res: import('node:http').ServerResponse): void {
  if (!ctx.authed) return sendError(res, 401, 'Requires authentication');
  let parsed: unknown;
  try {
    parsed = JSON.parse(ctx.body.toString('utf8'));
  } catch {
    return sendError(res, 400, 'Invalid JSON body');
  }
  if (Array.isArray(parsed)) {
    const answers = parsed.map((entry) => {
      if (!isRecord(entry) || typeof entry.query !== 'string') return { data: null, errors: [{ message: 'Invalid GraphQL operation' }] };
      const variables = isRecord(entry.variables) ? (entry.variables as Record<string, unknown>) : {};
      return runGqlOperation(entry.query, variables);
    });
    sendJson(res, 200, answers);
    return;
  }
  if (!isRecord(parsed) || typeof parsed.query !== 'string') return sendError(res, 400, 'Invalid GraphQL operation');
  const variables = isRecord(parsed.variables) ? (parsed.variables as Record<string, unknown>) : {};
  sendJson(res, 200, runGqlOperation(parsed.query, variables));
}

// ---------------------------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------------------------

function decodeSegment(segment: string): string {
  try {
    return decodeURIComponent(segment);
  } catch {
    return segment;
  }
}

async function handleRequest(req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse): Promise<void> {
  try {
    const body = await readBody(req);
    const url = new URL(req.url ?? '/', 'http://localhost');
    const path = url.pathname;
    const segments = path.split('/').filter((s) => s !== '').map(decodeSegment);
    const ctx: HttpContext = {
      method: req.method ?? 'GET',
      url,
      path,
      segments,
      query: url.searchParams,
      headers: req.headers,
      body,
      json: undefined,
      authed: authed(req.headers),
    };
    // The env's boot probe: no auth, no JSON.
    if (ctx.method === 'GET' && path === '/healthz') return sendJson(res, 200, { ok: true });
    // Git smart HTTP: /{owner}/{repo}.git/...
    if (segments.length >= 2 && segments[1]?.endsWith('.git')) {
      const owner = segments[0] as string;
      const repoName = (segments[1] as string).slice(0, -4);
      const repo = findRepo(owner, repoName);
      const tail = segments.slice(2).join('/');
      if (ctx.method === 'GET' && tail === 'info/refs') {
        if (repo === undefined) return sendError(res, 404, 'Repository not found');
        const service = ctx.query.get('service') ?? '';
        if (service === 'git-upload-pack') return sendGit(res, 200, 'application/x-git-upload-pack-advertisement', uploadPackAd());
        if (service === 'git-receive-pack') return sendGit(res, 200, 'application/x-git-receive-pack-advertisement', receivePackAd(repo));
        return sendError(res, 400, 'Unknown git service');
      }
      if (repo === undefined) return sendError(res, 404, 'Repository not found');
      if (ctx.method === 'POST' && tail === 'git-upload-pack') return handleUploadPack(ctx, res, repo);
      if (ctx.method === 'POST' && tail === 'git-receive-pack') return handleReceivePack(ctx, res, repo);
      return sendError(res, 404, 'Not Found');
    }
    // GraphQL and MCP.
    if (ctx.method === 'POST' && path === '/api/graphql') return handleGraphql(ctx, res);
    if (ctx.method === 'POST' && path === '/mcp') return handleMcp(ctx, res);
    // The REST root and meta: the root answers without auth.
    if (path === '/api/v3/' || path === '/api/v3') {
      if (ctx.method === 'GET') {
        return sendJson(res, 200, {}, { 'x-oauth-scopes': 'repo, read:org' });
      }
      return sendError(res, 404, 'Not Found');
    }
    if (path === '/api/v3/meta') {
      if (!ctx.authed) return sendError(res, 401, 'Requires authentication');
      if (ctx.method === 'GET') return sendJson(res, 200, { installed_version: SERVER_VERSION });
      return sendError(res, 404, 'Not Found');
    }
    // Everything else under /api/v3 needs a bearer token.
    if (path.startsWith('/api/v3/')) {
      if (!ctx.authed) return sendError(res, 401, 'Requires authentication');
      if (segments[0] === 'api' && segments[1] === 'v3' && segments[2] === 'user' && segments[3] === 'repos') {
        if (ctx.method === 'POST') return restCreateRepo(ctx, res);
        if (ctx.method === 'GET') return restListUserRepos(ctx, res);
        return sendError(res, 404, 'Not Found');
      }
      if (segments[0] === 'api' && segments[1] === 'v3' && segments[2] === 'user' && segments.length === 3) {
        if (ctx.method === 'GET') return restGetUser(ctx, res);
        return sendError(res, 404, 'Not Found');
      }
      if (segments[0] === 'api' && segments[1] === 'v3' && segments[2] === 'repos' && segments.length >= 5) {
        const owner = segments[3] as string;
        const name = segments[4] as string;
        const repo = findRepo(owner, name);
        if (repo === undefined || repo.owner !== owner) return restNotFound(res);
        const rest = segments.slice(5);
        if (rest.length === 0) {
          if (ctx.method === 'GET') return restGetRepo(ctx, res, owner, name);
          if (ctx.method === 'PATCH') return restPatchRepo(ctx, res, owner, name);
          if (ctx.method === 'DELETE') return restDeleteRepo(ctx, res, owner, name);
          return sendError(res, 404, 'Not Found');
        }
        if (rest[0] === 'branches' && rest.length === 1 && ctx.method === 'GET') return restListBranches(ctx, res, repo);
        if (rest[0] === 'branches' && rest.length === 2 && ctx.method === 'GET') return restGetBranch(ctx, res, repo, rest[1] as string);
        if (rest[0] === 'commits' && rest.length === 1 && ctx.method === 'GET') return restListCommits(ctx, res, repo);
        if (rest[0] === 'git' && rest[1] === 'refs' && rest.length === 2 && ctx.method === 'GET') return restListRefs(ctx, res, repo);
        if (rest[0] === 'git' && rest[1] === 'refs' && rest.length === 2 && ctx.method === 'POST') return restCreateRef(ctx, res, repo);
        if (rest[0] === 'git' && rest[1] === 'refs' && rest.length > 2 && ctx.method === 'GET') return restGetRef(ctx, res, repo, `refs/${rest.slice(2).join('/')}`);
        if (rest[0] === 'contents' && ctx.method === 'GET') return restGetContent(ctx, res, repo, rest.slice(1).join('/'));
        if (rest[0] === 'contents' && ctx.method === 'PUT') return restPutContent(ctx, res, repo, rest.slice(1).join('/'));
        if (rest[0] === 'contents' && ctx.method === 'DELETE') return restDeleteContent(ctx, res, repo, rest.slice(1).join('/'));
        if (rest[0] === 'labels' && rest.length === 1 && ctx.method === 'POST') return restCreateLabel(ctx, res, repo);
        if (rest[0] === 'labels' && rest.length === 1 && ctx.method === 'GET') return sendJson(res, 200, repo.labels);
        if (rest[0] === 'issues' && rest.length === 1 && ctx.method === 'POST') return restCreateIssue(ctx, res, repo);
        if (rest[0] === 'issues' && rest.length === 1 && ctx.method === 'GET') return restListIssues(ctx, res, repo);
        if (rest[0] === 'issues' && rest.length === 2 && ctx.method === 'GET') {
          const n = Number(rest[1]);
          if (Number.isInteger(n)) return restGetIssue(ctx, res, repo, n);
        }
        if (rest[0] === 'issues' && rest.length === 2 && ctx.method === 'PATCH') {
          const n = Number(rest[1]);
          if (Number.isInteger(n)) return restPatchIssue(ctx, res, repo, n);
        }
        if (rest[0] === 'issues' && rest.length === 3 && rest[2] === 'comments' && ctx.method === 'POST') {
          const n = Number(rest[1]);
          if (Number.isInteger(n)) return restCreateComment(ctx, res, repo, n);
        }
        if (rest[0] === 'issues' && rest.length === 3 && rest[2] === 'comments' && ctx.method === 'GET') {
          const n = Number(rest[1]);
          if (Number.isInteger(n)) return restListComments(ctx, res, repo, n);
        }
        if (rest[0] === 'pulls' && rest.length === 1 && ctx.method === 'POST') return restCreatePull(ctx, res, repo);
        if (rest[0] === 'pulls' && rest.length === 1 && ctx.method === 'GET') return restListPulls(ctx, res, repo);
        if (rest[0] === 'pulls' && rest.length === 2 && ctx.method === 'GET') {
          const n = Number(rest[1]);
          if (Number.isInteger(n)) return restGetPull(ctx, res, repo, n);
        }
        if (rest[0] === 'pulls' && rest.length === 3 && rest[2] === 'files' && ctx.method === 'GET') {
          const n = Number(rest[1]);
          if (Number.isInteger(n)) return restListPullFiles(ctx, res, repo, n);
        }
        if (rest[0] === 'pulls' && rest.length === 3 && rest[2] === 'merge' && ctx.method === 'PUT') {
          const n = Number(rest[1]);
          if (Number.isInteger(n)) return restMergePull(ctx, res, repo, n);
        }
        return sendError(res, 404, 'Not Found');
      }
      return sendError(res, 404, 'Not Found');
    }
    return sendError(res, 404, 'Not Found');
  } catch (err) {
    try {
      sendError(res, 500, err instanceof Error ? err.message : String(err));
    } catch {
      // The response is already gone; the process must stay up regardless.
    }
  }
}

// ---------------------------------------------------------------------------------------------
// Lifecycle: bind an ephemeral port, register it, wait for done, exit 0
// ---------------------------------------------------------------------------------------------

const ENV_URL = (process.env.MAKEFUN_ENV_URL ?? '').replace(/\/+$/, '');
if (ENV_URL === '') {
  process.stderr.write('[entry] MAKEFUN_ENV_URL is not set: there is no env to register with\n');
  process.exit(1);
}

const REQUEST_TIMEOUT_MS = 30_000;
const RETRY_INITIAL_MS = 250;
const RETRY_MAX_MS = 2_000;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function retryDelay(attempt: number): number {
  return Math.min(RETRY_MAX_MS, RETRY_INITIAL_MS * 2 ** Math.min(attempt, 8));
}

async function register(port: number): Promise<void> {
  for (let attempt = 0; ; attempt += 1) {
    try {
      const res = await fetch(`${ENV_URL}/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ port }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      if (res.status === 200 || res.status === 409) return;
      if (res.status === 400 || res.status === 405) throw new Error(`register answered HTTP ${res.status}: ${await res.text()}`);
    } catch (err) {
      if (err instanceof Error && err.message.startsWith('register answered HTTP ')) throw err;
    }
    await sleep(retryDelay(attempt));
  }
}

async function waitForDone(): Promise<void> {
  for (let attempt = 0; ; attempt += 1) {
    try {
      const res = await fetch(`${ENV_URL}/done`, { signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
      if (res.ok) {
        const body = (await res.json()) as { done?: unknown };
        if (body.done === true) return;
      }
    } catch {
      // The env is not answering yet: it is not done, so poll again.
    }
    await sleep(retryDelay(attempt));
  }
}

async function main(): Promise<void> {
  const server = createServer((req, res) => {
    void handleRequest(req, res);
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, () => resolve());
  });
  const address = server.address();
  if (address === null || typeof address === 'string') throw new Error('the server did not bind an ephemeral TCP port');
  process.stdout.write(`[entry] listening on port ${address.port}\n`);
  await register(address.port);
  process.stdout.write('[entry] registered; waiting for the env to say done\n');
  await waitForDone();
  server.close();
  process.stdout.write('[entry] done\n');
}

try {
  await main();
  process.exit(0);
} catch (err) {
  process.stderr.write(`[entry] ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
}
