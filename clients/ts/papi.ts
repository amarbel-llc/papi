// papi — a TypeScript client for the Personal API (PAPI) wire format (RFC-0001),
// the JS/zx layer of FDR-0007. It owns the HTTP (Node/zx `fetch`) and delegates
// all RFC-0001 parsing and the §5/§10 crypto to the network-free Go core compiled
// to WASM (cmd/papi-client-wasm / build/papi-client.wasm), so JS consumers never
// re-derive the wire format.
//
// Two layers (FDR-0007):
//   - bare core — decodeDocument/decodeRepos/decodeProfiles/decodeCaches/
//     decodeDiscovery/verifyDocument: pure, take bytes the caller already has.
//   - Client — does the fetch, then calls the core.
//
// The core is a Go js/wasm module driven via Go's canonical wasm_exec.js loader:
// it registers a synchronous `papiCall(reqJSON) -> resJSON` global, which this
// module instantiates once (lazily) and calls per request. js/wasm rather than
// wasip1 because Bun's node:wasi cannot instantiate a Go wasip1 module — it OOBs
// at start() on every Bun through 1.4.0-canary.1 (see FDR-0007). A wasip1 module
// also has no sockets, which is the other reason fetch stays here in JS.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

// --- wire types (mirror internal/0/papi + internal/alfa/inspect) ---

export interface Profile {
  id: string;
  flakeref: string;
  home_flakeref?: string;
  description?: string;
  platform?: string;
  kind?: string;
}

export interface Repo {
  name: string;
  url: string;
  owner: string;
  forge: string;
  kind: string;
  visibility: string;
  default_branch: string;
  description: string;
}

export interface Cache {
  id: string;
  url: string;
  trusted_public_keys: string[];
  priority: number;
  kind: string;
}

export interface Discovery {
  version: string;
  handle: string;
  resources: Record<string, string>;
  auth?: { scheme: string; challenge: string; response: string; present_session_as: string };
}

// PapiDocument is intentionally loose — only the members JS consumers commonly
// read are typed; unknown members pass through (the Go core is the schema).
export interface PapiDocument {
  version: string;
  person?: Record<string, unknown>;
  piggy?: Record<string, unknown>;
  profiles?: Profile[];
  caches?: Cache[];
  [k: string]: unknown;
}

export interface SigCheck {
  name: string;
  ok: boolean;
  skipped: boolean;
  detail: string;
}

export interface SigVerifyResult {
  authentic: boolean;
  checks: SigCheck[];
}

// --- the wasm core driver ---

export interface CallOptions {
  /** Override the wasm path (default: $PAPI_CLIENT_WASM or ./papi-client.wasm). */
  wasmPath?: string;
  /** Override Go's wasm_exec.js (default: $PAPI_CLIENT_WASM_EXEC or sibling of the wasm). */
  wasmExecPath?: string;
  /** Published slot-9A markl-ids (the §10.1 trust anchor) — for verify_document. */
  publishedIds?: string[];
}

function resolveWasm(override?: string): string {
  if (override) return override;
  if (process.env.PAPI_CLIENT_WASM) return process.env.PAPI_CLIENT_WASM;
  return fileURLToPath(new URL("./papi-client.wasm", import.meta.url));
}

function resolveWasmExec(wasmPath: string, override?: string): string {
  if (override) return override;
  if (process.env.PAPI_CLIENT_WASM_EXEC) return process.env.PAPI_CLIENT_WASM_EXEC;
  return join(dirname(wasmPath), "wasm_exec.js");
}

// papiCall is the synchronous string->string entrypoint the Go js/wasm module
// registers on the global object (export_js.go).
type PapiCall = (reqJSON: string) => string;

// The instance is loaded once and kept alive (the Go main parks on select{}), so
// papiCall stays callable across every request.
let loaded: PapiCall | undefined;

function ensureLoaded(opts: CallOptions): PapiCall {
  if (loaded) return loaded;

  const wasmPath = resolveWasm(opts.wasmPath);
  const execPath = resolveWasmExec(wasmPath, opts.wasmExecPath);

  // wasm_exec.js is a classic script that assigns globalThis.Go; indirect eval
  // runs it in global scope regardless of the host's module-mode guess.
  (0, eval)(readFileSync(execPath, "utf8"));
  const Go = (globalThis as { Go?: new () => GoInstance }).Go;
  if (!Go) throw new Error(`wasm_exec.js at ${execPath} did not define globalThis.Go`);

  const go = new Go();
  const mod = new WebAssembly.Module(readFileSync(wasmPath));
  const instance = new WebAssembly.Instance(mod, go.importObject);
  // Not awaited: the synchronous part of go.run executes Go's main up to its
  // select{} park, which registers globalThis.papiCall before returning here.
  void go.run(instance);

  const papiCall = (globalThis as { papiCall?: PapiCall }).papiCall;
  if (typeof papiCall !== "function") {
    throw new Error("papi-client-wasm did not register globalThis.papiCall");
  }
  loaded = papiCall;
  return loaded;
}

// GoInstance is the minimal shape of the wasm_exec.js Go object we use.
interface GoInstance {
  importObject: WebAssembly.Imports;
  run(instance: WebAssembly.Instance): Promise<void>;
}

interface CallResult<T> {
  ok: boolean;
  value?: T;
  error?: string;
}

/**
 * call drives the core once: it hands a {fn, body} request to the wasm's papiCall
 * and unwraps the {ok, value, error} envelope. Synchronous (the core is pure);
 * fetch is the async part and lives in Client.
 */
export function call<T>(fn: string, body: string, opts: CallOptions = {}): T {
  const papiCall = ensureLoaded(opts);
  const req: Record<string, unknown> = { fn, body };
  if (opts.publishedIds) req.published_ids = opts.publishedIds;

  const res = JSON.parse(papiCall(JSON.stringify(req))) as CallResult<T>;
  if (!res.ok) {
    throw new Error(`papi-client-wasm fn=${fn}: ${res.error ?? "unknown error"}`);
  }
  return res.value as T;
}

// --- bare core (network-free; caller supplies the bytes) ---

export const decodeDocument = (body: string, o?: CallOptions): PapiDocument =>
  call<PapiDocument>("decode_document", body, o);
export const decodeDiscovery = (body: string, o?: CallOptions): Discovery =>
  call<Discovery>("decode_discovery", body, o);
export const decodeRepos = (body: string, o?: CallOptions): Repo[] =>
  call<Repo[]>("decode_repos", body, o);
export const decodeProfiles = (body: string, o?: CallOptions): Profile[] =>
  call<Profile[]>("decode_profiles", body, o);
export const decodeCaches = (body: string, o?: CallOptions): Cache[] =>
  call<Cache[]>("decode_caches", body, o);
export const verifyDocument = (
  body: string,
  publishedIds: string[],
  o?: CallOptions,
): SigVerifyResult => call<SigVerifyResult>("verify_document", body, { ...o, publishedIds });

// --- convenience Client (does the fetch, then the core) ---

export class Client {
  readonly base: string;

  constructor(base: string) {
    this.base = base;
  }

  /** for normalizes a bare domain or URL to a scheme://host base (https default). */
  static for(target: string): Client {
    const u = new URL(target.includes("://") ? target : `https://${target}`);
    return new Client(`${u.protocol}//${u.host}`);
  }

  private async text(path: string): Promise<string> {
    const r = await fetch(this.base + path);
    if (!r.ok) throw new Error(`GET ${path} → HTTP ${r.status}`);
    return await r.text();
  }

  async document(): Promise<PapiDocument> {
    return decodeDocument(await this.text("/papi"));
  }
  async repos(): Promise<Repo[]> {
    return decodeRepos(await this.text("/papi/repos"));
  }
  async profiles(): Promise<Profile[]> {
    return decodeProfiles(await this.text("/papi/profiles"));
  }
  async caches(): Promise<Cache[]> {
    return decodeCaches(await this.text("/papi/caches"));
  }
  /** sshAuthorizedKeys returns the raw text/plain body (RFC-0001 §4.2). */
  async sshAuthorizedKeys(): Promise<string> {
    return this.text("/papi/ssh-authorized-keys");
  }
  /** verifyDocument checks the fetched /papi against published slot-9A ids (§10). */
  async verifyDocument(publishedIds: string[]): Promise<SigVerifyResult> {
    return verifyDocument(await this.text("/papi"), publishedIds);
  }
}
