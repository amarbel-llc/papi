// bun:test smoke tests for the TS wrapper's wasm loader + bare-core decoders
// (FDR-0007). Network-free: they drive build/papi-client.wasm directly (path via
// $PAPI_CLIENT_WASM, set by `just test-ts`); the fetch-based Client is exercised
// against a live domain, not here.

import { test, expect } from "bun:test";
import {
  decodeProfiles,
  decodeRepos,
  decodeDocument,
  verifyDocument,
  Client,
} from "./papi.ts";

test("decodeProfiles: NixOS pair + non-NixOS home", () => {
  const body =
    `{"data":[` +
    `{"id":"framework-laptop","flakeref":"github:amarbel-llc/eng#nixosConfigurations.framework-laptop",` +
    `"home_flakeref":"github:amarbel-llc/eng#homeConfigurations.framework-laptop","kind":"nixos-configuration"},` +
    `{"id":"dev","flakeref":"github:amarbel-llc/eng#homeConfigurations.dev","kind":"home-configuration"}` +
    `],"meta":{"type":"profiles","count":2}}`;
  const ps = decodeProfiles(body);
  expect(ps.length).toBe(2);
  expect(ps[0].id).toBe("framework-laptop");
  expect(ps[0].home_flakeref).toBeTruthy();
  expect(ps[1].home_flakeref ?? "").toBe("");
});

test("decodeRepos", () => {
  const body =
    `{"data":[{"name":"papi","url":"https://github.com/amarbel-llc/papi","owner":"amarbel-llc"}],"meta":{"count":1}}`;
  const rs = decodeRepos(body);
  expect(rs.length).toBe(1);
  expect(rs[0].name).toBe("papi");
});

test("decodeDocument unwraps the envelope", () => {
  const doc = decodeDocument(
    `{"data":{"version":"papi/v0","profiles":[{"id":"dev","flakeref":"github:x#homeConfigurations.dev","kind":"home-configuration"}]},"meta":{}}`,
  );
  expect(doc.version).toBe("papi/v0");
  expect(doc.profiles?.length).toBe(1);
});

test("verifyDocument: unsigned is not authentic", () => {
  const res = verifyDocument(`{"data":{"version":"papi/v0"},"meta":{}}`, []);
  expect(res.authentic).toBe(false);
});

test("Client.for normalizes a bare domain to an https base", () => {
  expect(Client.for("linenisgreat.com").base).toBe("https://linenisgreat.com");
  expect(Client.for("https://api.example.test/x").base).toBe("https://api.example.test");
});
