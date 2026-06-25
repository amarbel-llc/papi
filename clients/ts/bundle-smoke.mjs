// Standalone smoke for the zero-dependency flake bundle (packages.papi-client-ts,
// FDR-0007). It imports papi.ts from $PAPI_CLIENT_TS_DIR (the nix store output)
// with NO $PAPI_CLIENT_WASM set, so it exercises papi.ts's default sibling
// resolution of papi-client.wasm + wasm_exec.js — the real consumer path that
// `just test-ts` (which hands the wasm path in) does not cover. Exits nonzero on
// mismatch. Driven by `just test-ts-bundle`.
const dir = process.env.PAPI_CLIENT_TS_DIR;
if (!dir) {
  console.error("set PAPI_CLIENT_TS_DIR to the papi-client-ts flake output");
  process.exit(2);
}

const { decodeRepos } = await import(`${dir}/papi.ts`);
const rs = decodeRepos(
  '{"data":[{"name":"papi","url":"https://github.com/amarbel-llc/papi","owner":"amarbel-llc"}],"meta":{"count":1}}',
);
if (rs.length !== 1 || rs[0].name !== "papi") {
  console.error("bundle smoke FAILED:", JSON.stringify(rs));
  process.exit(1);
}
console.log("bundle smoke OK:", rs[0].name);
