//go:build js && wasm

package main

import "syscall/js"

// main (js/wasm, the primary target) registers papiCall on the global object and
// then blocks so the Go runtime stays alive for repeated calls. papiCall takes one
// string argument — the {fn, body, published_ids?} request JSON — and returns the
// dispatchJSON {ok, value, error} envelope as a JSON string. It never throws; the
// TS wrapper rethrows on {ok:false}.
func main() {
	js.Global().Set("papiCall", js.FuncOf(func(_ js.Value, args []js.Value) any {
		if len(args) < 1 || args[0].Type() != js.TypeString {
			return string(encodeResponse(response{Error: "papiCall(reqJSON): want one string argument"}))
		}
		return string(dispatchJSON([]byte(args[0].String())))
	}))
	select {} // keep the runtime alive so papiCall remains callable
}
