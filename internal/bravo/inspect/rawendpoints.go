package inspect

import (
	"encoding/json"
	"net/http"
	"strings"

	"code.linenisgreat.com/papi/internal/alfa/papi"
)

// rawEndpoints are the RFC-0001 §4.2 endpoints that return a raw, unenveloped
// body, with the Content-Type each SHOULD carry.
var rawEndpoints = []struct{ suffix, contentType string }{
	{"/papi/piggy-ids", "text/plain"},
	{"/papi/ssh-authorized-keys", "text/plain"},
	{"/papi/bootstrap", "text/plain"},
	{"/papi/pigpen", "text/vnd.pigpen"},
	{conformistProfilePath, "text/plain"},
}

func rawEndpointContentType(path string) (string, bool) {
	for _, e := range rawEndpoints {
		if strings.HasSuffix(path, e.suffix) {
			return e.contentType, true
		}
	}
	return "", false
}

// rawEndpointPoint checks a raw endpoint: 200, a body that is NOT the JSON
// envelope (§4.2), and (SHOULD) the endpoint's Content-Type.
func rawEndpointPoint(resp *papi.Response, wantType string) point {
	if resp.Status != http.StatusOK {
		return mustFail("conformance: "+resp.Path+" status 200", map[string]any{"got": resp.Status})
	}
	var env map[string]json.RawMessage
	if json.Unmarshal(resp.Body, &env) == nil && hasKey(env, "data") && hasKey(env, "meta") {
		return mustFail("conformance: "+resp.Path+" MUST NOT use the {data,meta} envelope (§4.2)",
			map[string]any{"content_type": resp.ContentType})
	}
	if !strings.HasPrefix(resp.ContentType, wantType) {
		return shouldFail("conformance: "+resp.Path+" Content-Type "+wantType+" (§4.2)",
			map[string]any{"got": resp.ContentType})
	}
	return ok("conformance: " + resp.Path + " raw " + wantType + ", not enveloped (§4.2)")
}
