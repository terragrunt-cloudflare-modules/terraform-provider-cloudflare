package zero_trust_access_ai_controls_mcp_portal

import (
	"encoding/json"
)

// injectServerIDs rewrites a raw portal API response so that each
// servers[].id is also present under the key servers[].server_id.
//
// The portal API returns each attached server's identity under the JSON key
// "id", but the resource schema and the Create/Update request body use
// "server_id" for the same value. apijson maps a struct field to a single JSON
// key for both read and write, so a plain unmarshal looking for "server_id"
// finds nothing in a response that uses "id", leaving server_id null in state.
//
// Populating server_id BEFORE the unmarshal (rather than reconciling after) is
// required now that servers is modeled as a set: a set keyed on server_id would
// otherwise collapse elements that differ only by the (null) server_id, and the
// set would also be unable to match config elements by identity. Injecting the
// key lets apijson populate server_id natively during (Computed)Unmarshal for
// Read, Import, Create, and Update alike.
//
// Best effort: returns the input unchanged on any parse error.
func injectServerIDs(body []byte) []byte {
	var env map[string]json.RawMessage
	if json.Unmarshal(body, &env) != nil {
		return body
	}
	resRaw, ok := env["result"]
	if !ok {
		return body
	}
	var portal map[string]json.RawMessage
	if json.Unmarshal(resRaw, &portal) != nil {
		return body
	}
	serversRaw, ok := portal["servers"]
	if !ok {
		return body
	}
	var servers []map[string]json.RawMessage
	if json.Unmarshal(serversRaw, &servers) != nil {
		return body
	}

	changed := false
	for _, s := range servers {
		if _, has := s["server_id"]; has {
			continue
		}
		if id, ok := s["id"]; ok {
			s["server_id"] = id
			changed = true
		}
	}
	if !changed {
		return body
	}

	ns, err := json.Marshal(servers)
	if err != nil {
		return body
	}
	portal["servers"] = ns
	np, err := json.Marshal(portal)
	if err != nil {
		return body
	}
	env["result"] = np
	out, err := json.Marshal(env)
	if err != nil {
		return body
	}
	return out
}
