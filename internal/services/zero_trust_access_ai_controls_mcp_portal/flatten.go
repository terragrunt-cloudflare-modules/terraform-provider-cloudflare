package zero_trust_access_ai_controls_mcp_portal

import (
	"context"
	"encoding/json"

	"github.com/cloudflare/terraform-provider-cloudflare/internal/customfield"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// reconcilePortalServerIDs re-derives each servers[].server_id from the raw API
// response.
//
// The portal API returns each attached server's identity under the JSON key
// "id", but the resource schema and the Create/Update request body use
// "server_id" for the same value. apijson maps a struct field to a single JSON
// key for both read and write, and the model field is additionally tagged
// `no_refresh`, so the Read unmarshal leaves server_id null. Without it the
// servers[] elements carry no identity, producing a perpetual `+ server_id`
// diff and positional churn after import.
//
// env.Result.Servers preserves the response array order, so the i-th decoded
// server corresponds to the i-th "id" in the raw response body.
func reconcilePortalServerIDs(ctx context.Context, data *ZeroTrustAccessAIControlsMcpPortalModel, body []byte, diags *diag.Diagnostics) {
	if data == nil || data.Servers.IsNullOrUnknown() {
		return
	}

	var raw struct {
		Result struct {
			Servers []struct {
				ID string `json:"id"`
			} `json:"servers"`
		} `json:"result"`
	}
	// Best effort: if the body cannot be parsed, leave state untouched.
	if err := json.Unmarshal(body, &raw); err != nil {
		return
	}

	servers, d := data.Servers.AsStructSliceT(ctx)
	diags.Append(d...)
	if diags.HasError() {
		return
	}

	changed := false
	for i := range servers {
		if i < len(raw.Result.Servers) && raw.Result.Servers[i].ID != "" {
			servers[i].ServerID = types.StringValue(raw.Result.Servers[i].ID)
			changed = true
		}
	}
	if !changed {
		return
	}

	list, d := customfield.NewObjectList(ctx, servers)
	diags.Append(d...)
	if diags.HasError() {
		return
	}
	data.Servers = list
}
