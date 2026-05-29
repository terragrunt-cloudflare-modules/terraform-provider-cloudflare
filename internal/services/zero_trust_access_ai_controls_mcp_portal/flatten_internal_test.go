package zero_trust_access_ai_controls_mcp_portal

import (
	"context"
	"testing"

	"github.com/cloudflare/terraform-provider-cloudflare/internal/customfield"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// TestReconcilePortalServerIDs verifies the Read-path fix that re-derives each
// servers[].server_id from the API response "id" key (the portal API returns
// identity under "id"; the schema/write path use "server_id", and the model
// field is no_refresh, so the unmarshal leaves server_id null). The fix maps
// response id -> server_id by position, since the decoded servers list
// preserves response order.
func TestReconcilePortalServerIDs(t *testing.T) {
	ctx := context.Background()

	mkData := func(n int) *ZeroTrustAccessAIControlsMcpPortalModel {
		servers := make([]ZeroTrustAccessAIControlsMcpPortalServersModel, n)
		for i := range servers {
			// server_id intentionally left null, mirroring post-unmarshal state.
			servers[i] = ZeroTrustAccessAIControlsMcpPortalServersModel{
				ServerID:        types.StringNull(),
				DefaultDisabled: types.BoolValue(false),
				OnBehalf:        types.BoolValue(false),
			}
		}
		return &ZeroTrustAccessAIControlsMcpPortalModel{
			Servers: customfield.NewObjectListMust(ctx, servers),
		}
	}

	t.Run("populates server_id from response id by position", func(t *testing.T) {
		data := mkData(2)
		body := []byte(`{"result":{"id":"portal-1","servers":[{"id":"alpha","name":"A"},{"id":"beta","name":"B"}]}}`)
		var diags diag.Diagnostics
		reconcilePortalServerIDs(ctx, data, body, &diags)
		if diags.HasError() {
			t.Fatalf("unexpected diagnostics: %v", diags)
		}
		got, d := data.Servers.AsStructSliceT(ctx)
		if d.HasError() {
			t.Fatalf("AsStructSliceT: %v", d)
		}
		want := []string{"alpha", "beta"}
		for i, w := range want {
			if got[i].ServerID.ValueString() != w {
				t.Errorf("servers[%d].server_id = %q, want %q", i, got[i].ServerID.ValueString(), w)
			}
		}
	})

	t.Run("null servers list is a no-op", func(t *testing.T) {
		data := &ZeroTrustAccessAIControlsMcpPortalModel{
			Servers: customfield.NullObjectList[ZeroTrustAccessAIControlsMcpPortalServersModel](ctx),
		}
		var diags diag.Diagnostics
		reconcilePortalServerIDs(ctx, data, []byte(`{"result":{"servers":[]}}`), &diags)
		if diags.HasError() {
			t.Fatalf("unexpected diagnostics: %v", diags)
		}
		if !data.Servers.IsNull() {
			t.Errorf("expected servers to remain null")
		}
	})

	t.Run("unparseable body leaves state untouched", func(t *testing.T) {
		data := mkData(1)
		var diags diag.Diagnostics
		reconcilePortalServerIDs(ctx, data, []byte(`not json`), &diags)
		if diags.HasError() {
			t.Fatalf("unexpected diagnostics: %v", diags)
		}
		got, _ := data.Servers.AsStructSliceT(ctx)
		if !got[0].ServerID.IsNull() {
			t.Errorf("server_id should stay null on unparseable body, got %q", got[0].ServerID.ValueString())
		}
	})
}
