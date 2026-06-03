package zero_trust_access_policy

import (
	"context"
	"testing"

	"github.com/cloudflare/terraform-provider-cloudflare/internal/customfield"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// findInclude returns the first element matching pred, or nil.
func findInclude(conds []ZeroTrustAccessPolicyIncludeModel, pred func(ZeroTrustAccessPolicyIncludeModel) bool) *ZeroTrustAccessPolicyIncludeModel {
	for i := range conds {
		if pred(conds[i]) {
			return &conds[i]
		}
	}
	return nil
}

// TestPruneEmptyIncludeSelectors_GSuitePhantom reproduces the provider bug where a
// real gsuite selector sharing an include set causes the decoder to stamp an empty
// gsuite = {} object onto sibling email/email_domain elements. After pruning, the
// phantom must be gone while the real gsuite element and the real siblings survive.
func TestPruneEmptyIncludeSelectors_GSuitePhantom(t *testing.T) {
	ctx := context.Background()

	set := customfield.NewObjectSetMust(ctx, []ZeroTrustAccessPolicyIncludeModel{
		// Real gsuite group element (source of truth).
		{
			GSuite: &ZeroTrustAccessPolicyIncludeGSuiteModel{
				Email:              types.StringValue("ogm-cloudflare@minutoseguros.com.br"),
				IdentityProviderID: types.StringValue("0142e72b-73b8-4ffc-81cf-48e35778ea35"),
			},
		},
		// Sibling email_domain element with phantom empty gsuite.
		{
			EmailDomain: &ZeroTrustAccessPolicyIncludeEmailDomainModel{Domain: types.StringValue("creditas.com")},
			GSuite: &ZeroTrustAccessPolicyIncludeGSuiteModel{
				Email:              types.StringNull(),
				IdentityProviderID: types.StringNull(),
			},
		},
		// Sibling email element with phantom empty gsuite.
		{
			Email: &ZeroTrustAccessPolicyIncludeEmailModel{Email: types.StringValue("emerson.barros@creditas.com")},
			GSuite: &ZeroTrustAccessPolicyIncludeGSuiteModel{
				Email:              types.StringNull(),
				IdentityProviderID: types.StringNull(),
			},
		},
	})

	if diags := pruneEmptyIncludeSelectors(ctx, &set); diags.HasError() {
		t.Fatalf("pruneEmptyIncludeSelectors returned errors: %v", diags)
	}

	conds, diags := set.AsStructSliceT(ctx)
	if diags.HasError() {
		t.Fatalf("AsStructSliceT returned errors: %v", diags)
	}
	if len(conds) != 3 {
		t.Fatalf("expected 3 elements after prune, got %d", len(conds))
	}

	// The real gsuite element must survive with its content intact.
	real := findInclude(conds, func(c ZeroTrustAccessPolicyIncludeModel) bool {
		return c.GSuite != nil && c.GSuite.Email.ValueString() == "ogm-cloudflare@minutoseguros.com.br"
	})
	if real == nil {
		t.Fatal("real gsuite element was lost during prune")
	}

	// The email_domain sibling must keep its domain and lose the phantom gsuite.
	ed := findInclude(conds, func(c ZeroTrustAccessPolicyIncludeModel) bool {
		return c.EmailDomain != nil && c.EmailDomain.Domain.ValueString() == "creditas.com"
	})
	if ed == nil {
		t.Fatal("email_domain sibling was lost during prune")
	}
	if ed.GSuite != nil {
		t.Errorf("phantom gsuite survived on email_domain sibling: %+v", ed.GSuite)
	}

	// The email sibling must keep its email and lose the phantom gsuite.
	em := findInclude(conds, func(c ZeroTrustAccessPolicyIncludeModel) bool {
		return c.Email != nil && c.Email.Email.ValueString() == "emerson.barros@creditas.com"
	})
	if em == nil {
		t.Fatal("email sibling was lost during prune")
	}
	if em.GSuite != nil {
		t.Errorf("phantom gsuite survived on email sibling: %+v", em.GSuite)
	}
}

// TestPruneEmptyIncludeSelectors_PreservesContentlessSelectors guards against
// over-pruning: everyone / certificate / any_valid_service_token are legitimately
// empty objects and must NOT be nulled by the emptiness check.
func TestPruneEmptyIncludeSelectors_PreservesContentlessSelectors(t *testing.T) {
	ctx := context.Background()

	set := customfield.NewObjectSetMust(ctx, []ZeroTrustAccessPolicyIncludeModel{
		{Everyone: &ZeroTrustAccessPolicyIncludeEveryoneModel{}},
		{Certificate: &ZeroTrustAccessPolicyIncludeCertificateModel{}},
		{AnyValidServiceToken: &ZeroTrustAccessPolicyIncludeAnyValidServiceTokenModel{}},
	})

	if diags := pruneEmptyIncludeSelectors(ctx, &set); diags.HasError() {
		t.Fatalf("pruneEmptyIncludeSelectors returned errors: %v", diags)
	}

	conds, diags := set.AsStructSliceT(ctx)
	if diags.HasError() {
		t.Fatalf("AsStructSliceT returned errors: %v", diags)
	}
	if len(conds) != 3 {
		t.Fatalf("content-less selectors were dropped: expected 3 elements, got %d", len(conds))
	}

	if findInclude(conds, func(c ZeroTrustAccessPolicyIncludeModel) bool { return c.Everyone != nil }) == nil {
		t.Error("everyone selector was incorrectly pruned")
	}
	if findInclude(conds, func(c ZeroTrustAccessPolicyIncludeModel) bool { return c.Certificate != nil }) == nil {
		t.Error("certificate selector was incorrectly pruned")
	}
	if findInclude(conds, func(c ZeroTrustAccessPolicyIncludeModel) bool { return c.AnyValidServiceToken != nil }) == nil {
		t.Error("any_valid_service_token selector was incorrectly pruned")
	}
}
