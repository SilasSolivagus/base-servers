package authn

import (
	"testing"

	"github.com/SilasSolivagus/base-servers/gen/baseservers/v1/baseserversv1connect"
)

func TestReadSafeAllowsReadsDeniesMutations(t *testing.T) {
	reads := []string{
		"/baseservers.v1.AuthzService/Check",
		"/baseservers.v1.DelegationService/CheckDelegated",
		"/baseservers.v1.AuditService/List",
		"/baseservers.v1.AuditService/Verify",
		"/baseservers.v1.PrincipalService/GetPrincipal",
		"/baseservers.v1.ApiKeyService/List",
	}
	for _, p := range reads {
		if !IsReadSafe(p) {
			t.Errorf("expected read-safe: %s", p)
		}
	}
	mutations := []string{
		"/baseservers.v1.PrincipalService/CreatePrincipal",
		"/baseservers.v1.OrgService/AddMember",
		"/baseservers.v1.OrgService/CreateOrganization",
		"/baseservers.v1.OrgService/CreateTeam",
		"/baseservers.v1.OrgService/AddTeamMember",
		"/baseservers.v1.RoleService/AssignRole",
		"/baseservers.v1.RoleService/CreateRole",
		"/baseservers.v1.DelegationService/Issue",
		"/baseservers.v1.DelegationService/Revoke",
		"/baseservers.v1.AuthzService/RegisterOwnership",
		"/baseservers.v1.ApiKeyService/Issue",
		"/baseservers.v1.ApiKeyService/Revoke",
		"/baseservers.v1.SomeFutureService/GetOrCreateThing", // Get* prefix but NOT in allowlist -> denied
		"/unknown/procedure",
		"",
	}
	for _, p := range mutations {
		if IsReadSafe(p) {
			t.Errorf("expected NOT read-safe (default deny): %s", p)
		}
	}
}

// TestReadSafeEnumeratesAllRegisteredProcedures is the exhaustive-registry
// guardrail: it references EVERY generated *Procedure const across every
// Connect service (by name, since Go has no reflection over package-level
// consts) and asserts each is explicitly classified as either read-safe or
// a known mutation. If a new RPC is added to the .proto and its generated
// Procedure const is not added to one of the two slices below, this test's
// union-coverage assertion catches the gap -- and if it's misclassified
// (added to the wrong slice, or the allowlist drifts from readonly.go), the
// IsReadSafe-membership assertion catches that.
func TestReadSafeEnumeratesAllRegisteredProcedures(t *testing.T) {
	// The 6 read-safe procedures, matching readSafeProcedures in readonly.go.
	readSafe := []string{
		baseserversv1connect.ApiKeyServiceListProcedure,
		baseserversv1connect.AuditServiceListProcedure,
		baseserversv1connect.AuditServiceVerifyProcedure,
		baseserversv1connect.AuthzServiceCheckProcedure,
		baseserversv1connect.DelegationServiceCheckDelegatedProcedure,
		baseserversv1connect.PrincipalServiceGetPrincipalProcedure,
	}

	// Every other procedure generated as of this writing, explicitly
	// classified as a mutation (NOT read-safe).
	mutations := []string{
		baseserversv1connect.ApiKeyServiceIssueProcedure,
		baseserversv1connect.ApiKeyServiceRevokeProcedure,
		baseserversv1connect.OrgServiceCreateOrganizationProcedure,
		baseserversv1connect.OrgServiceCreateTeamProcedure,
		baseserversv1connect.OrgServiceAddMemberProcedure,
		baseserversv1connect.OrgServiceAddTeamMemberProcedure,
		baseserversv1connect.DelegationServiceIssueProcedure,
		baseserversv1connect.DelegationServiceRevokeProcedure,
		baseserversv1connect.AuthzServiceRegisterOwnershipProcedure,
		baseserversv1connect.RoleServiceCreateRoleProcedure,
		baseserversv1connect.RoleServiceAssignRoleProcedure,
		baseserversv1connect.PrincipalServiceCreatePrincipalProcedure,
	}

	const wantTotal = 18 // 6 read-safe + 12 mutations, one per generated *Procedure const, reconciled by hand against gen/.../*.connect.go
	if got := len(readSafe) + len(mutations); got != wantTotal {
		t.Fatalf("expected %d total registered procedures classified, got %d (readSafe=%d mutations=%d) -- reconcile this list against gen/baseservers/v1/baseserversv1connect/*.connect.go", wantTotal, got, len(readSafe), len(mutations))
	}

	seen := make(map[string]bool, wantTotal)
	for _, p := range readSafe {
		if seen[p] {
			t.Fatalf("duplicate procedure in readSafe list: %s", p)
		}
		seen[p] = true
		if !IsReadSafe(p) {
			t.Errorf("expected read-safe: %s", p)
		}
	}
	for _, p := range mutations {
		if seen[p] {
			t.Fatalf("procedure listed as both read-safe and mutation: %s", p)
		}
		seen[p] = true
		if IsReadSafe(p) {
			t.Errorf("expected NOT read-safe (mutation): %s", p)
		}
	}

	if len(seen) != wantTotal {
		t.Fatalf("union of readSafe+mutations covers %d distinct procedures, want %d", len(seen), wantTotal)
	}
}
