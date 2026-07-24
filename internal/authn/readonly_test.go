package authn

import "testing"

func TestReadSafeAllowsReadsDeniesMutations(t *testing.T) {
	reads := []string{
		"/baseservers.v1.AuthzService/Check",
		"/baseservers.v1.DelegationService/CheckDelegated",
		"/baseservers.v1.AuditService/List",
		"/baseservers.v1.AuditService/Verify",
		"/baseservers.v1.PrincipalService/GetPrincipal",
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
