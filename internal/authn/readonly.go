package authn

// readSafeProcedures is the EXPLICIT allowlist of read-only-safe Connect
// procedures. A read-only API key may ONLY invoke procedures in this set;
// everything else (all mutations, and any new/unclassified procedure) is
// denied by default (fail-safe). Adding a new read RPC? Add it here AND to
// the enumeration test, or read-only keys will (safely) be denied it.
//
// Reconciled against the procedures actually registered in
// gen/baseservers/v1/baseserversv1connect/*.connect.go:
//
//	AuditService:      List (read) -> safe; Verify (read, tamper-check) -> safe
//	AuthzService:      Check (read) -> safe; RegisterOwnership (mutation) -> NOT safe
//	DelegationService: CheckDelegated (read) -> safe; Issue, Revoke (mutations) -> NOT safe
//	OrgService:        CreateOrganization, CreateTeam, AddMember, AddTeamMember
//	                   -> all mutations, NOT safe (no Get/List procedure is
//	                   registered yet, so none is allowlisted)
//	PrincipalService:  GetPrincipal (read) -> safe; CreatePrincipal (mutation) -> NOT safe
//	RoleService:       CreateRole, AssignRole -> mutations, NOT safe
//
// ApiKeyService has no generated Connect procedures yet (pending a later
// task), so nothing for it is allowlisted here either.
var readSafeProcedures = map[string]bool{
	"/baseservers.v1.AuditService/List":                true,
	"/baseservers.v1.AuditService/Verify":              true,
	"/baseservers.v1.AuthzService/Check":               true,
	"/baseservers.v1.DelegationService/CheckDelegated": true,
	"/baseservers.v1.PrincipalService/GetPrincipal":    true,
}

// IsReadSafe reports whether a read-only credential may invoke this procedure.
func IsReadSafe(procedure string) bool { return readSafeProcedures[procedure] }
