package delegation

import "time"

type Delegation struct {
	ID, AgentID, DelegatorID, OrgID string
	Scope                           []string
	ExpiresAt                       time.Time
	Revoked                         bool
	CnfJkt                          string
}
