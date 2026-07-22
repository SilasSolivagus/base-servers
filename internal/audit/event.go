// Package audit 记录一条只追加、每租户哈希链、篡改可验的审计流。
package audit

import (
	"crypto/sha256"
	"encoding/json"
	"strings"
)

const (
	ActorHuman   = "human"
	ActorService = "service"
	ActorAgent   = "agent"
	ActorSystem  = "system"
)
const (
	OutcomeSuccess = "success"
	OutcomeDenied  = "denied"
	OutcomeError   = "error"
)

// Event 是一条待记录的审计事件(未落库、未算链)。
type Event struct {
	ActorID, ActorType   string
	SystemAdmin          bool
	Action               string
	TargetType, TargetID string
	OrgID                string
	Outcome              string
	Detail               map[string]string
}

// ChainOf:空 org → "system" 链。
func ChainOf(orgID string) string {
	if orgID == "" {
		return "system"
	}
	return orgID
}

// canonicalRecord 是参与哈希的规范结构;字段固定顺序,map 由 encoding/json 按键排序 → 确定性。
type canonicalRecord struct {
	Seq         int64             `json:"seq"`
	TsUnixNano  int64             `json:"ts"`
	ActorID     string            `json:"actor_id"`
	ActorType   string            `json:"actor_type"`
	SystemAdmin bool              `json:"system_admin"`
	Action      string            `json:"action"`
	TargetType  string            `json:"target_type"`
	TargetID    string            `json:"target_id"`
	OrgID       string            `json:"org_id"`
	Outcome     string            `json:"outcome"`
	Detail      map[string]string `json:"detail"`
}

func canonicalHash(seq int64, tsUnixNano int64, e Event, prevHash []byte) []byte {
	b, _ := json.Marshal(canonicalRecord{
		Seq: seq, TsUnixNano: tsUnixNano, ActorID: e.ActorID, ActorType: e.ActorType,
		SystemAdmin: e.SystemAdmin, Action: e.Action, TargetType: e.TargetType, TargetID: e.TargetID,
		OrgID: e.OrgID, Outcome: e.Outcome, Detail: e.Detail,
	})
	h := sha256.New()
	h.Write(b)
	h.Write(prevHash)
	return h.Sum(nil)
}

// Redact 丢掉任何看起来像密钥的字段,防止审计成为泄密面。
func Redact(d map[string]string) map[string]string {
	if d == nil {
		return nil
	}
	out := make(map[string]string, len(d))
	for k, v := range d {
		lk := strings.ToLower(k)
		if strings.Contains(lk, "token") || strings.Contains(lk, "secret") ||
			strings.Contains(lk, "kek") || strings.Contains(lk, "password") ||
			strings.Contains(lk, "proof") || strings.Contains(lk, "key") ||
			strings.Contains(lk, "dpop") || strings.Contains(lk, "cnf") {
			continue
		}
		out[k] = v
	}
	return out
}
