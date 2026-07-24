package apikey

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/SilasSolivagus/base-servers/internal/audit"
)

var ErrInvalidKey = errors.New("invalid api key")

const unknownFlushWindow = 10 * time.Second

type Verifier struct {
	store *Store
	h     *Hasher
	rec   audit.Recorder
	now   func() time.Time

	// unknown-keyid sampler: single aggregate counter + last-flush time, guarded
	// by unkMu. Attacker-controlled keyids are unbounded cardinality, so this is
	// deliberately NOT a per-keyid map -- one counter, flushed at most once per
	// unknownFlushWindow, piggybacked on traffic (no background goroutine).
	unkMu        sync.Mutex
	unkCount     int64
	unkLastFlush time.Time
}

func NewVerifier(store *Store, h *Hasher, rec audit.Recorder) *Verifier {
	return &Verifier{store: store, h: h, rec: rec, now: time.Now}
}

// prefix returns the first ~6 chars of a keyID (non-secret; the secret is a
// separate segment already discarded by Parse) for use as a non-sensitive
// audit TargetID.
func prefix(keyID string) string {
	const n = 6
	if len(keyID) <= n {
		return keyID
	}
	return keyID[:n]
}

func (v *Verifier) emitAuthDenied(ctx context.Context, keyIDPrefix, reason string) {
	if v.rec == nil {
		return
	}
	v.rec.Record(ctx, audit.Event{
		Action: "apikey.auth", TargetType: "apikey", TargetID: keyIDPrefix,
		Outcome: audit.OutcomeDenied, Detail: map[string]string{"reason": reason},
	})
}

// sampleUnknown accumulates unknown-keyid (or unparseable) auth misses and
// flushes a single aggregate count at most once per unknownFlushWindow. No
// background goroutine: the flush is piggybacked on whichever call happens to
// cross the window boundary, so there is no Close() to wire up.
func (v *Verifier) sampleUnknown(ctx context.Context) {
	if v.rec == nil {
		return
	}
	now := v.now()
	v.unkMu.Lock()
	v.unkCount++
	var flush int64
	if now.Sub(v.unkLastFlush) > unknownFlushWindow {
		flush = v.unkCount
		v.unkCount = 0
		v.unkLastFlush = now
	}
	v.unkMu.Unlock()
	if flush > 0 {
		v.rec.Record(ctx, audit.Event{
			Action: "apikey.auth", TargetType: "apikey", Outcome: audit.OutcomeDenied,
			Detail: map[string]string{"reason": "unknown", "count": strconv.FormatInt(flush, 10)},
		})
	}
}

// Verify parses+authenticates a presented token. Fail-closed: any defect -> ErrInvalidKey.
// The secret is never logged and never leaves this function.
func (v *Verifier) Verify(ctx context.Context, token string) (string, bool, error) {
	keyID, secret, ok := Parse(token)
	if !ok {
		// no keyID to attribute to; attacker-controlled cardinality -> sampled, not per-attempt.
		v.sampleUnknown(ctx)
		return "", false, ErrInvalidKey
	}
	rec, err := v.store.GetByKeyID(ctx, keyID)
	if err != nil {
		// unknown keyid (pgx.ErrNoRows) or any DB error -> fail closed, do not distinguish to caller.
		// Still attacker-controlled cardinality -> sampled, never a per-keyid map.
		v.sampleUnknown(ctx)
		return "", false, ErrInvalidKey
	}
	if !v.h.Equal(secret, rec.Hash) {
		v.emitAuthDenied(ctx, prefix(keyID), "mismatch")
		return "", false, ErrInvalidKey
	}
	if rec.Revoked {
		v.emitAuthDenied(ctx, prefix(keyID), "revoked")
		return "", false, ErrInvalidKey
	}
	if rec.ExpiresAt != nil && time.Now().After(*rec.ExpiresAt) {
		v.emitAuthDenied(ctx, prefix(keyID), "expired")
		return "", false, ErrInvalidKey
	}
	// best-effort last_used update; never block/fail the request
	go func() {
		bg, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = v.store.TouchLastUsed(bg, keyID)
	}()
	return rec.PrincipalID, rec.ReadOnly, nil
}
