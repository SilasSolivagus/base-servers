package apikey

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/SilasSolivagus/base-servers/internal/audit"
)

// TestSampleUnknownAggregatesIntoSingleFlush is a white-box unit test on the
// unknown-keyid sampler itself: it uses the unexported `now` seam to control
// the flush window deterministically, since a container-level test asserting
// "N misses -> exactly one aggregated flush" would be timing-sensitive (it'd
// need to either wait out unknownFlushWindow in real time or race it).
func TestSampleUnknownAggregatesIntoSingleFlush(t *testing.T) {
	rec := &audit.FakeRecorder{}
	base := time.Unix(1_700_000_000, 0)
	cur := base
	v := &Verifier{rec: rec, now: func() time.Time { return cur }}
	v.unkLastFlush = base // pretend a flush just happened at t=base

	ctx := context.Background()
	const n = 5
	for i := 0; i < n; i++ {
		cur = base.Add(time.Second) // still well inside the window
		v.sampleUnknown(ctx)
	}
	if len(rec.Events) != 0 {
		t.Fatalf("no flush expected while inside the window, got %d events", len(rec.Events))
	}

	// cross the window boundary on the next miss: this one call must flush
	// the aggregate of all n+1 misses as a SINGLE event, never one per miss.
	cur = base.Add(unknownFlushWindow + time.Second)
	v.sampleUnknown(ctx)

	if len(rec.Events) != 1 {
		t.Fatalf("expected exactly one flush event, got %d", len(rec.Events))
	}
	e := rec.Events[0]
	if e.Action != "apikey.auth" || e.TargetType != "apikey" || e.Outcome != audit.OutcomeDenied {
		t.Fatalf("unexpected event shape: %+v", e)
	}
	if e.Detail["reason"] != "unknown" {
		t.Fatalf("expected reason=unknown, got %q", e.Detail["reason"])
	}
	if e.Detail["count"] != strconv.Itoa(n+1) {
		t.Fatalf("expected count=%d, got %q", n+1, e.Detail["count"])
	}
	if e.TargetID != "" {
		t.Fatalf("unknown-class event must carry no keyid TargetID, got %q", e.TargetID)
	}
}
