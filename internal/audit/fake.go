package audit

import "context"

// FakeRecorder 是测试友好的内存 Recorder:同步收集 Event,不落库、不排队。
type FakeRecorder struct{ Events []Event }

func (f *FakeRecorder) Record(_ context.Context, e Event) { f.Events = append(f.Events, e) }
