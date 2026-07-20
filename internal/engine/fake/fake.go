package fake

import (
	"context"
	"fmt"
	"sync"

	"github.com/SilasSolivagus/base-servers/internal/engine"
)

type Engine struct {
	Caps                 engine.Capabilities
	mu                   sync.Mutex
	seq                  int
	items                map[string]engine.EnginePrincipal
	CreatePrincipalCalls int
}

func New() *Engine {
	return &Engine{items: map[string]engine.EnginePrincipal{}}
}

func (e *Engine) Capabilities() engine.Capabilities { return e.Caps }

func (e *Engine) CreatePrincipal(_ context.Context, p engine.EnginePrincipal) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.CreatePrincipalCalls++
	e.seq++
	id := fmt.Sprintf("fake-%d", e.seq)
	p.ID = id
	e.items[id] = p
	return id, nil
}

func (e *Engine) GetPrincipal(_ context.Context, id string) (engine.EnginePrincipal, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	p, ok := e.items[id]
	if !ok {
		return engine.EnginePrincipal{}, fmt.Errorf("principal %q not found", id)
	}
	return p, nil
}
