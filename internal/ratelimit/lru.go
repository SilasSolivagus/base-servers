package ratelimit

import "container/list"

// lru is a fixed-capacity map keyed by string. On insert past capacity it evicts
// the least-recently-used entry. Not safe for concurrent use — callers hold a shard lock.
type lru struct {
	cap int
	ll  *list.List // front = most recently used
	m   map[string]*list.Element
}

type lruItem struct {
	key string
	val interface{}
}

func newLRU(capacity int) *lru {
	if capacity < 1 {
		capacity = 1
	}
	return &lru{cap: capacity, ll: list.New(), m: make(map[string]*list.Element, capacity)}
}

// get returns the value and true if present, marking it most-recently-used.
func (c *lru) get(key string) (interface{}, bool) {
	if el, ok := c.m[key]; ok {
		c.ll.MoveToFront(el)
		return el.Value.(*lruItem).val, true
	}
	return nil, false
}

// put inserts/updates key, evicting the LRU entry if over capacity.
func (c *lru) put(key string, val interface{}) {
	if el, ok := c.m[key]; ok {
		c.ll.MoveToFront(el)
		el.Value.(*lruItem).val = val
		return
	}
	el := c.ll.PushFront(&lruItem{key: key, val: val})
	c.m[key] = el
	if c.ll.Len() > c.cap {
		old := c.ll.Back()
		if old != nil {
			c.ll.Remove(old)
			delete(c.m, old.Value.(*lruItem).key)
		}
	}
}

func (c *lru) len() int { return c.ll.Len() }
