package service

import (
	"sync"

	"github.com/gingered-cat/asiri/internal/domain"
)

// broker wakes long-poll waiters when a request changes. Publish is called
// after the change commits, so waiters only ever see committed state.
type broker struct {
	mu   sync.Mutex
	subs map[domain.RequestID][]chan struct{}
}

func (b *broker) subscribe(id domain.RequestID) (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	b.mu.Lock()
	if b.subs == nil {
		b.subs = map[domain.RequestID][]chan struct{}{}
	}
	b.subs[id] = append(b.subs[id], ch)
	b.mu.Unlock()
	return ch, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		list := b.subs[id]
		for i, c := range list {
			if c == ch {
				b.subs[id] = append(list[:i], list[i+1:]...)
				break
			}
		}
		if len(b.subs[id]) == 0 {
			delete(b.subs, id)
		}
	}
}

func (b *broker) publish(id domain.RequestID) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, ch := range b.subs[id] {
		select {
		case ch <- struct{}{}:
		default: // already signalled
		}
	}
}
