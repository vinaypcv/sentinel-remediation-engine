package storage

import (
	"context"
	"sync"
	"time"
)

type shardLeaseHandle struct {
	ctx    context.Context
	cancel context.CancelFunc
	lost   bool
}

type shardLeaseManager struct {
	store    KinesisShardLeaseStore
	stream   string
	owner    string
	duration time.Duration
	parent   context.Context
	mu       sync.Mutex
	handles  map[string]*shardLeaseHandle
	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once
}

func newShardLeaseManager(ctx context.Context, store KinesisShardLeaseStore, stream, owner string, duration time.Duration) *shardLeaseManager {
	return &shardLeaseManager{
		store: store, stream: stream, owner: owner, duration: duration, parent: ctx,
		handles: make(map[string]*shardLeaseHandle), stop: make(chan struct{}), done: make(chan struct{}),
	}
}

func (m *shardLeaseManager) Start() {
	interval := m.duration / 3
	if interval < time.Second {
		interval = time.Second
	}
	go func() {
		defer close(m.done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-m.stop:
				return
			case <-m.parent.Done():
				return
			case <-ticker.C:
				m.renewAll()
			}
		}
	}()
}

func (m *shardLeaseManager) Acquire(ctx context.Context, shard string) (bool, bool, error) {
	acquired, err := m.store.AcquireLease(ctx, m.stream, shard, m.owner, m.duration)
	if err != nil {
		m.markLost(shard, nil)
		return false, false, err
	}
	if !acquired {
		m.markLost(shard, nil)
		return false, false, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	handle := m.handles[shard]
	if handle != nil && !handle.lost {
		return true, false, nil
	}
	leaseCtx, cancel := context.WithCancel(m.parent)
	m.handles[shard] = &shardLeaseHandle{ctx: leaseCtx, cancel: cancel}
	return true, true, nil
}

func (m *shardLeaseManager) Context(shard string) context.Context {
	m.mu.Lock()
	defer m.mu.Unlock()
	if handle := m.handles[shard]; handle != nil && !handle.lost {
		return handle.ctx
	}
	return m.parent
}

func (m *shardLeaseManager) Lost(shard string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	handle := m.handles[shard]
	return handle != nil && handle.lost
}

func (m *shardLeaseManager) Release(ctx context.Context, shard string) error {
	m.mu.Lock()
	handle := m.handles[shard]
	delete(m.handles, shard)
	if handle != nil {
		handle.cancel()
	}
	m.mu.Unlock()
	if handle == nil || handle.lost {
		return nil
	}
	releaseCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return m.store.ReleaseLease(releaseCtx, m.stream, shard, m.owner)
}

func (m *shardLeaseManager) ReleaseAll() {
	m.stopOnce.Do(func() { close(m.stop) })
	<-m.done
	m.mu.Lock()
	shards := make([]string, 0, len(m.handles))
	for shard, handle := range m.handles {
		if !handle.lost {
			shards = append(shards, shard)
		}
		handle.cancel()
	}
	clear(m.handles)
	m.mu.Unlock()

	releaseCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, shard := range shards {
		_ = m.store.ReleaseLease(releaseCtx, m.stream, shard, m.owner)
	}
}

func (m *shardLeaseManager) renewAll() {
	type ownedShard struct {
		id     string
		handle *shardLeaseHandle
	}
	m.mu.Lock()
	owned := make([]ownedShard, 0, len(m.handles))
	for shard, handle := range m.handles {
		if !handle.lost {
			owned = append(owned, ownedShard{id: shard, handle: handle})
		}
	}
	m.mu.Unlock()

	for _, shard := range owned {
		ctx, cancel := context.WithTimeout(m.parent, 5*time.Second)
		acquired, err := m.store.AcquireLease(ctx, m.stream, shard.id, m.owner, m.duration)
		cancel()
		if err != nil || !acquired {
			m.markLost(shard.id, shard.handle)
			continue
		}
		m.mu.Lock()
		stillOwned := m.handles[shard.id] == shard.handle && !shard.handle.lost
		m.mu.Unlock()
		if !stillOwned {
			releaseCtx, releaseCancel := context.WithTimeout(context.Background(), 3*time.Second)
			_ = m.store.ReleaseLease(releaseCtx, m.stream, shard.id, m.owner)
			releaseCancel()
		}
	}
}

func (m *shardLeaseManager) markLost(shard string, expected *shardLeaseHandle) {
	m.mu.Lock()
	defer m.mu.Unlock()
	handle := m.handles[shard]
	if handle == nil || (expected != nil && handle != expected) || handle.lost {
		return
	}
	handle.lost = true
	handle.cancel()
}
