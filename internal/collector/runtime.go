package collector

import "sync/atomic"

type Runtime struct {
	attached              atomic.Bool
	ready                 atomic.Bool
	collectionFailures    atomic.Uint64
	symbolRefreshFailures atomic.Uint64
}

func (r *Runtime) SetAttached(value bool) { r.attached.Store(value) }
func (r *Runtime) Attached() bool         { return r.attached.Load() }
func (r *Runtime) SetReady(value bool)    { r.ready.Store(value) }
func (r *Runtime) Ready() bool            { return r.ready.Load() }
func (r *Runtime) CollectionFailure()     { r.collectionFailures.Add(1) }
func (r *Runtime) CollectionFailures() uint64 {
	return r.collectionFailures.Load()
}
func (r *Runtime) SymbolRefreshFailure() { r.symbolRefreshFailures.Add(1) }
func (r *Runtime) SymbolRefreshFailures() uint64 {
	return r.symbolRefreshFailures.Load()
}
