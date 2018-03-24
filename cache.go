package certbot

import (
	"context"
	"crypto/tls"
	"errors"
	"sync"
)

// Cache describes the interface that certificate caches must implement.
// Cache implementations must be thread safe.
type Cache interface {
	// Get returns a certificate data for the specified key.
	// If there's no such key, Get returns ErrCacheMiss.
	Get(context.Context, string) (*tls.Certificate, error)

	// Put stores the data in the cache under the specified key.
	Put(context.Context, string, *tls.Certificate) error

	// Delete removes a certificate data from the cache under the specified key.
	// If there's no such key in the cache, Delete returns nil.
	Delete(context.Context, string) error
}

// ErrCacheMiss should be returned by Cache implementations
// when a certificate could not be found.
var ErrCacheMiss = errors.New("no matching certificate found")

type memCache struct {
	mu    *sync.RWMutex
	cache map[string]*tls.Certificate
}

// NewMemCache creates an in-memory cache that implements the Cache interface.
func NewMemCache() Cache {
	return &memCache{
		mu:    &sync.RWMutex{},
		cache: map[string]*tls.Certificate{},
	}
}

func (m memCache) Get(_ context.Context, key string) (*tls.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	cert, ok := m.cache[key]
	if ok {
		return cert, nil
	}

	return nil, ErrCacheMiss
}

func (m *memCache) Put(_ context.Context, key string, cert *tls.Certificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.cache[key] = cert
	return nil
}

func (m *memCache) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.cache, key)
	return nil
}
