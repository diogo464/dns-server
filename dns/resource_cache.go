package dns

import (
	"math"
	"sync"
	"time"
)

var _ ResourceCache = (*SharedResourceCache)(nil)

type ResourceCache interface {
	Get(domain string, ty uint16) []RR
	Put(domain string, ty uint16, rrs []RR)
}

type resourceCacheKey struct {
	domain string
	ty     uint16
}

type resourceCacheEntry struct {
	rrs       []RR
	ttl       uint32
	timestamp time.Time
}

type SharedResourceCache struct {
	sync.Mutex
	entries map[resourceCacheKey]resourceCacheEntry
}

func NewSharedResourceCache() *SharedResourceCache {
	return &SharedResourceCache{
		Mutex:   sync.Mutex{},
		entries: make(map[resourceCacheKey]resourceCacheEntry),
	}
}

// Get implements ResourceCache.
func (s *SharedResourceCache) Get(domain string, ty uint16) []RR {
	s.Lock()
	defer s.Unlock()

	key := resourceCacheKey{domain: domain, ty: ty}
	entry, ok := s.entries[key]
	if !ok {
		return nil
	}

	elapsed := uint32(time.Since(entry.timestamp).Seconds())
	if elapsed >= entry.ttl {
		delete(s.entries, key)
		return nil
	}

	rrs := make([]RR, len(entry.rrs))
	for idx, rr := range entry.rrs {
		rrs[idx] = rr
		rrs[idx].TTL -= elapsed
	}

	return rrs
}

// Put implements ResourceCache.
func (s *SharedResourceCache) Put(domain string, ty uint16, rrs []RR) {
	if len(rrs) == 0 {
		return
	}

	key := resourceCacheKey{domain: domain, ty: ty}
	minTTL := uint32(math.MaxUint32)
	for _, rr := range rrs {
		minTTL = min(minTTL, rr.TTL)
	}

	s.Lock()
	defer s.Unlock()

	s.entries[key] = resourceCacheEntry{
		rrs:       rrs,
		ttl:       minTTL,
		timestamp: time.Now(),
	}
}
