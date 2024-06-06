package dns

import (
	"slices"
	"strings"
	"sync"
	"time"
)

var _ AuthorityCache = (*ExclusiveAuthorityCache)(nil)
var _ AuthorityCache = (*SharedAuthorityCache)(nil)

type AuthorityCache interface {
	Get(zone string) []string
	Put(zone string, nameservers []string, ttl uint32)
}

func FindBestAuthorityServers(cache AuthorityCache, domain string) []string {
	nameservers := slices.Clone(RootNameServers)
	labels := splitNameIntoLabels(domain)
	if len(labels) == 0 {
		return nameservers
	}

	for i := len(labels) - 1; i >= 0; i-- {
		zone := strings.Join(labels[i:], ".")
		for _, ns := range cache.Get(zone) {
			nameservers = append(nameservers, ns)
		}
	}

	return nameservers
}

type authorityCacheEntry struct {
	nameservers []string
	ttl         uint32
	timestamp   time.Time
}

type ExclusiveAuthorityCache struct {
	entries map[string]authorityCacheEntry
}

func NewExclusiveAuthorityCache() *ExclusiveAuthorityCache {
	return &ExclusiveAuthorityCache{
		entries: make(map[string]authorityCacheEntry),
	}
}

// Get implements AuthorityCache.
func (e *ExclusiveAuthorityCache) Get(zone string) []string {
	entry, ok := e.entries[zone]
	if !ok {
		return nil
	}
	if uint32(time.Since(entry.timestamp).Seconds()) >= entry.ttl {
		delete(e.entries, zone)
		return nil
	}
	return entry.nameservers
}

// Put implements AuthorityCache.
func (e *ExclusiveAuthorityCache) Put(zone string, nameservers []string, ttl uint32) {
	e.entries[zone] = authorityCacheEntry{
		nameservers: nameservers,
		ttl:         ttl,
		timestamp:   time.Now(),
	}
}

type SharedAuthorityCache struct {
	sync.RWMutex
	exclusive *ExclusiveAuthorityCache
}

func NewSharedAuthorityCache() *SharedAuthorityCache {
	return &SharedAuthorityCache{
		RWMutex:   sync.RWMutex{},
		exclusive: NewExclusiveAuthorityCache(),
	}
}

// Get implements AuthorityCache.
func (s *SharedAuthorityCache) Get(zone string) []string {
	s.RLock()
	defer s.RUnlock()
	return s.exclusive.Get(zone)
}

// Put implements AuthorityCache.
func (s *SharedAuthorityCache) Put(zone string, nameservers []string, ttl uint32) {
	s.Lock()
	defer s.Unlock()
	s.exclusive.Put(zone, nameservers, ttl)
}
