package dns

import (
	"time"
)

// TODO: handle TYPE_ANY

type workerCacheEntry struct {
	rr        RR
	timestamp time.Time
}

type workerCacheKey struct {
	name string
	ty   uint16
}

type workerCache struct {
	entries map[workerCacheKey][]workerCacheEntry
}

func newWorkerCache() *workerCache {
	return &workerCache{
		entries: make(map[workerCacheKey][]workerCacheEntry),
	}
}

// returns the cached RRs and a bool indicating if the caller should fetch RRs for this name again
func (wc *workerCache) get(name string, ty uint16) []RR {
	key := workerCacheKey{name: name, ty: ty}
	entries, ok := wc.entries[key]
	if !ok {
		return nil
	}

	// invalid the cache if any one entry for this type has expired
	for _, entry := range entries {
		if uint32(time.Since(entry.timestamp).Seconds()) >= entry.rr.TTL {
			delete(wc.entries, key)
			return nil
		}
	}

	rrs := make([]RR, len(entries))
	for idx, entry := range entries {
		rrs[idx] = entry.rr
		rrs[idx].TTL -= uint32(time.Since(entry.timestamp).Seconds())
	}

	return rrs
}

func (wc *workerCache) put(name string, ty uint16, rrs []RR) {
	key := workerCacheKey{name: name, ty: ty}
	entries := make([]workerCacheEntry, len(rrs))
	for idx, rr := range rrs {
		entries[idx] = workerCacheEntry{
			rr:        rr,
			timestamp: time.Now(),
		}
	}
	wc.entries[key] = entries
}
