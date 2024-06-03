package dns

import (
	"slices"
	"time"
)

type workerCacheEntry struct {
	rr        RR
	header    RR_Header
	timestamp time.Time
}

type workerCache struct {
	entries map[string][]workerCacheEntry
}

func newWorkerCache() *workerCache {
	return &workerCache{
		entries: make(map[string][]workerCacheEntry),
	}
}

// returns the cached RRs and a bool indicating if the caller should fetch RRs for this name again
func (wc *workerCache) get(name string, ty uint16) ([]RR, bool) {
	entries, ok := wc.entries[name]
	if !ok {
		return nil, true
	}

	rrs := []RR{}
	modified := false
	for idx := 0; idx < len(entries); {
		entry := &entries[idx]
		if entry.header.Type != ty {
			idx += 1
			continue
		}
		if uint32(time.Since(entry.timestamp).Seconds()) >= entry.header.TTL {
			entries[idx] = entries[len(entries)-1]
			entries = entries[:len(entries)-1]
			modified = true
		} else {
			rrs = append(rrs, entry.rr)
			idx += 1
		}
	}
	wc.entries[name] = entries

	return rrs, modified
}

// replace all RR with type 'ty' by 'rrs'
func (wc *workerCache) put(name string, rrs []RR, ty uint16) {
	if entries, ok := wc.entries[name]; ok {
		wc.entries[name] = slices.DeleteFunc(entries, func(entry workerCacheEntry) bool {
			return entry.header.Type == ty
		})
	}

	entries := wc.entries[name]
	for _, rr := range rrs {
		entries = append(entries, workerCacheEntry{
			rr:        rr,
			header:    rr.Header(),
			timestamp: time.Now(),
		})
	}
	wc.entries[name] = entries
}
