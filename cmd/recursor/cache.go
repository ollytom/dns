package main

import (
	"sync"
	"golang.org/x/net/dns/dnsmessage"
)

var cache = struct {
	m map[dnsmessage.Name]map[dnsmessage.Type][]dnsmessage.Resource
	sync.RWMutex
}{m: make(map[dnsmessage.Name]map[dnsmessage.Type][]dnsmessage.Resource)}

func lookup(n dnsmessage.Name, t dnsmessage.Type) ([]dnsmessage.Resource, bool) {
	cache.RLock()
	if rr, ok := cache.m[n][t]; ok {
		cache.RUnlock()
		if expired(n, t) {
			cache.Lock()
			delete(cache.m[n], t)
			cache.Unlock()
			return nil, false
		}
		return rr, true
	}
	l := len(cache.m[n])
	cache.RUnlock()
	if l < 1 {
		cache.Lock()
		cache.m[n] = make(map[dnsmessage.Type][]dnsmessage.Resource)
		cache.Unlock()
	}
	return nil, false
}

func insert(n dnsmessage.Name, t dnsmessage.Type, rrs []dnsmessage.Resource) {
	cache.Lock()
	cache.m[n][t] = rrs
	cache.Unlock()
	return
}

func expired(n dnsmessage.Name, t dnsmessage.Type) bool { return false }
