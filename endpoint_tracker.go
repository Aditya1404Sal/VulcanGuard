package main

import (
	"sync"
	"time"
)

type EndpointTracker struct {
	endpoints map[string]*EndpointStats
	mu        sync.Mutex
}

type EndpointStats struct {
	RequestCount int
	LastMinute   int
	LastHour     int
}

func NewEndpointTracker() *EndpointTracker {
	return &EndpointTracker{
		endpoints: make(map[string]*EndpointStats),
	}
}

func (et *EndpointTracker) TrackRequest(path string) bool {
	et.mu.Lock()
	defer et.mu.Unlock()

	stats, exists := et.endpoints[path]
	if !exists {
		stats = &EndpointStats{}
		et.endpoints[path] = stats
	}

	stats.RequestCount++
	stats.LastMinute++
	stats.LastHour++

	if stats.LastMinute > 1000 && stats.LastMinute > stats.LastHour/60*10 {
		return false
	}

	return true
}

func (et *EndpointTracker) cleanUpStats() {
	for {
		time.Sleep(time.Minute)
		et.mu.Lock()
		for _, stats := range et.endpoints {
			stats.LastMinute = 0
		}
		et.mu.Unlock()
	}
}

func (et *EndpointTracker) cleanUpHourlyStats() {
	for {
		time.Sleep(time.Hour)
		et.mu.Lock()
		for _, stats := range et.endpoints {
			stats.LastHour = 0
		}
		et.mu.Unlock()
	}
}
