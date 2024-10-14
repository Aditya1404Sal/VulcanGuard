package trafan

import (
	"sync"
	"time"
)

type TrafficAnalyser struct {
	attackTimes             map[string][]time.Time
	detectedAttackTypes     map[string]bool
	endpointMaptoAttackType map[string]string
	detectionDuration       time.Duration
	maxRequests             int
	mu                      sync.Mutex
	trackerMaps             map[string]*trafficTracker
}

type trafficTracker struct {
	endpoint            string
	totalRequestsCount  int
	ipMaptoRequestCount map[string]int
}

func NewTrafficAnalyser(detectionDuration time.Duration, maxRequests int) *TrafficAnalyser {
	return &TrafficAnalyser{
		attackTimes:             make(map[string][]time.Time),
		detectedAttackTypes:     make(map[string]bool),
		endpointMaptoAttackType: make(map[string]string),
		detectionDuration:       detectionDuration,
		maxRequests:             maxRequests,
		trackerMaps:             make(map[string]*trafficTracker),
	}
}

func NewTrafficTracker(endpoint string) *trafficTracker {
	return &trafficTracker{
		endpoint:            endpoint,
		totalRequestsCount:  0,
		ipMaptoRequestCount: make(map[string]int),
	}
}
