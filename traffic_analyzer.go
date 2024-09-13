package main

import (
	"log"
	"math"
	"sync"
	"time"
)

type TrafficAnalyzer struct {
	trafficHistory []int
	mu             sync.Mutex
}

func NewTrafficAnalyzer() *TrafficAnalyzer {
	return &TrafficAnalyzer{
		trafficHistory: make([]int, 24*60), // Store last 24 hours of minute-by-minute data
	}
}

func (ta *TrafficAnalyzer) RecordTraffic(count int) {
	ta.mu.Lock()
	defer ta.mu.Unlock()

	copy(ta.trafficHistory[1:], ta.trafficHistory)
	ta.trafficHistory[0] = count
}

func (ta *TrafficAnalyzer) DetectOddPatterns() bool {
	ta.mu.Lock()
	defer ta.mu.Unlock()

	spikes := make([]int, 0)
	for i, count := range ta.trafficHistory[:60] {
		if i > 0 && count > ta.trafficHistory[i-1]*2 {
			spikes = append(spikes, i)
		}
	}

	if len(spikes) > 3 {
		intervals := make([]int, len(spikes)-1)
		for i := 1; i < len(spikes); i++ {
			intervals[i-1] = spikes[i] - spikes[i-1]
		}

		if hasConsistentIntervals(intervals) {
			return true // Odd pattern detected
		}
	}

	return false
}

func hasConsistentIntervals(intervals []int) bool {
	if len(intervals) < 2 {
		return false
	}

	sum := 0
	for _, interval := range intervals {
		sum += interval
	}
	mean := float64(sum) / float64(len(intervals))

	variance := 0.0
	for _, interval := range intervals {
		variance += math.Pow(float64(interval)-mean, 2)
	}
	variance /= float64(len(intervals))

	return math.Sqrt(variance) < mean*0.1
}

func (ta *TrafficAnalyzer) AnalyzeTraffic() {
	ticker := time.NewTicker(time.Minute)
	for range ticker.C {
		count := countRequestsLastMinute() // Implement this function
		ta.RecordTraffic(count)

		if ta.DetectOddPatterns() {
			// Take action, e.g., trigger an alert or increase monitoring
			// TODO: change ratelimit to some decreased value
			log.Println("Odd traffic pattern detected!")
		}
	}
}

func countRequestsLastMinute() int {
	// Implement this function to count requests in the last minute
	// This could involve maintaining a separate counter or analyzing logs
	return 0 // Placeholder return
}
