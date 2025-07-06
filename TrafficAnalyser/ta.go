package trafan

import (
	"fmt"
	"log"
	"math"
	"sort"
	"sync"
	"time"
)

type TrafficAnalyser struct {
	// Existing fields
	attackTimes             map[string][]time.Time
	detectedAttackTypes     map[string]bool
	endpointMaptoAttackType map[string]string
	detectionDuration       time.Duration
	maxRequests             int
	mu                      sync.Mutex
	trackerMaps             map[string]*trafficTracker

	// New fields for enhanced analysis
	endpointBaselines map[string]*EndpointBaseline
	trafficPatterns   map[string]*TrafficPattern
	anomalyThresholds *AnomalyThresholds
	alertChannel      chan Alert
	globalStats       *GlobalTrafficStats
	analysisQueue     chan *TrafficEvent
	isRunning         bool
}

type trafficTracker struct {
	endpoint            string
	totalRequestsCount  int
	ipMaptoRequestCount map[string]int
	// Enhanced tracking
	hourlyStats  map[int]*HourlyStats
	lastAnalysis time.Time
	peakTraffic  int
	avgTraffic   float64
}

// New types for enhanced functionality
type EndpointBaseline struct {
	Endpoint             string
	NormalRequestsPerMin float64
	StdDeviation         float64
	PeakHours            []int
	TypicalUserAgents    map[string]int
	AvgResponseSize      float64
	ErrorRate            float64
	LastUpdated          time.Time
}

type TrafficPattern struct {
	IP                  string
	RequestsPerInterval []int
	IntervalDuration    time.Duration
	PatternScore        float64 // 0-1, higher means more suspicious
	IsRegularPattern    bool
	LastDetection       time.Time
}

type AnomalyThresholds struct {
	SpikeMultiplier        float64 // How many times normal traffic constitutes a spike
	PatternSimilarity      float64 // Threshold for detecting similar patterns
	MinRequestsForBaseline int
	BaselineWindow         time.Duration
	AlertCooldown          time.Duration
}

type HourlyStats struct {
	Hour         int
	RequestCount int
	UniqueIPs    map[string]bool
	ErrorCount   int
	AvgResponse  float64
}

type GlobalTrafficStats struct {
	TotalRequests      int64
	UniqueIPs          int
	TopEndpoints       map[string]int
	TrafficByHour      [24]int
	AverageRequestRate float64
	LastReset          time.Time
}

type TrafficEvent struct {
	IP            string
	Endpoint      string
	Timestamp     time.Time
	UserAgent     string
	StatusCode    int
	ResponseTime  int64
	ContentLength int64
	Method        string
}

type Alert struct {
	Type      string
	Severity  string
	IP        string
	Endpoint  string
	Message   string
	Timestamp time.Time
	Data      map[string]interface{}
}

func NewTrafficAnalyser(detectionDuration time.Duration, maxRequests int, alertChannel chan Alert) *TrafficAnalyser {
	ta := &TrafficAnalyser{
		// Existing initialization
		attackTimes:             make(map[string][]time.Time),
		detectedAttackTypes:     make(map[string]bool),
		endpointMaptoAttackType: make(map[string]string),
		detectionDuration:       detectionDuration,
		maxRequests:             maxRequests,
		trackerMaps:             make(map[string]*trafficTracker),

		// New initialization
		endpointBaselines: make(map[string]*EndpointBaseline),
		trafficPatterns:   make(map[string]*TrafficPattern),
		alertChannel:      alertChannel,
		analysisQueue:     make(chan *TrafficEvent, 10000),
		globalStats: &GlobalTrafficStats{
			TopEndpoints: make(map[string]int),
			LastReset:    time.Now(),
		},
		anomalyThresholds: &AnomalyThresholds{
			SpikeMultiplier:        3.0,
			PatternSimilarity:      0.8,
			MinRequestsForBaseline: 100,
			BaselineWindow:         24 * time.Hour,
			AlertCooldown:          5 * time.Minute,
		},
		isRunning: true,
	}

	// Start background workers
	go ta.eventProcessor()
	go ta.baselineUpdater()
	go ta.patternAnalyzer()
	go ta.anomalyDetector()

	return ta
}

func NewTrafficTracker(endpoint string) *trafficTracker {
	return &trafficTracker{
		endpoint:            endpoint,
		totalRequestsCount:  0,
		ipMaptoRequestCount: make(map[string]int),
		hourlyStats:         make(map[int]*HourlyStats),
		lastAnalysis:        time.Now(),
	}
}

// ProcessRequest processes a new request and adds it to analysis
func (ta *TrafficAnalyser) ProcessRequest(ip, endpoint, userAgent, method string, statusCode int, responseTime, contentLength int64) {
	event := &TrafficEvent{
		IP:            ip,
		Endpoint:      endpoint,
		Timestamp:     time.Now(),
		UserAgent:     userAgent,
		StatusCode:    statusCode,
		ResponseTime:  responseTime,
		ContentLength: contentLength,
		Method:        method,
	}

	// Non-blocking send to analysis queue
	select {
	case ta.analysisQueue <- event:
	default:
		log.Printf("Traffic analysis queue full, dropping event from IP: %s", ip)
	}
}

// eventProcessor processes traffic events from the queue
func (ta *TrafficAnalyser) eventProcessor() {
	for ta.isRunning {
		select {
		case event := <-ta.analysisQueue:
			ta.processTrafficEvent(event)
		case <-time.After(100 * time.Millisecond):
			// Timeout to check isRunning periodically
		}
	}
}

// processTrafficEvent processes individual traffic events
func (ta *TrafficAnalyser) processTrafficEvent(event *TrafficEvent) {
	ta.mu.Lock()
	defer ta.mu.Unlock()

	// Update tracker
	tracker, exists := ta.trackerMaps[event.Endpoint]
	if !exists {
		tracker = NewTrafficTracker(event.Endpoint)
		ta.trackerMaps[event.Endpoint] = tracker
	}

	tracker.totalRequestsCount++
	tracker.ipMaptoRequestCount[event.IP]++

	// Update hourly stats
	hour := event.Timestamp.Hour()
	if tracker.hourlyStats[hour] == nil {
		tracker.hourlyStats[hour] = &HourlyStats{
			Hour:      hour,
			UniqueIPs: make(map[string]bool),
		}
	}

	hourlyStats := tracker.hourlyStats[hour]
	hourlyStats.RequestCount++
	hourlyStats.UniqueIPs[event.IP] = true
	if event.StatusCode >= 400 {
		hourlyStats.ErrorCount++
	}

	// Update global stats
	ta.globalStats.TotalRequests++
	ta.globalStats.TopEndpoints[event.Endpoint]++
	ta.globalStats.TrafficByHour[hour]++

	// Update traffic pattern for IP
	ta.updateTrafficPattern(event.IP, event.Timestamp)

	// Immediate spike detection
	ta.detectImmediateSpike(event.Endpoint, tracker)
}

// updateTrafficPattern updates traffic patterns for an IP
func (ta *TrafficAnalyser) updateTrafficPattern(ip string, timestamp time.Time) {
	pattern, exists := ta.trafficPatterns[ip]
	if !exists {
		pattern = &TrafficPattern{
			IP:                  ip,
			RequestsPerInterval: make([]int, 0),
			IntervalDuration:    time.Minute,
			LastDetection:       timestamp,
		}
		ta.trafficPatterns[ip] = pattern
	}

	// Update pattern intervals (track requests per minute)
	minute := timestamp.Truncate(time.Minute)
	lastMinute := pattern.LastDetection.Truncate(time.Minute)

	if minute.Equal(lastMinute) {
		// Same minute, increment current interval
		if len(pattern.RequestsPerInterval) == 0 {
			pattern.RequestsPerInterval = append(pattern.RequestsPerInterval, 1)
		} else {
			pattern.RequestsPerInterval[len(pattern.RequestsPerInterval)-1]++
		}
	} else {
		// New minute, add new interval
		pattern.RequestsPerInterval = append(pattern.RequestsPerInterval, 1)

		// Keep only last 60 minutes
		if len(pattern.RequestsPerInterval) > 60 {
			pattern.RequestsPerInterval = pattern.RequestsPerInterval[1:]
		}
	}

	pattern.LastDetection = timestamp
	pattern.PatternScore = ta.calculatePatternScore(pattern.RequestsPerInterval)
	pattern.IsRegularPattern = ta.isRegularPattern(pattern.RequestsPerInterval)
}

// detectImmediateSpike detects sudden traffic spikes
func (ta *TrafficAnalyser) detectImmediateSpike(endpoint string, tracker *trafficTracker) {
	baseline, exists := ta.endpointBaselines[endpoint]
	if !exists || tracker.totalRequestsCount < ta.anomalyThresholds.MinRequestsForBaseline {
		return
	}

	// Calculate current request rate (requests per minute)
	now := time.Now()
	minuteAgo := now.Add(-time.Minute)

	recentRequests := 0
	for _, times := range ta.attackTimes {
		for _, t := range times {
			if t.After(minuteAgo) && t.Before(now) {
				recentRequests++
			}
		}
	}

	currentRate := float64(recentRequests)
	expectedRate := baseline.NormalRequestsPerMin
	threshold := expectedRate * ta.anomalyThresholds.SpikeMultiplier

	if currentRate > threshold {
		alert := Alert{
			Type:      "traffic_spike",
			Severity:  "high",
			Endpoint:  endpoint,
			Message:   fmt.Sprintf("Traffic spike detected: %.2f req/min (expected: %.2f)", currentRate, expectedRate),
			Timestamp: now,
			Data: map[string]interface{}{
				"current_rate":  currentRate,
				"expected_rate": expectedRate,
				"threshold":     threshold,
			},
		}

		ta.sendAlert(alert)
	}
}

// calculatePatternScore calculates how suspicious a traffic pattern is
func (ta *TrafficAnalyser) calculatePatternScore(intervals []int) float64 {
	if len(intervals) < 5 {
		return 0.0
	}

	// Calculate coefficient of variation (CV = std dev / mean)
	mean := 0.0
	for _, count := range intervals {
		mean += float64(count)
	}
	mean /= float64(len(intervals))

	if mean == 0 {
		return 0.0
	}

	variance := 0.0
	for _, count := range intervals {
		variance += math.Pow(float64(count)-mean, 2)
	}
	variance /= float64(len(intervals))
	stdDev := math.Sqrt(variance)

	cv := stdDev / mean

	// Low CV indicates regular pattern (suspicious)
	// High mean with low CV is very suspicious
	suspiciousScore := (mean / 10.0) * (1.0 - cv)

	if suspiciousScore > 1.0 {
		return 1.0
	}
	return suspiciousScore
}

// isRegularPattern determines if a pattern shows regular intervals
func (ta *TrafficAnalyser) isRegularPattern(intervals []int) bool {
	if len(intervals) < 10 {
		return false
	}

	// Check for repeating patterns
	for patternLength := 2; patternLength <= len(intervals)/3; patternLength++ {
		if ta.hasRepeatingPattern(intervals, patternLength) {
			return true
		}
	}

	return false
}

// hasRepeatingPattern checks if intervals have a repeating pattern of given length
func (ta *TrafficAnalyser) hasRepeatingPattern(intervals []int, patternLength int) bool {
	if len(intervals) < patternLength*3 {
		return false
	}

	pattern := intervals[:patternLength]
	matches := 0
	totalChecks := 0

	for i := patternLength; i+patternLength <= len(intervals); i += patternLength {
		totalChecks++
		segment := intervals[i : i+patternLength]

		if ta.arraysEqual(pattern, segment) {
			matches++
		}
	}

	// If 70% or more segments match the pattern, consider it repeating
	return float64(matches)/float64(totalChecks) >= 0.7
}

// arraysEqual checks if two integer arrays are equal
func (ta *TrafficAnalyser) arraysEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// baselineUpdater updates endpoint baselines periodically
func (ta *TrafficAnalyser) baselineUpdater() {
	ticker := time.NewTicker(ta.anomalyThresholds.BaselineWindow / 24) // Update baselines hourly
	defer ticker.Stop()

	for ta.isRunning {
		select {
		case <-ticker.C:
			ta.updateBaselines()
		case <-time.After(100 * time.Millisecond):
			// Check isRunning periodically
		}
	}
}

// updateBaselines updates traffic baselines for all endpoints
func (ta *TrafficAnalyser) updateBaselines() {
	ta.mu.Lock()
	defer ta.mu.Unlock()

	for endpoint, tracker := range ta.trackerMaps {
		if tracker.totalRequestsCount < ta.anomalyThresholds.MinRequestsForBaseline {
			continue
		}

		baseline := ta.endpointBaselines[endpoint]
		if baseline == nil {
			baseline = &EndpointBaseline{
				Endpoint:          endpoint,
				TypicalUserAgents: make(map[string]int),
			}
			ta.endpointBaselines[endpoint] = baseline
		}

		// Calculate statistics from hourly data
		requestsPerHour := make([]float64, 0)
		peakHours := make([]int, 0)

		for hour, stats := range tracker.hourlyStats {
			if stats.RequestCount > 0 {
				requestsPerHour = append(requestsPerHour, float64(stats.RequestCount)/60.0) // requests per minute

				// Identify peak hours (above average)
				if float64(stats.RequestCount) > tracker.avgTraffic*1.5 {
					peakHours = append(peakHours, hour)
				}
			}
		}

		if len(requestsPerHour) > 0 {
			// Calculate mean and standard deviation
			sum := 0.0
			for _, rate := range requestsPerHour {
				sum += rate
			}
			baseline.NormalRequestsPerMin = sum / float64(len(requestsPerHour))

			variance := 0.0
			for _, rate := range requestsPerHour {
				variance += math.Pow(rate-baseline.NormalRequestsPerMin, 2)
			}
			baseline.StdDeviation = math.Sqrt(variance / float64(len(requestsPerHour)))
			baseline.PeakHours = peakHours
			baseline.LastUpdated = time.Now()
		}
	}
}

// patternAnalyzer analyzes traffic patterns for coordinated attacks
func (ta *TrafficAnalyser) patternAnalyzer() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for ta.isRunning {
		select {
		case <-ticker.C:
			ta.analyzeCoordinatedPatterns()
		case <-time.After(100 * time.Millisecond):
			// Check isRunning periodically
		}
	}
}

// analyzeCoordinatedPatterns detects coordinated attack patterns
func (ta *TrafficAnalyser) analyzeCoordinatedPatterns() {
	ta.mu.Lock()
	defer ta.mu.Unlock()

	suspiciousPatterns := make([]*TrafficPattern, 0)

	// Find suspicious patterns
	for _, pattern := range ta.trafficPatterns {
		if pattern.PatternScore > 0.7 || pattern.IsRegularPattern {
			suspiciousPatterns = append(suspiciousPatterns, pattern)
		}
	}

	// Group similar patterns
	groups := ta.groupSimilarPatterns(suspiciousPatterns)

	// Alert on large coordinated groups
	for _, group := range groups {
		if len(group) >= 5 { // 5 or more IPs with similar patterns
			alert := Alert{
				Type:      "coordinated_attack",
				Severity:  "critical",
				Message:   fmt.Sprintf("Coordinated attack detected: %d IPs with similar patterns", len(group)),
				Timestamp: time.Now(),
				Data: map[string]interface{}{
					"ip_count": len(group),
					"ips":      ta.extractIPsFromPatterns(group),
				},
			}
			ta.sendAlert(alert)
		}
	}
}

// groupSimilarPatterns groups traffic patterns by similarity
func (ta *TrafficAnalyser) groupSimilarPatterns(patterns []*TrafficPattern) [][]*TrafficPattern {
	groups := make([][]*TrafficPattern, 0)
	used := make(map[int]bool)

	for i, pattern1 := range patterns {
		if used[i] {
			continue
		}

		group := []*TrafficPattern{pattern1}
		used[i] = true

		for j, pattern2 := range patterns {
			if i != j && !used[j] {
				similarity := ta.calculatePatternSimilarity(pattern1, pattern2)
				if similarity > ta.anomalyThresholds.PatternSimilarity {
					group = append(group, pattern2)
					used[j] = true
				}
			}
		}

		if len(group) > 1 {
			groups = append(groups, group)
		}
	}

	return groups
}

// calculatePatternSimilarity calculates similarity between two traffic patterns
func (ta *TrafficAnalyser) calculatePatternSimilarity(p1, p2 *TrafficPattern) float64 {
	if len(p1.RequestsPerInterval) == 0 || len(p2.RequestsPerInterval) == 0 {
		return 0.0
	}

	// Normalize lengths
	minLen := len(p1.RequestsPerInterval)
	if len(p2.RequestsPerInterval) < minLen {
		minLen = len(p2.RequestsPerInterval)
	}

	if minLen < 5 {
		return 0.0
	}

	// Calculate correlation coefficient
	pattern1 := p1.RequestsPerInterval[:minLen]
	pattern2 := p2.RequestsPerInterval[:minLen]

	return ta.calculateCorrelation(pattern1, pattern2)
}

// calculateCorrelation calculates Pearson correlation coefficient
func (ta *TrafficAnalyser) calculateCorrelation(x, y []int) float64 {
	n := float64(len(x))
	if n == 0 {
		return 0.0
	}

	// Calculate means
	meanX, meanY := 0.0, 0.0
	for i := 0; i < len(x); i++ {
		meanX += float64(x[i])
		meanY += float64(y[i])
	}
	meanX /= n
	meanY /= n

	// Calculate correlation components
	numerator := 0.0
	sumX2 := 0.0
	sumY2 := 0.0

	for i := 0; i < len(x); i++ {
		dx := float64(x[i]) - meanX
		dy := float64(y[i]) - meanY
		numerator += dx * dy
		sumX2 += dx * dx
		sumY2 += dy * dy
	}

	denominator := math.Sqrt(sumX2 * sumY2)
	if denominator == 0 {
		return 0.0
	}

	return math.Abs(numerator / denominator) // Use absolute value
}

// extractIPsFromPatterns extracts IP addresses from traffic patterns
func (ta *TrafficAnalyser) extractIPsFromPatterns(patterns []*TrafficPattern) []string {
	ips := make([]string, len(patterns))
	for i, pattern := range patterns {
		ips[i] = pattern.IP
	}
	return ips
}

// anomalyDetector detects various traffic anomalies
func (ta *TrafficAnalyser) anomalyDetector() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for ta.isRunning {
		select {
		case <-ticker.C:
			ta.detectAnomalies()
		case <-time.After(100 * time.Millisecond):
			// Check isRunning periodically
		}
	}
}

// detectAnomalies detects various types of traffic anomalies
func (ta *TrafficAnalyser) detectAnomalies() {
	ta.mu.Lock()
	defer ta.mu.Unlock()

	now := time.Now()

	// Detect odd hour traffic patterns
	ta.detectOddHourTraffic(now)

	// Detect endpoint abuse
	ta.detectEndpointAbuse()

	// Detect geographical anomalies
	ta.detectGeographicalAnomalies()
}

// detectOddHourTraffic detects traffic at unusual hours
func (ta *TrafficAnalyser) detectOddHourTraffic(now time.Time) {
	currentHour := now.Hour()

	// Define odd hours (typically 2 AM - 6 AM)
	if currentHour >= 2 && currentHour <= 6 {
		currentTraffic := ta.globalStats.TrafficByHour[currentHour]

		// Compare with peak hours
		peakTraffic := 0
		for hour := 9; hour <= 17; hour++ { // Business hours
			if ta.globalStats.TrafficByHour[hour] > peakTraffic {
				peakTraffic = ta.globalStats.TrafficByHour[hour]
			}
		}

		// If current odd hour traffic is more than 50% of peak, alert
		if float64(currentTraffic) > float64(peakTraffic)*0.5 {
			alert := Alert{
				Type:      "odd_hour_traffic",
				Severity:  "medium",
				Message:   fmt.Sprintf("Unusual traffic at %d:00 - %d requests (peak: %d)", currentHour, currentTraffic, peakTraffic),
				Timestamp: now,
				Data: map[string]interface{}{
					"hour":          currentHour,
					"current_count": currentTraffic,
					"peak_count":    peakTraffic,
				},
			}
			ta.sendAlert(alert)
		}
	}
}

// detectEndpointAbuse detects abuse of specific endpoints
func (ta *TrafficAnalyser) detectEndpointAbuse() {
	// Sort endpoints by traffic volume
	type endpointTraffic struct {
		endpoint string
		count    int
	}

	endpoints := make([]endpointTraffic, 0, len(ta.globalStats.TopEndpoints))
	totalTraffic := 0

	for endpoint, count := range ta.globalStats.TopEndpoints {
		endpoints = append(endpoints, endpointTraffic{endpoint, count})
		totalTraffic += count
	}

	sort.Slice(endpoints, func(i, j int) bool {
		return endpoints[i].count > endpoints[j].count
	})

	// Check if top endpoint has disproportionate traffic
	if len(endpoints) > 0 && totalTraffic > 0 {
		topEndpoint := endpoints[0]
		percentage := float64(topEndpoint.count) / float64(totalTraffic) * 100

		if percentage > 70.0 { // More than 70% of traffic to one endpoint
			alert := Alert{
				Type:      "endpoint_abuse",
				Severity:  "high",
				Endpoint:  topEndpoint.endpoint,
				Message:   fmt.Sprintf("Endpoint abuse detected: %.1f%% of traffic to %s", percentage, topEndpoint.endpoint),
				Timestamp: time.Now(),
				Data: map[string]interface{}{
					"percentage":     percentage,
					"request_count":  topEndpoint.count,
					"total_requests": totalTraffic,
				},
			}
			ta.sendAlert(alert)
		}
	}
}

// detectGeographicalAnomalies detects geographical traffic anomalies
func (ta *TrafficAnalyser) detectGeographicalAnomalies() {
	// This would require integration with the behavioral profiler
	// For now, we'll implement a placeholder
	log.Println("Geographical anomaly detection - integration with behavioral profiler needed")
}

// sendAlert sends an alert through the alert channel
func (ta *TrafficAnalyser) sendAlert(alert Alert) {
	select {
	case ta.alertChannel <- alert:
		log.Printf("Alert sent: %s - %s", alert.Type, alert.Message)
	default:
		log.Printf("Alert channel full, dropping alert: %s", alert.Message)
	}
}

// GetEndpointStats returns statistics for an endpoint
func (ta *TrafficAnalyser) GetEndpointStats(endpoint string) (*trafficTracker, bool) {
	ta.mu.Lock()
	defer ta.mu.Unlock()
	tracker, exists := ta.trackerMaps[endpoint]
	return tracker, exists
}

// GetGlobalStats returns global traffic statistics
func (ta *TrafficAnalyser) GetGlobalStats() *GlobalTrafficStats {
	ta.mu.Lock()
	defer ta.mu.Unlock()
	return ta.globalStats
}

// Stop stops the traffic analyzer
func (ta *TrafficAnalyser) Stop() {
	ta.isRunning = false
}
