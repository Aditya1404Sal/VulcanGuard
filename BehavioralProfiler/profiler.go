package profiler

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"sync"
	"time"
)

// IPProfile represents behavioral characteristics of an IP address
type IPProfile struct {
	IP                    string           `json:"ip"`
	FirstSeen             time.Time        `json:"first_seen"`
	LastSeen              time.Time        `json:"last_seen"`
	TotalRequests         int              `json:"total_requests"`
	RequestFrequency      float64          `json:"request_frequency"` // requests per minute
	EndpointAccess        map[string]int   `json:"endpoint_access"`
	UserAgents            map[string]int   `json:"user_agents"`
	GeolocationData       *GeolocationInfo `json:"geolocation_data"`
	RequestPatterns       []RequestPattern `json:"request_patterns"`
	SuspiciousScore       float64          `json:"suspicious_score"`
	AttackVectors         []string         `json:"attack_vectors"`
	BehavioralFingerprint string           `json:"behavioral_fingerprint"`
	CreatedAt             time.Time        `json:"created_at"`
	UpdatedAt             time.Time        `json:"updated_at"`
}

type GeolocationInfo struct {
	Country   string  `json:"country"`
	Region    string  `json:"region"`
	City      string  `json:"city"`
	ISP       string  `json:"isp"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	Timezone  string  `json:"timezone"`
	Mobile    bool    `json:"mobile"`
	Proxy     bool    `json:"proxy"`
	Hosting   bool    `json:"hosting"`
}

type RequestPattern struct {
	IP            string    `json:"ip"` // Add IP field
	Timestamp     time.Time `json:"timestamp"`
	Endpoint      string    `json:"endpoint"`
	Method        string    `json:"method"`
	StatusCode    int       `json:"status_code"`
	ResponseTime  int64     `json:"response_time"` // in milliseconds
	UserAgent     string    `json:"user_agent"`
	Referer       string    `json:"referer"`
	ContentLength int64     `json:"content_length"`
}

// BehavioralProfiler manages IP behavioral analysis
type BehavioralProfiler struct {
	profiles            map[string]*IPProfile
	globalBlacklist     map[string]bool
	similarityThreshold float64
	maxProfileAge       time.Duration
	mu                  sync.RWMutex
	analysisQueue       chan *RequestPattern
	profileUpdateCh     chan string
	blacklistCh         chan string
}

// NewBehavioralProfiler creates a new behavioral profiler
func NewBehavioralProfiler(blacklistCh chan string) *BehavioralProfiler {
	bp := &BehavioralProfiler{
		profiles:            make(map[string]*IPProfile),
		globalBlacklist:     make(map[string]bool),
		similarityThreshold: 0.85, // 85% similarity threshold
		maxProfileAge:       24 * time.Hour,
		analysisQueue:       make(chan *RequestPattern, 1000),
		profileUpdateCh:     make(chan string, 100),
		blacklistCh:         blacklistCh,
	}

	// Start background workers
	go bp.profileAnalysisWorker()
	go bp.cleanupWorker()
	go bp.similarityAnalysisWorker()

	return bp
}

// AnalyzeRequest adds a request to the analysis queue
func (bp *BehavioralProfiler) AnalyzeRequest(ip, endpoint, method, userAgent, referer string, statusCode int, responseTime int64, contentLength int64) {
	pattern := &RequestPattern{
		IP:            ip, // Include IP in the pattern
		Timestamp:     time.Now(),
		Endpoint:      endpoint,
		Method:        method,
		StatusCode:    statusCode,
		ResponseTime:  responseTime,
		UserAgent:     userAgent,
		Referer:       referer,
		ContentLength: contentLength,
	}

	// Non-blocking send to analysis queue
	select {
	case bp.analysisQueue <- pattern:
		// Request queued for analysis
	default:
		log.Printf("Analysis queue full, dropping request from IP: %s", ip)
	}
}

// profileAnalysisWorker processes requests from the analysis queue
func (bp *BehavioralProfiler) profileAnalysisWorker() {
	for pattern := range bp.analysisQueue {
		bp.updateProfile(pattern)
	}
}

// updateProfile updates or creates an IP profile
func (bp *BehavioralProfiler) updateProfile(pattern *RequestPattern) {
	ip := extractIPFromPattern(pattern)

	bp.mu.Lock()
	defer bp.mu.Unlock()

	profile, exists := bp.profiles[ip]
	if !exists {
		profile = &IPProfile{
			IP:              ip,
			FirstSeen:       pattern.Timestamp,
			EndpointAccess:  make(map[string]int),
			UserAgents:      make(map[string]int),
			RequestPatterns: make([]RequestPattern, 0),
			AttackVectors:   make([]string, 0),
			CreatedAt:       time.Now(),
		}
		bp.profiles[ip] = profile

		// Fetch geolocation data for new IPs
		go bp.fetchGeolocationData(ip)
	}

	// Update profile data
	profile.LastSeen = pattern.Timestamp
	profile.TotalRequests++
	profile.EndpointAccess[pattern.Endpoint]++
	profile.UserAgents[pattern.UserAgent]++
	profile.RequestPatterns = append(profile.RequestPatterns, *pattern)
	profile.UpdatedAt = time.Now()

	// Keep only recent patterns (last 1000 requests or 1 hour)
	if len(profile.RequestPatterns) > 1000 {
		profile.RequestPatterns = profile.RequestPatterns[len(profile.RequestPatterns)-1000:]
	}

	// Calculate request frequency
	timeDiff := profile.LastSeen.Sub(profile.FirstSeen).Minutes()
	if timeDiff > 0 {
		profile.RequestFrequency = float64(profile.TotalRequests) / timeDiff
	}

	// Update behavioral fingerprint
	profile.BehavioralFingerprint = bp.generateBehavioralFingerprint(profile)

	// Calculate suspicious score
	profile.SuspiciousScore = bp.calculateSuspiciousScore(profile)

	// Check if profile should be blacklisted
	if profile.SuspiciousScore > 8.0 { // Threshold for immediate blacklisting
		bp.blacklistIP(ip, "High suspicious score")
	}

	// Queue for similarity analysis
	select {
	case bp.profileUpdateCh <- ip:
	default:
		// Channel full, skip similarity analysis for this update
	}
}

// fetchGeolocationData fetches geolocation information for an IP
func (bp *BehavioralProfiler) fetchGeolocationData(ip string) {
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,message,country,regionName,city,isp,lat,lon,timezone,mobile,proxy,hosting", ip)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		log.Printf("Failed to fetch geolocation for IP %s: %v", ip, err)
		return
	}
	defer resp.Body.Close()

	var geoData struct {
		Status     string  `json:"status"`
		Country    string  `json:"country"`
		RegionName string  `json:"regionName"`
		City       string  `json:"city"`
		ISP        string  `json:"isp"`
		Lat        float64 `json:"lat"`
		Lon        float64 `json:"lon"`
		Timezone   string  `json:"timezone"`
		Mobile     bool    `json:"mobile"`
		Proxy      bool    `json:"proxy"`
		Hosting    bool    `json:"hosting"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&geoData); err != nil {
		log.Printf("Failed to decode geolocation data for IP %s: %v", ip, err)
		return
	}

	if geoData.Status != "success" {
		return
	}

	bp.mu.Lock()
	defer bp.mu.Unlock()

	if profile, exists := bp.profiles[ip]; exists {
		profile.GeolocationData = &GeolocationInfo{
			Country:   geoData.Country,
			Region:    geoData.RegionName,
			City:      geoData.City,
			ISP:       geoData.ISP,
			Latitude:  geoData.Lat,
			Longitude: geoData.Lon,
			Timezone:  geoData.Timezone,
			Mobile:    geoData.Mobile,
			Proxy:     geoData.Proxy,
			Hosting:   geoData.Hosting,
		}

		// Update suspicious score based on geolocation
		if geoData.Proxy || geoData.Hosting {
			profile.SuspiciousScore += 2.0
		}
	}
}

// generateBehavioralFingerprint creates a unique fingerprint for behavioral patterns
func (bp *BehavioralProfiler) generateBehavioralFingerprint(profile *IPProfile) string {
	// Create a fingerprint based on behavior patterns
	fingerprint := fmt.Sprintf("freq:%.2f|", profile.RequestFrequency)

	// Add most accessed endpoints
	for endpoint, count := range profile.EndpointAccess {
		if count > 5 { // Only include frequently accessed endpoints
			fingerprint += fmt.Sprintf("ep:%s:%d|", endpoint, count)
		}
	}

	// Add user agents
	for ua, count := range profile.UserAgents {
		if count > 3 {
			fingerprint += fmt.Sprintf("ua:%s:%d|", ua[:min(20, len(ua))], count)
		}
	}

	// Add geolocation if available
	if profile.GeolocationData != nil {
		fingerprint += fmt.Sprintf("geo:%s:%s|", profile.GeolocationData.Country, profile.GeolocationData.ISP)
	}

	return fingerprint
}

// calculateSuspiciousScore calculates a suspicious score for an IP profile
func (bp *BehavioralProfiler) calculateSuspiciousScore(profile *IPProfile) float64 {
	score := 0.0

	// High request frequency (more than 10 requests per minute)
	if profile.RequestFrequency > 10 {
		score += 3.0
	} else if profile.RequestFrequency > 5 {
		score += 1.5
	}

	// Accessing too many different endpoints
	if len(profile.EndpointAccess) > 20 {
		score += 2.0
	}

	// Multiple user agents (bot-like behavior)
	if len(profile.UserAgents) > 5 {
		score += 2.5
	}

	// Geolocation-based scoring
	if profile.GeolocationData != nil {
		if profile.GeolocationData.Proxy {
			score += 2.0
		}
		if profile.GeolocationData.Hosting {
			score += 1.5
		}
	}

	// Pattern analysis - check for regular intervals (bot-like)
	if bp.hasRegularIntervals(profile.RequestPatterns) {
		score += 3.0
	}

	// High error rate
	errorRate := bp.calculateErrorRate(profile.RequestPatterns)
	if errorRate > 0.5 {
		score += 2.0
	} else if errorRate > 0.3 {
		score += 1.0
	}

	return score
}

// hasRegularIntervals checks if requests come at suspiciously regular intervals
func (bp *BehavioralProfiler) hasRegularIntervals(patterns []RequestPattern) bool {
	if len(patterns) < 10 {
		return false
	}

	intervals := make([]float64, 0, len(patterns)-1)
	for i := 1; i < len(patterns); i++ {
		interval := patterns[i].Timestamp.Sub(patterns[i-1].Timestamp).Seconds()
		intervals = append(intervals, interval)
	}

	// Calculate variance of intervals
	mean := 0.0
	for _, interval := range intervals {
		mean += interval
	}
	mean /= float64(len(intervals))

	variance := 0.0
	for _, interval := range intervals {
		variance += math.Pow(interval-mean, 2)
	}
	variance /= float64(len(intervals))

	// Low variance indicates regular intervals (suspicious)
	return variance < 1.0 && mean < 10.0 // Less than 1 second variance and avg 10 sec intervals
}

// calculateErrorRate calculates the error rate from request patterns
func (bp *BehavioralProfiler) calculateErrorRate(patterns []RequestPattern) float64 {
	if len(patterns) == 0 {
		return 0.0
	}

	errorCount := 0
	for _, pattern := range patterns {
		if pattern.StatusCode >= 400 {
			errorCount++
		}
	}

	return float64(errorCount) / float64(len(patterns))
}

// similarityAnalysisWorker analyzes profile similarities
func (bp *BehavioralProfiler) similarityAnalysisWorker() {
	for ip := range bp.profileUpdateCh {
		bp.analyzeSimilarProfiles(ip)
	}
}

// analyzeSimilarProfiles finds and analyzes similar behavioral profiles
func (bp *BehavioralProfiler) analyzeSimilarProfiles(targetIP string) {
	bp.mu.RLock()
	targetProfile, exists := bp.profiles[targetIP]
	if !exists {
		bp.mu.RUnlock()
		return
	}

	similarProfiles := make([]*IPProfile, 0)
	for ip, profile := range bp.profiles {
		if ip != targetIP {
			similarity := bp.calculateSimilarity(targetProfile, profile)
			if similarity > bp.similarityThreshold {
				similarProfiles = append(similarProfiles, profile)
			}
		}
	}
	bp.mu.RUnlock()

	// If we found many similar profiles, it might be a coordinated attack
	if len(similarProfiles) > 5 {
		log.Printf("Detected %d similar profiles to IP %s - potential coordinated attack", len(similarProfiles), targetIP)

		// Blacklist all similar IPs
		for _, profile := range similarProfiles {
			bp.blacklistIP(profile.IP, fmt.Sprintf("Similar behavior to suspicious IP %s", targetIP))
		}
		bp.blacklistIP(targetIP, "Part of coordinated attack pattern")
	}
}

// calculateSimilarity calculates behavioral similarity between two profiles
func (bp *BehavioralProfiler) calculateSimilarity(profile1, profile2 *IPProfile) float64 {
	similarity := 0.0
	factors := 0.0

	// Request frequency similarity
	if profile1.RequestFrequency > 0 && profile2.RequestFrequency > 0 {
		freqSim := 1.0 - math.Abs(profile1.RequestFrequency-profile2.RequestFrequency)/math.Max(profile1.RequestFrequency, profile2.RequestFrequency)
		similarity += freqSim * 0.3
		factors += 0.3
	}

	// Endpoint access pattern similarity
	endpointSim := bp.calculateEndpointSimilarity(profile1.EndpointAccess, profile2.EndpointAccess)
	similarity += endpointSim * 0.4
	factors += 0.4

	// User agent similarity
	uaSim := bp.calculateUserAgentSimilarity(profile1.UserAgents, profile2.UserAgents)
	similarity += uaSim * 0.2
	factors += 0.2

	// Geolocation similarity
	if profile1.GeolocationData != nil && profile2.GeolocationData != nil {
		geoSim := bp.calculateGeolocationSimilarity(profile1.GeolocationData, profile2.GeolocationData)
		similarity += geoSim * 0.1
		factors += 0.1
	}

	if factors > 0 {
		return similarity / factors
	}
	return 0.0
}

// calculateEndpointSimilarity calculates similarity in endpoint access patterns
func (bp *BehavioralProfiler) calculateEndpointSimilarity(endpoints1, endpoints2 map[string]int) float64 {
	if len(endpoints1) == 0 && len(endpoints2) == 0 {
		return 1.0
	}
	if len(endpoints1) == 0 || len(endpoints2) == 0 {
		return 0.0
	}

	commonEndpoints := 0
	totalEndpoints := make(map[string]bool)

	for endpoint := range endpoints1 {
		totalEndpoints[endpoint] = true
		if _, exists := endpoints2[endpoint]; exists {
			commonEndpoints++
		}
	}

	for endpoint := range endpoints2 {
		totalEndpoints[endpoint] = true
	}

	return float64(commonEndpoints) / float64(len(totalEndpoints))
}

// calculateUserAgentSimilarity calculates similarity in user agent patterns
func (bp *BehavioralProfiler) calculateUserAgentSimilarity(ua1, ua2 map[string]int) float64 {
	if len(ua1) == 0 && len(ua2) == 0 {
		return 1.0
	}
	if len(ua1) == 0 || len(ua2) == 0 {
		return 0.0
	}

	commonUA := 0
	totalUA := make(map[string]bool)

	for ua := range ua1 {
		totalUA[ua] = true
		if _, exists := ua2[ua]; exists {
			commonUA++
		}
	}

	for ua := range ua2 {
		totalUA[ua] = true
	}

	return float64(commonUA) / float64(len(totalUA))
}

// calculateGeolocationSimilarity calculates similarity in geolocation data
func (bp *BehavioralProfiler) calculateGeolocationSimilarity(geo1, geo2 *GeolocationInfo) float64 {
	similarity := 0.0
	factors := 0.0

	// Country similarity
	if geo1.Country == geo2.Country {
		similarity += 0.4
	}
	factors += 0.4

	// ISP similarity
	if geo1.ISP == geo2.ISP {
		similarity += 0.3
	}
	factors += 0.3

	// Proxy/Hosting similarity
	if geo1.Proxy == geo2.Proxy && geo1.Hosting == geo2.Hosting {
		similarity += 0.3
	}
	factors += 0.3

	return similarity / factors
}

// blacklistIP adds an IP to the global blacklist
func (bp *BehavioralProfiler) blacklistIP(ip, reason string) {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	if !bp.globalBlacklist[ip] {
		bp.globalBlacklist[ip] = true
		log.Printf("IP %s blacklisted by behavioral profiler: %s", ip, reason)

		// Send to main blacklist channel
		select {
		case bp.blacklistCh <- ip:
		default:
			log.Printf("Blacklist channel full, failed to blacklist IP: %s", ip)
		}

		// Update profile with attack vector
		if profile, exists := bp.profiles[ip]; exists {
			profile.AttackVectors = append(profile.AttackVectors, reason)
		}
	}
}

// IsBlacklisted checks if an IP is in the global blacklist
func (bp *BehavioralProfiler) IsBlacklisted(ip string) bool {
	bp.mu.RLock()
	defer bp.mu.RUnlock()
	return bp.globalBlacklist[ip]
}

// GetProfile returns the profile for an IP
func (bp *BehavioralProfiler) GetProfile(ip string) (*IPProfile, bool) {
	bp.mu.RLock()
	defer bp.mu.RUnlock()

	profile, exists := bp.profiles[ip]
	return profile, exists
}

// GetProfiles returns all IP profiles (for dashboard API)
func (bp *BehavioralProfiler) GetProfiles() map[string]*IPProfile {
	bp.mu.RLock()
	defer bp.mu.RUnlock()

	// Create a copy to avoid race conditions
	profiles := make(map[string]*IPProfile)
	for ip, profile := range bp.profiles {
		profiles[ip] = profile
	}
	return profiles
}

// cleanupWorker removes old profiles
func (bp *BehavioralProfiler) cleanupWorker() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		bp.cleanupOldProfiles()
	}
}

// cleanupOldProfiles removes profiles older than maxProfileAge
func (bp *BehavioralProfiler) cleanupOldProfiles() {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	now := time.Now()
	for ip, profile := range bp.profiles {
		if now.Sub(profile.LastSeen) > bp.maxProfileAge {
			delete(bp.profiles, ip)
			delete(bp.globalBlacklist, ip)
			log.Printf("Cleaned up old profile for IP: %s", ip)
		}
	}
}

// Helper functions
func extractIPFromPattern(pattern *RequestPattern) string {
	// Return the IP field from the RequestPattern struct
	return pattern.IP
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
