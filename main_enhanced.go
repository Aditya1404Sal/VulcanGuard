package main

import (
	profiler "Suboptimal/Firewall/BehavioralProfiler"
	loadb "Suboptimal/Firewall/LoadB"
	p2p "Suboptimal/Firewall/P2P"
	trafan "Suboptimal/Firewall/TrafficAnalyser"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	rateLimit           = 20
	trackingDuration    = 20 * time.Second
	brownListedDuration = 25 * time.Second
)

type rateLimiter struct {
	requests    map[string][]time.Time
	blackList   map[string]bool
	brownList   map[string]time.Time
	mu          sync.Mutex
	blacklistCh chan string
	unblockCh   chan string
}

// EnhancedFirewall combines all protection mechanisms
type EnhancedFirewall struct {
	rateLimiter         *rateLimiter
	behavioralProfiler  *profiler.BehavioralProfiler
	trafficAnalyser     *trafan.TrafficAnalyser
	p2pNetwork          *p2p.P2PNetwork
	alertChannel        chan trafan.Alert
	intelligenceChannel chan *p2p.ThreatIntelligence
	blacklistCh         chan string
	unblockCh           chan string
}

func newRateLimiter(blacklistCh chan string, unblockCh chan string) *rateLimiter {
	rl := &rateLimiter{
		requests:    make(map[string][]time.Time),
		blackList:   make(map[string]bool),
		brownList:   make(map[string]time.Time),
		blacklistCh: blacklistCh,
		unblockCh:   unblockCh,
	}
	go rl.cleanUp()
	return rl
}

func NewEnhancedFirewall(nodeID string) *EnhancedFirewall {
	// Create communication channels
	blacklistCh := make(chan string, 1000)
	unblockCh := make(chan string, 100)
	alertChannel := make(chan trafan.Alert, 1000)

	// Initialize components
	rateLimiter := newRateLimiter(blacklistCh, unblockCh)
	behavioralProfiler := profiler.NewBehavioralProfiler(blacklistCh)
	trafficAnalyser := trafan.NewTrafficAnalyser(trackingDuration, rateLimit, alertChannel)
	p2pNetwork := p2p.NewP2PNetwork(nodeID, "9001") // P2P on different port

	firewall := &EnhancedFirewall{
		rateLimiter:         rateLimiter,
		behavioralProfiler:  behavioralProfiler,
		trafficAnalyser:     trafficAnalyser,
		p2pNetwork:          p2pNetwork,
		alertChannel:        alertChannel,
		intelligenceChannel: make(chan *p2p.ThreatIntelligence, 1000),
		blacklistCh:         blacklistCh,
		unblockCh:           unblockCh,
	}

	// Start background workers
	go firewall.alertProcessor()
	go firewall.intelligenceProcessor()
	go firewall.threatIntelligenceSharing()

	return firewall
}

// Enhanced request handling with multiple layers of protection
func (ef *EnhancedFirewall) handleRequest(w http.ResponseWriter, r *http.Request, lb *loadb.Loadbalancer) {
	startTime := time.Now()
	clientIP := strings.Split(r.RemoteAddr, ":")[0]
	userAgent := r.UserAgent()
	endpoint := r.URL.Path
	method := r.Method

	// Layer 1: P2P Intelligence Check
	if ef.p2pNetwork.GetKnowledgeCache().IsBlacklisted(clientIP) {
		http.Error(w, "IP blocked by global threat intelligence", http.StatusForbidden)
		log.Printf("Request blocked by P2P intelligence for IP: %s", clientIP)
		return
	}

	// Layer 2: Behavioral Profiling Check
	if ef.behavioralProfiler.IsBlacklisted(clientIP) {
		http.Error(w, "IP blocked by behavioral analysis", http.StatusForbidden)
		log.Printf("Request blocked by behavioral profiler for IP: %s", clientIP)
		return
	}

	// Layer 3: Rate Limiting Check
	var rateLimitPassed bool
	if sessionID := r.Header.Get("Session-ID"); sessionID != "" {
		rateLimitPassed = ef.rateLimiter.sessionCheck(clientIP)
		if !rateLimitPassed {
			http.Error(w, "Session Rate Limit exceeded", http.StatusTooManyRequests)
			log.Printf("Session limit exceeded for IP: %s", clientIP)
			return
		}
	} else {
		rateLimitPassed = ef.rateLimiter.limitCheck(clientIP)
		if !rateLimitPassed {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			log.Printf("Rate limit exceeded for IP: %s", clientIP)
			return
		}
	}

	// Process the request through load balancer
	log.Printf("Processing request from IP: %s to endpoint: %s", clientIP, endpoint)
	lb.ServeProxy(w, r)

	// Post-request analysis
	responseTime := time.Since(startTime).Milliseconds()
	statusCode := 200 // Default, would need response writer wrapper to capture actual status

	// Update behavioral profiler
	ef.behavioralProfiler.AnalyzeRequest(
		clientIP, endpoint, method, userAgent, r.Referer(),
		statusCode, responseTime, r.ContentLength,
	)

	// Update traffic analyzer
	ef.trafficAnalyser.ProcessRequest(
		clientIP, endpoint, userAgent, method,
		statusCode, responseTime, r.ContentLength,
	)
}

// alertProcessor processes alerts from various components
func (ef *EnhancedFirewall) alertProcessor() {
	for alert := range ef.alertChannel {
		log.Printf("ALERT [%s]: %s - %s", alert.Severity, alert.Type, alert.Message)

		// Create threat intelligence based on alert
		intel := ef.createThreatIntelligenceFromAlert(alert)
		if intel != nil {
			ef.p2pNetwork.ShareThreatIntelligence(intel)
		}

		// Take action based on alert type and severity
		ef.handleAlert(alert)
	}
}

// createThreatIntelligenceFromAlert converts alerts to threat intelligence
func (ef *EnhancedFirewall) createThreatIntelligenceFromAlert(alert trafan.Alert) *p2p.ThreatIntelligence {
	intel := &p2p.ThreatIntelligence{
		ID:         fmt.Sprintf("alert-%d", time.Now().UnixNano()),
		Type:       "attack_signature",
		Timestamp:  alert.Timestamp,
		ExpiresAt:  alert.Timestamp.Add(24 * time.Hour),
		Severity:   alert.Severity,
		Metadata:   alert.Data,
		Verified:   false,
		Confidence: ef.calculateConfidenceFromAlert(alert),
	}

	// Add IP information if available
	if alert.IP != "" {
		intel.IPAddresses = []string{alert.IP}
	}

	// Create attack pattern based on alert type
	switch alert.Type {
	case "traffic_spike":
		intel.AttackPatterns = []p2p.AttackPattern{{
			Name:        "Traffic Spike",
			Description: alert.Message,
			Frequency:   ef.extractFrequencyFromAlert(alert),
		}}

	case "coordinated_attack":
		intel.Type = "coordinated_pattern"
		intel.Severity = "critical"
		if ips, ok := alert.Data["ips"].([]string); ok {
			intel.IPAddresses = ips
		}

	case "endpoint_abuse":
		intel.AttackPatterns = []p2p.AttackPattern{{
			Name:            "Endpoint Abuse",
			EndpointTargets: []string{alert.Endpoint},
			Description:     alert.Message,
		}}

	case "odd_hour_traffic":
		intel.AttackPatterns = []p2p.AttackPattern{{
			Name:        "Odd Hour Activity",
			Description: alert.Message,
		}}
	}

	return intel
}

// calculateConfidenceFromAlert calculates confidence score for threat intelligence
func (ef *EnhancedFirewall) calculateConfidenceFromAlert(alert trafan.Alert) float64 {
	switch alert.Severity {
	case "critical":
		return 0.95
	case "high":
		return 0.85
	case "medium":
		return 0.70
	case "low":
		return 0.55
	default:
		return 0.50
	}
}

// extractFrequencyFromAlert extracts frequency information from alert data
func (ef *EnhancedFirewall) extractFrequencyFromAlert(alert trafan.Alert) float64 {
	if currentRate, ok := alert.Data["current_rate"].(float64); ok {
		return currentRate
	}
	return 0.0
}

// handleAlert takes action based on alert type and severity
func (ef *EnhancedFirewall) handleAlert(alert trafan.Alert) {
	switch alert.Type {
	case "coordinated_attack":
		// Immediately blacklist all IPs involved in coordinated attack
		if ips, ok := alert.Data["ips"].([]string); ok {
			for _, ip := range ips {
				select {
				case ef.blacklistCh <- ip:
					log.Printf("Emergency blacklist: %s (coordinated attack)", ip)
				default:
					log.Printf("Blacklist channel full, failed to emergency blacklist: %s", ip)
				}
			}
		}

	case "traffic_spike":
		if alert.Endpoint != "" {
			log.Printf("Implementing endpoint throttling for: %s", alert.Endpoint)
			// Additional endpoint-specific throttling could be implemented here
		}

	case "endpoint_abuse":
		if alert.IP != "" {
			select {
			case ef.blacklistCh <- alert.IP:
				log.Printf("Blacklisting IP for endpoint abuse: %s", alert.IP)
			default:
				log.Printf("Blacklist channel full, failed to blacklist: %s", alert.IP)
			}
		}
	}
}

// intelligenceProcessor processes threat intelligence received from P2P network
func (ef *EnhancedFirewall) intelligenceProcessor() {
	intelCh := ef.p2pNetwork.GetReceivedIntelligence()

	for intel := range intelCh {
		log.Printf("Processing threat intelligence: %s from %s", intel.ID, intel.Source)

		// Apply threat intelligence to local protection
		ef.applyThreatIntelligence(intel)
	}
}

// applyThreatIntelligence applies received threat intelligence to local systems
func (ef *EnhancedFirewall) applyThreatIntelligence(intel *p2p.ThreatIntelligence) {
	// Apply IP blacklists
	for _, ip := range intel.IPAddresses {
		select {
		case ef.blacklistCh <- ip:
			log.Printf("Applied P2P blacklist for IP: %s (source: %s)", ip, intel.Source)
		default:
			log.Printf("Blacklist channel full, failed to apply P2P blacklist for: %s", ip)
		}
	}

	// Log attack patterns for future reference
	for _, pattern := range intel.AttackPatterns {
		log.Printf("Learned attack pattern: %s - %s", pattern.Name, pattern.Description)
	}

	// Update local behavioral signatures
	for _, sig := range intel.BehavioralSigs {
		log.Printf("Learned behavioral signature: %s", sig.Name)
		// Could integrate with behavioral profiler here
	}
}

// threatIntelligenceSharing shares local threat discoveries with P2P network
func (ef *EnhancedFirewall) threatIntelligenceSharing() {
	ticker := time.NewTicker(10 * time.Minute) // Share intelligence every 10 minutes
	defer ticker.Stop()

	for range ticker.C {
		ef.shareLocalIntelligence()
	}
}

// shareLocalIntelligence creates and shares threat intelligence from local data
func (ef *EnhancedFirewall) shareLocalIntelligence() {
	// Get global stats from traffic analyzer
	stats := ef.trafficAnalyser.GetGlobalStats()

	if stats.TotalRequests > 1000 { // Only share if we have significant data
		// Create intelligence about traffic patterns
		intel := &p2p.ThreatIntelligence{
			ID:         fmt.Sprintf("local-stats-%d", time.Now().Unix()),
			Type:       "traffic_baseline",
			Timestamp:  time.Now(),
			ExpiresAt:  time.Now().Add(6 * time.Hour),
			Severity:   "low",
			Confidence: 0.6,
			Metadata: map[string]interface{}{
				"total_requests":   stats.TotalRequests,
				"unique_ips":       stats.UniqueIPs,
				"avg_request_rate": stats.AverageRequestRate,
				"top_endpoints":    stats.TopEndpoints,
			},
			Verified: true,
		}

		ef.p2pNetwork.ShareThreatIntelligence(intel)
		log.Printf("Shared local traffic intelligence with P2P network")
	}
}

// Original rate limiter methods (preserved for compatibility)
func (rl *rateLimiter) sessionCheck(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if endTime, found := rl.brownList[ip]; found {
		if time.Now().Before(endTime) {
			return false
		} else {
			delete(rl.brownList, ip)
		}
	}

	now := time.Now()
	rl.requests[ip] = append(rl.requests[ip], now)

	cutoff := now.Add(-trackingDuration)
	filteredRequests := []time.Time{}

	for _, t := range rl.requests[ip] {
		if t.After(cutoff) {
			filteredRequests = append(filteredRequests, t)
		}
	}
	rl.requests[ip] = filteredRequests

	if len(rl.requests[ip]) > rateLimit {
		rl.brownList[ip] = now.Add(brownListedDuration)
		log.Printf("IP %s has been brown-listed 🚫", ip)
		fmt.Printf("\nIP %s has been brown-listed 🚫", ip)
		rl.blacklistCh <- ip
		go startTimer(ip, rl.unblockCh, brownListedDuration)
		return false
	}

	return true
}

func startTimer(ip string, unblockCh chan string, duration time.Duration) {
	time.Sleep(duration)
	log.Printf("Access to IP %s has been Granted ✅", ip)
	fmt.Printf("\nAccess to IP %s has been Granted ✅", ip)
	unblockCh <- ip
}

func (rl *rateLimiter) limitCheck(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if rl.blackList[ip] {
		return false
	}

	now := time.Now()
	rl.requests[ip] = append(rl.requests[ip], now)

	cutoff := now.Add(-trackingDuration)
	filteredRequests := []time.Time{}

	for _, t := range rl.requests[ip] {
		if t.After(cutoff) {
			filteredRequests = append(filteredRequests, t)
		}
	}
	rl.requests[ip] = filteredRequests

	if len(rl.requests[ip]) > rateLimit {
		rl.blackList[ip] = true
		log.Printf("IP %s has been blacklisted ❗❌❗", ip)
		fmt.Printf("IP %s has been blacklisted ❗❌❗", ip)
		rl.blacklistCh <- ip
		return false
	}

	return true
}

func (rl *rateLimiter) cleanUp() {
	for {
		time.Sleep(trackingDuration)
		rl.mu.Lock()
		for ip, times := range rl.requests {
			cutoff := time.Now().Add(-trackingDuration)
			filteredRequests := []time.Time{}

			for _, t := range times {
				if t.After(cutoff) {
					filteredRequests = append(filteredRequests, t)
				}
			}
			rl.requests[ip] = filteredRequests
		}
		rl.mu.Unlock()
	}
}

func main() {
	// Initialize logging to file
	logFile, err := os.OpenFile("Firewall.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		fmt.Printf("Error opening log file: %v\n", err)
		return
	}
	defer logFile.Close()
	log.SetOutput(logFile)

	// Log the start of the application
	log.Println("\n🛡️ Enhanced VulcanGuard Firewall Activated 🛡️")
	fmt.Println("🛡️ Enhanced VulcanGuard Firewall Starting...")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Generate unique node ID
	nodeID := fmt.Sprintf("vulcan-node-%d", time.Now().Unix())

	// Initialize enhanced firewall
	firewall := NewEnhancedFirewall(nodeID)

	// Add some initial P2P peers (in production, these would be discovered)
	// firewall.p2pNetwork.AddPeer("peer1", "10.0.0.2", "9001")
	// firewall.p2pNetwork.AddPeer("peer2", "10.0.0.3", "9001")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		PkfilterInit(ctx, firewall.blacklistCh, firewall.unblockCh)
	}()

	// Configure load balancer
	servers := []loadb.Server{
		loadb.NewServer("https://www.youtube.com/"),
		loadb.NewServer("https://wasmcloud.com/"),
		loadb.NewServer("https://x.com/"),
	}
	lb := loadb.NewLoadbalancer("8888", servers, "lc")

	// Enhanced request handler
	handleRedirect := func(w http.ResponseWriter, r *http.Request) {
		firewall.handleRequest(w, r, lb)
	}

	http.HandleFunc("/", handleRedirect)

	// Dashboard API endpoints
	http.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		firewall.handleStatsAPI(w, r)
	})

	http.HandleFunc("/api/geo-stats", func(w http.ResponseWriter, r *http.Request) {
		firewall.handleGeoStatsAPI(w, r)
	})

	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		firewall.handleMetricsAPI(w, r)
	})

	// Add health check endpoint
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		stats := firewall.trafficAnalyser.GetGlobalStats()
		response := map[string]interface{}{
			"status":         "healthy",
			"node_id":        nodeID,
			"total_requests": stats.TotalRequests,
			"unique_ips":     stats.UniqueIPs,
			"peer_count":     len(firewall.p2pNetwork.GetKnowledgeCache().GetThreatsSince(time.Now().Add(-time.Hour))),
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status": "%s", "node_id": "%s", "total_requests": %d, "unique_ips": %d}`,
			response["status"], response["node_id"], response["total_requests"], response["unique_ips"])
	})

	// Set up signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	// Start the HTTP server in a goroutine
	serverErrors := make(chan error, 1)
	go func() {
		log.Printf("🚀 Enhanced VulcanGuard serving requests at localhost:%s", lb.Port)
		fmt.Printf("🚀 Enhanced VulcanGuard serving requests at localhost:%s\n", lb.Port)
		fmt.Printf("🔗 P2P network active on port 9001\n")
		fmt.Printf("📊 Health endpoint: http://localhost:%s/health\n", lb.Port)
		serverErrors <- http.ListenAndServe(":"+lb.Port, nil)
	}()

	// Wait for shutdown signal or server error
	select {
	case <-sigCh:
		fmt.Println("\n🛑 Received shutdown signal. Stopping Enhanced VulcanGuard...")
		log.Println("🛑 Received shutdown signal. Stopping Enhanced VulcanGuard...")
	case err := <-serverErrors:
		fmt.Printf("❌ Server error: %v\n", err)
		log.Printf("❌ Server error: %v", err)
	}

	// Graceful shutdown
	fmt.Println("🔄 Shutting down components...")
	log.Println("🔄 Shutting down components...")

	// Stop components
	firewall.trafficAnalyser.Stop()
	firewall.p2pNetwork.Stop()

	// Cancel the context to signal all goroutines to stop
	cancel()

	// Wait for PkfilterInit to finish
	wg.Wait()

	fmt.Println("✅ All operations stopped. Enhanced VulcanGuard shutdown complete! 👋")
	log.Println("✅ All operations stopped. Enhanced VulcanGuard shutdown complete! 👋")
}

// Dashboard API handlers
func (ef *EnhancedFirewall) handleStatsAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	globalStats := ef.trafficAnalyser.GetGlobalStats()
	profiles := ef.behavioralProfiler.GetProfiles()

	// Count blacklisted IPs
	blacklistedCount := 0
	ef.rateLimiter.mu.Lock()
	blacklistedCount = len(ef.rateLimiter.blackList)
	ef.rateLimiter.mu.Unlock()

	stats := map[string]interface{}{
		"total_requests":      globalStats.TotalRequests,
		"blocked_requests":    int64(blacklistedCount), // Count of blacklisted IPs as proxy
		"allowed_requests":    globalStats.TotalRequests,
		"active_connections":  len(ef.rateLimiter.requests),
		"blacklisted_ips":     blacklistedCount,
		"unique_ips":          globalStats.UniqueIPs,
		"behavioral_profiles": len(profiles),
		"p2p_peers":           len(ef.p2pNetwork.GetKnowledgeCache().GetThreatsSince(time.Now().Add(-time.Hour))),
	}

	response, _ := json.Marshal(stats)
	w.Write(response)
}

func (ef *EnhancedFirewall) handleGeoStatsAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Get behavioral profiles with geographic data
	profiles := ef.behavioralProfiler.GetProfiles()
	geoStats := make([]map[string]interface{}, 0)

	// Aggregate by country (simplified - in real implementation, you'd use proper geolocation)
	countryStats := make(map[string]map[string]interface{})

	for _, profile := range profiles {
		// Extract country from IP (simplified - use proper geolocation service)
		country := ef.getCountryFromIP(profile.IP)
		city := ef.getCityFromIP(profile.IP)
		lat, lon := ef.getCoordinatesFromIP(profile.IP)

		if stats, exists := countryStats[country]; exists {
			stats["requests"] = stats["requests"].(int) + profile.TotalRequests
		} else {
			countryStats[country] = map[string]interface{}{
				"country":   country,
				"city":      city,
				"latitude":  lat,
				"longitude": lon,
				"requests":  profile.TotalRequests,
			}
		}
	}

	// Convert to slice
	for _, stats := range countryStats {
		geoStats = append(geoStats, stats)
	}

	response, _ := json.Marshal(geoStats)
	w.Write(response)
}

func (ef *EnhancedFirewall) handleMetricsAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	globalStats := ef.trafficAnalyser.GetGlobalStats()
	profiles := ef.behavioralProfiler.GetProfiles()

	ef.rateLimiter.mu.Lock()
	blacklistedCount := len(ef.rateLimiter.blackList)
	activeConnections := len(ef.rateLimiter.requests)
	ef.rateLimiter.mu.Unlock()

	// Generate Prometheus-style metrics
	metrics := fmt.Sprintf(`# HELP vulcanguard_requests_total Total number of requests processed
# TYPE vulcanguard_requests_total counter
vulcanguard_requests_total %d

# HELP vulcanguard_blocked_requests_total Total number of blocked requests
# TYPE vulcanguard_blocked_requests_total counter
vulcanguard_blocked_requests_total %d

# HELP vulcanguard_allowed_requests_total Total number of allowed requests
# TYPE vulcanguard_allowed_requests_total counter
vulcanguard_allowed_requests_total %d

# HELP vulcanguard_active_connections Number of active connections
# TYPE vulcanguard_active_connections gauge
vulcanguard_active_connections %d

# HELP vulcanguard_blacklisted_ips Number of blacklisted IP addresses
# TYPE vulcanguard_blacklisted_ips gauge
vulcanguard_blacklisted_ips %d

# HELP vulcanguard_behavioral_profiles Number of behavioral profiles
# TYPE vulcanguard_behavioral_profiles gauge
vulcanguard_behavioral_profiles %d

# HELP vulcanguard_unique_ips Number of unique IP addresses seen
# TYPE vulcanguard_unique_ips gauge
vulcanguard_unique_ips %d
`,
		globalStats.TotalRequests,
		blacklistedCount, // Simplified - track actual blocked requests
		globalStats.TotalRequests-int64(blacklistedCount),
		activeConnections,
		blacklistedCount,
		len(profiles),
		globalStats.UniqueIPs,
	)

	w.Write([]byte(metrics))
}

// Helper functions for geolocation (simplified - use proper geolocation service in production)
func (ef *EnhancedFirewall) getCountryFromIP(ip string) string {
	// Simplified mapping - use real geolocation service
	if strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "127.") {
		return "Local"
	}
	// Add more sophisticated geolocation logic here
	countries := []string{"United States", "Germany", "Japan", "United Kingdom", "France", "Canada", "Australia", "Brazil"}
	return countries[len(ip)%len(countries)]
}

func (ef *EnhancedFirewall) getCityFromIP(ip string) string {
	// Simplified mapping
	if strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "127.") {
		return "Localhost"
	}
	cities := []string{"New York", "Berlin", "Tokyo", "London", "Paris", "Toronto", "Sydney", "São Paulo"}
	return cities[len(ip)%len(cities)]
}

func (ef *EnhancedFirewall) getCoordinatesFromIP(ip string) (float64, float64) {
	// Simplified mapping - use real geolocation service
	if strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "127.") {
		return 0.0, 0.0
	}
	// Return sample coordinates
	coordinates := [][2]float64{
		{40.7128, -74.0060},  // New York
		{52.5200, 13.4050},   // Berlin
		{35.6762, 139.6503},  // Tokyo
		{51.5074, -0.1278},   // London
		{48.8566, 2.3522},    // Paris
		{43.6532, -79.3832},  // Toronto
		{-33.8688, 151.2093}, // Sydney
		{-23.5505, -46.6333}, // São Paulo
	}
	coordIndex := len(ip) % len(coordinates)
	return coordinates[coordIndex][0], coordinates[coordIndex][1]
}
