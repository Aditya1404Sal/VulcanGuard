package identity

import (
	"crypto/md5"
	"fmt"
	"log"
	"math"
	"sort"
	"sync"
	"time"
)

// IdentityAnalyzer manages identity analysis and similarity detection
type IdentityAnalyzer struct {
	identities          map[string]*Identity
	similarityGroups    map[string]*SimilarityGroup
	weightingMatrix     *WeightingMatrix
	analysisQueue       chan *AnalysisRequest
	similarityThreshold float64
	mu                  sync.RWMutex
	isRunning           bool
	alertCallback       func(AlertType, string, map[string]interface{})
}

// Identity represents a unique behavioral identity
type Identity struct {
	ID                    string                 `json:"id"`
	IPs                   []string               `json:"ips"`
	BehavioralFingerprint *BehavioralFingerprint `json:"behavioral_fingerprint"`
	ThreatScore           float64                `json:"threat_score"`
	SimilarityGroup       string                 `json:"similarity_group"`
	FirstSeen             time.Time              `json:"first_seen"`
	LastSeen              time.Time              `json:"last_seen"`
	ScreeningStrictness   float64                `json:"screening_strictness"` // 0.0 - 1.0
	AttackHistory         []AttackEvent          `json:"attack_history"`
	Metadata              map[string]interface{} `json:"metadata"`
}

// BehavioralFingerprint represents a comprehensive behavioral profile
type BehavioralFingerprint struct {
	RequestPatternHash   string                `json:"request_pattern_hash"`
	TimingPattern        *TimingPattern        `json:"timing_pattern"`
	EndpointPreferences  map[string]float64    `json:"endpoint_preferences"`
	UserAgentSignature   string                `json:"user_agent_signature"`
	GeographicIndicators *GeographicIndicators `json:"geographic_indicators"`
	TechnicalProfile     *TechnicalProfile     `json:"technical_profile"`
	NetworkBehavior      *NetworkBehavior      `json:"network_behavior"`
}

// TimingPattern represents request timing characteristics
type TimingPattern struct {
	AverageInterval  float64   `json:"average_interval"`
	IntervalVariance float64   `json:"interval_variance"`
	BurstPatterns    []float64 `json:"burst_patterns"`
	RegularityScore  float64   `json:"regularity_score"`
	PeakHours        []int     `json:"peak_hours"`
	SessionDurations []float64 `json:"session_durations"`
}

// GeographicIndicators represents geographic behavior patterns
type GeographicIndicators struct {
	PrimaryCountry  string             `json:"primary_country"`
	CountryChanges  int                `json:"country_changes"`
	RegionStability float64            `json:"region_stability"`
	ISPFingerprint  string             `json:"isp_fingerprint"`
	ProxyIndicators map[string]float64 `json:"proxy_indicators"`
	TimezonePattern string             `json:"timezone_pattern"`
}

// TechnicalProfile represents technical characteristics
type TechnicalProfile struct {
	UserAgentPatterns []string           `json:"user_agent_patterns"`
	HTTPVersions      map[string]int     `json:"http_versions"`
	HeaderFingerprint string             `json:"header_fingerprint"`
	CompressionUsage  map[string]float64 `json:"compression_usage"`
	TLSFingerprint    string             `json:"tls_fingerprint"`
	LanguageSettings  []string           `json:"language_settings"`
}

// NetworkBehavior represents network-level behavior patterns
type NetworkBehavior struct {
	ConcurrentConnections int                `json:"concurrent_connections"`
	KeepAliveUsage        float64            `json:"keep_alive_usage"`
	RetryPatterns         map[string]int     `json:"retry_patterns"`
	ErrorResponseRatio    float64            `json:"error_response_ratio"`
	PayloadSizeDistrib    map[string]float64 `json:"payload_size_distrib"`
	ProtocolUsage         map[string]float64 `json:"protocol_usage"`
}

// SimilarityGroup represents a group of similar identities
type SimilarityGroup struct {
	ID                string                 `json:"id"`
	Members           []string               `json:"members"`
	CommonFingerprint *BehavioralFingerprint `json:"common_fingerprint"`
	ThreatLevel       string                 `json:"threat_level"`
	CreatedAt         time.Time              `json:"created_at"`
	LastUpdated       time.Time              `json:"last_updated"`
	Confidence        float64                `json:"confidence"`
}

// WeightingMatrix defines importance weights for different behavioral aspects
type WeightingMatrix struct {
	RequestPatternWeight float64 `json:"request_pattern_weight"`
	TimingWeight         float64 `json:"timing_weight"`
	EndpointWeight       float64 `json:"endpoint_weight"`
	UserAgentWeight      float64 `json:"user_agent_weight"`
	GeographicWeight     float64 `json:"geographic_weight"`
	TechnicalWeight      float64 `json:"technical_weight"`
	NetworkWeight        float64 `json:"network_weight"`
	AdaptiveWeighting    bool    `json:"adaptive_weighting"`
}

// AnalysisRequest represents a request for identity analysis
type AnalysisRequest struct {
	IP          string                 `json:"ip"`
	RequestData map[string]interface{} `json:"request_data"`
	Timestamp   time.Time              `json:"timestamp"`
	Priority    int                    `json:"priority"` // 1-5, 5 being highest
}

// AttackEvent represents a recorded attack event
type AttackEvent struct {
	Type        string                 `json:"type"`
	Timestamp   time.Time              `json:"timestamp"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// AlertType represents different types of identity alerts
type AlertType int

const (
	SimilarIdentitiesDetected AlertType = iota
	HighThreatIdentity
	IdentityGroupEvolution
	AnomalousIdentityChange
)

// NewIdentityAnalyzer creates a new identity analyzer
func NewIdentityAnalyzer(alertCallback func(AlertType, string, map[string]interface{})) *IdentityAnalyzer {
	analyzer := &IdentityAnalyzer{
		identities:          make(map[string]*Identity),
		similarityGroups:    make(map[string]*SimilarityGroup),
		analysisQueue:       make(chan *AnalysisRequest, 5000),
		similarityThreshold: 0.80,
		isRunning:           true,
		alertCallback:       alertCallback,
		weightingMatrix: &WeightingMatrix{
			RequestPatternWeight: 0.25,
			TimingWeight:         0.20,
			EndpointWeight:       0.15,
			UserAgentWeight:      0.15,
			GeographicWeight:     0.10,
			TechnicalWeight:      0.10,
			NetworkWeight:        0.05,
			AdaptiveWeighting:    true,
		},
	}

	// Start background workers
	go analyzer.analysisWorker()
	go analyzer.similarityAnalysisWorker()
	go analyzer.adaptiveWeightingWorker()

	return analyzer
}

// AnalyzeIdentity adds an identity analysis request to the queue
func (ia *IdentityAnalyzer) AnalyzeIdentity(ip string, requestData map[string]interface{}, priority int) {
	request := &AnalysisRequest{
		IP:          ip,
		RequestData: requestData,
		Timestamp:   time.Now(),
		Priority:    priority,
	}

	select {
	case ia.analysisQueue <- request:
		// Successfully queued
	default:
		log.Printf("Identity analysis queue full, dropping request for IP: %s", ip)
	}
}

// analysisWorker processes identity analysis requests
func (ia *IdentityAnalyzer) analysisWorker() {
	// Use priority queue for processing
	requests := make([]*AnalysisRequest, 0)

	for ia.isRunning {
		select {
		case request := <-ia.analysisQueue:
			requests = append(requests, request)

			// Process batch when we have enough requests or timeout
			if len(requests) >= 10 {
				ia.processBatch(requests)
				requests = requests[:0]
			}

		case <-time.After(5 * time.Second):
			// Process any pending requests
			if len(requests) > 0 {
				ia.processBatch(requests)
				requests = requests[:0]
			}
		}
	}
}

// processBatch processes a batch of identity analysis requests
func (ia *IdentityAnalyzer) processBatch(requests []*AnalysisRequest) {
	// Sort by priority
	sort.Slice(requests, func(i, j int) bool {
		return requests[i].Priority > requests[j].Priority
	})

	for _, request := range requests {
		ia.processIdentityRequest(request)
	}
}

// processIdentityRequest processes a single identity analysis request
func (ia *IdentityAnalyzer) processIdentityRequest(request *AnalysisRequest) {
	ia.mu.Lock()
	defer ia.mu.Unlock()

	// Create or update identity
	identity := ia.getOrCreateIdentity(request.IP)

	// Update behavioral fingerprint
	ia.updateBehavioralFingerprint(identity, request.RequestData)

	// Calculate threat score
	identity.ThreatScore = ia.calculateThreatScore(identity)

	// Update screening strictness based on threat score
	ia.updateScreeningStrictness(identity)

	// Update timestamps
	identity.LastSeen = request.Timestamp

	// Queue for similarity analysis
	go ia.queueSimilarityAnalysis(identity.ID)
}

// getOrCreateIdentity retrieves or creates an identity for an IP
func (ia *IdentityAnalyzer) getOrCreateIdentity(ip string) *Identity {
	// First check if this IP is already associated with an identity
	for _, identity := range ia.identities {
		for _, identityIP := range identity.IPs {
			if identityIP == ip {
				return identity
			}
		}
	}

	// Create new identity
	identityID := ia.generateIdentityID(ip)
	identity := &Identity{
		ID:                    identityID,
		IPs:                   []string{ip},
		BehavioralFingerprint: &BehavioralFingerprint{},
		ThreatScore:           0.0,
		FirstSeen:             time.Now(),
		LastSeen:              time.Now(),
		ScreeningStrictness:   0.5, // Default moderate strictness
		AttackHistory:         make([]AttackEvent, 0),
		Metadata:              make(map[string]interface{}),
	}

	ia.identities[identityID] = identity
	return identity
}

// updateBehavioralFingerprint updates the behavioral fingerprint based on request data
func (ia *IdentityAnalyzer) updateBehavioralFingerprint(identity *Identity, requestData map[string]interface{}) {
	fingerprint := identity.BehavioralFingerprint

	// Update request pattern hash
	if patterns, ok := requestData["request_patterns"].([]interface{}); ok {
		fingerprint.RequestPatternHash = ia.generateRequestPatternHash(patterns)
	}

	// Update timing patterns
	if timingData, ok := requestData["timing_data"].(map[string]interface{}); ok {
		fingerprint.TimingPattern = ia.extractTimingPattern(timingData)
	}

	// Update endpoint preferences
	if endpoints, ok := requestData["endpoints"].(map[string]interface{}); ok {
		fingerprint.EndpointPreferences = ia.calculateEndpointPreferences(endpoints)
	}

	// Update user agent signature
	if userAgent, ok := requestData["user_agent"].(string); ok {
		fingerprint.UserAgentSignature = ia.generateUserAgentSignature(userAgent)
	}

	// Update geographic indicators
	if geoData, ok := requestData["geographic_data"].(map[string]interface{}); ok {
		fingerprint.GeographicIndicators = ia.extractGeographicIndicators(geoData)
	}

	// Update technical profile
	if techData, ok := requestData["technical_data"].(map[string]interface{}); ok {
		fingerprint.TechnicalProfile = ia.extractTechnicalProfile(techData)
	}

	// Update network behavior
	if networkData, ok := requestData["network_data"].(map[string]interface{}); ok {
		fingerprint.NetworkBehavior = ia.extractNetworkBehavior(networkData)
	}
}

// generateRequestPatternHash generates a hash of request patterns
func (ia *IdentityAnalyzer) generateRequestPatternHash(patterns []interface{}) string {
	hasher := md5.New()
	for _, pattern := range patterns {
		if patternStr, ok := pattern.(string); ok {
			hasher.Write([]byte(patternStr))
		}
	}
	return fmt.Sprintf("%x", hasher.Sum(nil))
}

// extractTimingPattern extracts timing patterns from timing data
func (ia *IdentityAnalyzer) extractTimingPattern(timingData map[string]interface{}) *TimingPattern {
	pattern := &TimingPattern{}

	if intervals, ok := timingData["intervals"].([]interface{}); ok {
		pattern.AverageInterval = ia.calculateAverage(intervals)
		pattern.IntervalVariance = ia.calculateVariance(intervals, pattern.AverageInterval)
		pattern.RegularityScore = ia.calculateRegularityScore(intervals)
	}

	if bursts, ok := timingData["bursts"].([]interface{}); ok {
		pattern.BurstPatterns = ia.convertToFloat64Slice(bursts)
	}

	if hours, ok := timingData["peak_hours"].([]interface{}); ok {
		pattern.PeakHours = ia.convertToIntSlice(hours)
	}

	return pattern
}

// calculateEndpointPreferences calculates preferences for different endpoints
func (ia *IdentityAnalyzer) calculateEndpointPreferences(endpoints map[string]interface{}) map[string]float64 {
	preferences := make(map[string]float64)
	total := 0.0

	// Calculate total requests
	for _, count := range endpoints {
		if countFloat, ok := count.(float64); ok {
			total += countFloat
		}
	}

	// Calculate preferences as percentages
	for endpoint, count := range endpoints {
		if countFloat, ok := count.(float64); ok && total > 0 {
			preferences[endpoint] = countFloat / total
		}
	}

	return preferences
}

// generateUserAgentSignature generates a signature from user agent string
func (ia *IdentityAnalyzer) generateUserAgentSignature(userAgent string) string {
	// Extract key components: browser, version, OS
	hasher := md5.New()
	hasher.Write([]byte(userAgent))
	return fmt.Sprintf("%x", hasher.Sum(nil))[:16] // Use first 16 chars
}

// extractGeographicIndicators extracts geographic indicators from geographic data
func (ia *IdentityAnalyzer) extractGeographicIndicators(geoData map[string]interface{}) *GeographicIndicators {
	indicators := &GeographicIndicators{}

	if country, ok := geoData["country"].(string); ok {
		indicators.PrimaryCountry = country
	}

	if isp, ok := geoData["isp"].(string); ok {
		hasher := md5.New()
		hasher.Write([]byte(isp))
		indicators.ISPFingerprint = fmt.Sprintf("%x", hasher.Sum(nil))[:12]
	}

	if timezone, ok := geoData["timezone"].(string); ok {
		indicators.TimezonePattern = timezone
	}

	// Extract proxy indicators
	indicators.ProxyIndicators = make(map[string]float64)
	if proxy, ok := geoData["proxy"].(bool); ok && proxy {
		indicators.ProxyIndicators["proxy"] = 1.0
	}
	if hosting, ok := geoData["hosting"].(bool); ok && hosting {
		indicators.ProxyIndicators["hosting"] = 1.0
	}

	return indicators
}

// extractTechnicalProfile extracts technical profile from technical data
func (ia *IdentityAnalyzer) extractTechnicalProfile(techData map[string]interface{}) *TechnicalProfile {
	profile := &TechnicalProfile{
		HTTPVersions:     make(map[string]int),
		CompressionUsage: make(map[string]float64),
	}

	if userAgents, ok := techData["user_agents"].([]interface{}); ok {
		profile.UserAgentPatterns = ia.convertToStringSlice(userAgents)
	}

	if headers, ok := techData["headers"].(map[string]interface{}); ok {
		hasher := md5.New()
		for key, value := range headers {
			hasher.Write([]byte(fmt.Sprintf("%s:%v", key, value)))
		}
		profile.HeaderFingerprint = fmt.Sprintf("%x", hasher.Sum(nil))[:16]
	}

	return profile
}

// extractNetworkBehavior extracts network behavior from network data
func (ia *IdentityAnalyzer) extractNetworkBehavior(networkData map[string]interface{}) *NetworkBehavior {
	behavior := &NetworkBehavior{
		RetryPatterns:      make(map[string]int),
		PayloadSizeDistrib: make(map[string]float64),
		ProtocolUsage:      make(map[string]float64),
	}

	if connections, ok := networkData["concurrent_connections"].(float64); ok {
		behavior.ConcurrentConnections = int(connections)
	}

	if keepAlive, ok := networkData["keep_alive_usage"].(float64); ok {
		behavior.KeepAliveUsage = keepAlive
	}

	if errorRatio, ok := networkData["error_ratio"].(float64); ok {
		behavior.ErrorResponseRatio = errorRatio
	}

	return behavior
}

// calculateThreatScore calculates threat score for an identity
func (ia *IdentityAnalyzer) calculateThreatScore(identity *Identity) float64 {
	score := 0.0

	// Base score from behavioral anomalies
	if identity.BehavioralFingerprint.TimingPattern != nil {
		// High regularity indicates bot-like behavior
		if identity.BehavioralFingerprint.TimingPattern.RegularityScore > 0.8 {
			score += 30.0
		}

		// Very short average intervals indicate aggressive behavior
		if identity.BehavioralFingerprint.TimingPattern.AverageInterval < 1.0 {
			score += 25.0
		}
	}

	// Geographic risk factors
	if identity.BehavioralFingerprint.GeographicIndicators != nil {
		indicators := identity.BehavioralFingerprint.GeographicIndicators

		// Proxy/hosting usage
		if proxyScore, exists := indicators.ProxyIndicators["proxy"]; exists && proxyScore > 0 {
			score += 15.0
		}
		if hostingScore, exists := indicators.ProxyIndicators["hosting"]; exists && hostingScore > 0 {
			score += 10.0
		}

		// Multiple country changes
		if indicators.CountryChanges > 3 {
			score += 20.0
		}
	}

	// Technical anomalies
	if identity.BehavioralFingerprint.TechnicalProfile != nil {
		// Multiple user agents indicate potential spoofing
		if len(identity.BehavioralFingerprint.TechnicalProfile.UserAgentPatterns) > 5 {
			score += 15.0
		}
	}

	// Network behavior anomalies
	if identity.BehavioralFingerprint.NetworkBehavior != nil {
		// High error response ratio
		if identity.BehavioralFingerprint.NetworkBehavior.ErrorResponseRatio > 0.3 {
			score += 10.0
		}

		// Excessive concurrent connections
		if identity.BehavioralFingerprint.NetworkBehavior.ConcurrentConnections > 20 {
			score += 15.0
		}
	}

	// Historical attack events
	score += float64(len(identity.AttackHistory)) * 5.0

	// Normalize to 0-100 scale
	if score > 100.0 {
		score = 100.0
	}

	return score
}

// updateScreeningStrictness updates screening strictness based on threat score
func (ia *IdentityAnalyzer) updateScreeningStrictness(identity *Identity) {
	// Map threat score to screening strictness
	if identity.ThreatScore > 80.0 {
		identity.ScreeningStrictness = 1.0 // Maximum strictness
	} else if identity.ThreatScore > 60.0 {
		identity.ScreeningStrictness = 0.8 // High strictness
	} else if identity.ThreatScore > 40.0 {
		identity.ScreeningStrictness = 0.6 // Moderate-high strictness
	} else if identity.ThreatScore > 20.0 {
		identity.ScreeningStrictness = 0.4 // Moderate strictness
	} else {
		identity.ScreeningStrictness = 0.2 // Low strictness
	}
}

// similarityAnalysisWorker performs similarity analysis between identities
func (ia *IdentityAnalyzer) similarityAnalysisWorker() {
	ticker := time.NewTicker(10 * time.Minute) // Run every 10 minutes
	defer ticker.Stop()

	for ia.isRunning {
		select {
		case <-ticker.C:
			ia.performSimilarityAnalysis()
		case <-time.After(100 * time.Millisecond):
			// Check isRunning periodically
		}
	}
}

// performSimilarityAnalysis performs comprehensive similarity analysis
func (ia *IdentityAnalyzer) performSimilarityAnalysis() {
	ia.mu.RLock()
	identities := make([]*Identity, 0, len(ia.identities))
	for _, identity := range ia.identities {
		identities = append(identities, identity)
	}
	ia.mu.RUnlock()

	// Find similar identity groups
	similarGroups := ia.findSimilarIdentities(identities)

	ia.mu.Lock()
	// Update similarity groups
	for _, group := range similarGroups {
		ia.similarityGroups[group.ID] = group

		// Update identities with group membership
		for _, memberID := range group.Members {
			if identity, exists := ia.identities[memberID]; exists {
				identity.SimilarityGroup = group.ID
			}
		}
	}
	ia.mu.Unlock()

	// Send alerts for significant groups
	for _, group := range similarGroups {
		if len(group.Members) >= 5 && group.Confidence > 0.8 {
			ia.sendAlert(SimilarIdentitiesDetected, group.ID, map[string]interface{}{
				"member_count": len(group.Members),
				"confidence":   group.Confidence,
				"threat_level": group.ThreatLevel,
				"members":      group.Members,
			})
		}
	}
}

// findSimilarIdentities finds groups of similar identities
func (ia *IdentityAnalyzer) findSimilarIdentities(identities []*Identity) []*SimilarityGroup {
	groups := make([]*SimilarityGroup, 0)
	processed := make(map[string]bool)

	for i, identity1 := range identities {
		if processed[identity1.ID] {
			continue
		}

		similarIdentities := []string{identity1.ID}
		processed[identity1.ID] = true

		for j := i + 1; j < len(identities); j++ {
			identity2 := identities[j]
			if processed[identity2.ID] {
				continue
			}

			similarity := ia.calculateIdentitySimilarity(identity1, identity2)
			if similarity > ia.similarityThreshold {
				similarIdentities = append(similarIdentities, identity2.ID)
				processed[identity2.ID] = true
			}
		}

		// Create group if we have multiple similar identities
		if len(similarIdentities) > 1 {
			group := &SimilarityGroup{
				ID:          ia.generateGroupID(),
				Members:     similarIdentities,
				ThreatLevel: ia.calculateGroupThreatLevel(similarIdentities),
				CreatedAt:   time.Now(),
				LastUpdated: time.Now(),
				Confidence:  ia.calculateGroupConfidence(similarIdentities),
			}
			groups = append(groups, group)
		}
	}

	return groups
}

// calculateIdentitySimilarity calculates similarity between two identities
func (ia *IdentityAnalyzer) calculateIdentitySimilarity(identity1, identity2 *Identity) float64 {
	weights := ia.weightingMatrix
	similarity := 0.0
	totalWeight := 0.0

	// Request pattern similarity
	if identity1.BehavioralFingerprint.RequestPatternHash != "" &&
		identity2.BehavioralFingerprint.RequestPatternHash != "" {
		if identity1.BehavioralFingerprint.RequestPatternHash == identity2.BehavioralFingerprint.RequestPatternHash {
			similarity += weights.RequestPatternWeight
		}
		totalWeight += weights.RequestPatternWeight
	}

	// Timing pattern similarity
	if identity1.BehavioralFingerprint.TimingPattern != nil &&
		identity2.BehavioralFingerprint.TimingPattern != nil {
		timingSim := ia.calculateTimingSimilarity(
			identity1.BehavioralFingerprint.TimingPattern,
			identity2.BehavioralFingerprint.TimingPattern,
		)
		similarity += timingSim * weights.TimingWeight
		totalWeight += weights.TimingWeight
	}

	// Endpoint preference similarity
	if len(identity1.BehavioralFingerprint.EndpointPreferences) > 0 &&
		len(identity2.BehavioralFingerprint.EndpointPreferences) > 0 {
		endpointSim := ia.calculateEndpointSimilarity(
			identity1.BehavioralFingerprint.EndpointPreferences,
			identity2.BehavioralFingerprint.EndpointPreferences,
		)
		similarity += endpointSim * weights.EndpointWeight
		totalWeight += weights.EndpointWeight
	}

	// User agent similarity
	if identity1.BehavioralFingerprint.UserAgentSignature != "" &&
		identity2.BehavioralFingerprint.UserAgentSignature != "" {
		if identity1.BehavioralFingerprint.UserAgentSignature == identity2.BehavioralFingerprint.UserAgentSignature {
			similarity += weights.UserAgentWeight
		}
		totalWeight += weights.UserAgentWeight
	}

	// Geographic similarity
	if identity1.BehavioralFingerprint.GeographicIndicators != nil &&
		identity2.BehavioralFingerprint.GeographicIndicators != nil {
		geoSim := ia.calculateGeographicSimilarity(
			identity1.BehavioralFingerprint.GeographicIndicators,
			identity2.BehavioralFingerprint.GeographicIndicators,
		)
		similarity += geoSim * weights.GeographicWeight
		totalWeight += weights.GeographicWeight
	}

	if totalWeight > 0 {
		return similarity / totalWeight
	}
	return 0.0
}

// calculateTimingSimilarity calculates similarity between timing patterns
func (ia *IdentityAnalyzer) calculateTimingSimilarity(pattern1, pattern2 *TimingPattern) float64 {
	similarity := 0.0
	factors := 0.0

	// Average interval similarity
	if pattern1.AverageInterval > 0 && pattern2.AverageInterval > 0 {
		intervalSim := 1.0 - math.Abs(pattern1.AverageInterval-pattern2.AverageInterval)/
			math.Max(pattern1.AverageInterval, pattern2.AverageInterval)
		similarity += intervalSim * 0.4
		factors += 0.4
	}

	// Regularity score similarity
	regularitySim := 1.0 - math.Abs(pattern1.RegularityScore-pattern2.RegularityScore)
	similarity += regularitySim * 0.3
	factors += 0.3

	// Peak hours similarity
	if len(pattern1.PeakHours) > 0 && len(pattern2.PeakHours) > 0 {
		peakSim := ia.calculateIntSliceSimilarity(pattern1.PeakHours, pattern2.PeakHours)
		similarity += peakSim * 0.3
		factors += 0.3
	}

	if factors > 0 {
		return similarity / factors
	}
	return 0.0
}

// calculateEndpointSimilarity calculates similarity between endpoint preferences
func (ia *IdentityAnalyzer) calculateEndpointSimilarity(prefs1, prefs2 map[string]float64) float64 {
	commonEndpoints := make(map[string]bool)
	for endpoint := range prefs1 {
		commonEndpoints[endpoint] = true
	}
	for endpoint := range prefs2 {
		commonEndpoints[endpoint] = true
	}

	if len(commonEndpoints) == 0 {
		return 0.0
	}

	similarity := 0.0
	for endpoint := range commonEndpoints {
		pref1 := prefs1[endpoint]
		pref2 := prefs2[endpoint]

		// Calculate similarity for this endpoint
		endpointSim := 1.0 - math.Abs(pref1-pref2)
		similarity += endpointSim
	}

	return similarity / float64(len(commonEndpoints))
}

// calculateGeographicSimilarity calculates similarity between geographic indicators
func (ia *IdentityAnalyzer) calculateGeographicSimilarity(geo1, geo2 *GeographicIndicators) float64 {
	similarity := 0.0
	factors := 0.0

	// Country similarity
	if geo1.PrimaryCountry == geo2.PrimaryCountry {
		similarity += 0.4
	}
	factors += 0.4

	// ISP fingerprint similarity
	if geo1.ISPFingerprint == geo2.ISPFingerprint {
		similarity += 0.3
	}
	factors += 0.3

	// Timezone pattern similarity
	if geo1.TimezonePattern == geo2.TimezonePattern {
		similarity += 0.3
	}
	factors += 0.3

	return similarity / factors
}

// Helper functions

// calculateAverage calculates average of interface slice
func (ia *IdentityAnalyzer) calculateAverage(values []interface{}) float64 {
	sum := 0.0
	count := 0
	for _, value := range values {
		if floatVal, ok := value.(float64); ok {
			sum += floatVal
			count++
		}
	}
	if count > 0 {
		return sum / float64(count)
	}
	return 0.0
}

// calculateVariance calculates variance of interface slice
func (ia *IdentityAnalyzer) calculateVariance(values []interface{}, mean float64) float64 {
	variance := 0.0
	count := 0
	for _, value := range values {
		if floatVal, ok := value.(float64); ok {
			variance += math.Pow(floatVal-mean, 2)
			count++
		}
	}
	if count > 0 {
		return variance / float64(count)
	}
	return 0.0
}

// calculateRegularityScore calculates how regular the intervals are
func (ia *IdentityAnalyzer) calculateRegularityScore(intervals []interface{}) float64 {
	if len(intervals) < 3 {
		return 0.0
	}

	average := ia.calculateAverage(intervals)
	variance := ia.calculateVariance(intervals, average)

	if average == 0 {
		return 0.0
	}

	// Low coefficient of variation indicates high regularity
	cv := math.Sqrt(variance) / average
	return math.Max(0.0, 1.0-cv)
}

// convertToFloat64Slice converts interface slice to float64 slice
func (ia *IdentityAnalyzer) convertToFloat64Slice(values []interface{}) []float64 {
	result := make([]float64, 0, len(values))
	for _, value := range values {
		if floatVal, ok := value.(float64); ok {
			result = append(result, floatVal)
		}
	}
	return result
}

// convertToIntSlice converts interface slice to int slice
func (ia *IdentityAnalyzer) convertToIntSlice(values []interface{}) []int {
	result := make([]int, 0, len(values))
	for _, value := range values {
		if floatVal, ok := value.(float64); ok {
			result = append(result, int(floatVal))
		}
	}
	return result
}

// convertToStringSlice converts interface slice to string slice
func (ia *IdentityAnalyzer) convertToStringSlice(values []interface{}) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if strVal, ok := value.(string); ok {
			result = append(result, strVal)
		}
	}
	return result
}

// calculateIntSliceSimilarity calculates similarity between two int slices
func (ia *IdentityAnalyzer) calculateIntSliceSimilarity(slice1, slice2 []int) float64 {
	if len(slice1) == 0 && len(slice2) == 0 {
		return 1.0
	}
	if len(slice1) == 0 || len(slice2) == 0 {
		return 0.0
	}

	// Find common elements
	set1 := make(map[int]bool)
	for _, val := range slice1 {
		set1[val] = true
	}

	common := 0
	for _, val := range slice2 {
		if set1[val] {
			common++
		}
	}

	// Jaccard similarity
	union := len(slice1) + len(slice2) - common
	if union == 0 {
		return 1.0
	}

	return float64(common) / float64(union)
}

// generateIdentityID generates a unique identity ID
func (ia *IdentityAnalyzer) generateIdentityID(ip string) string {
	return fmt.Sprintf("identity-%s-%d", ip, time.Now().UnixNano())
}

// generateGroupID generates a unique group ID
func (ia *IdentityAnalyzer) generateGroupID() string {
	return fmt.Sprintf("group-%d", time.Now().UnixNano())
}

// calculateGroupThreatLevel calculates threat level for a similarity group
func (ia *IdentityAnalyzer) calculateGroupThreatLevel(memberIDs []string) string {
	averageThreatScore := 0.0
	count := 0

	for _, memberID := range memberIDs {
		if identity, exists := ia.identities[memberID]; exists {
			averageThreatScore += identity.ThreatScore
			count++
		}
	}

	if count > 0 {
		averageThreatScore /= float64(count)
	}

	if averageThreatScore > 80.0 {
		return "critical"
	} else if averageThreatScore > 60.0 {
		return "high"
	} else if averageThreatScore > 40.0 {
		return "medium"
	} else {
		return "low"
	}
}

// calculateGroupConfidence calculates confidence for a similarity group
func (ia *IdentityAnalyzer) calculateGroupConfidence(memberIDs []string) float64 {
	// Confidence based on group size and similarity scores
	groupSize := len(memberIDs)

	// Larger groups have higher confidence
	sizeConfidence := math.Min(1.0, float64(groupSize)/10.0)

	// Base confidence for similarity grouping
	baseConfidence := 0.7

	return baseConfidence + (sizeConfidence * 0.3)
}

// queueSimilarityAnalysis queues an identity for similarity analysis
func (ia *IdentityAnalyzer) queueSimilarityAnalysis(identityID string) {
	// This could be implemented to queue specific identities for analysis
	// For now, we rely on the periodic analysis
}

// adaptiveWeightingWorker adjusts weighting matrix based on detection effectiveness
func (ia *IdentityAnalyzer) adaptiveWeightingWorker() {
	if !ia.weightingMatrix.AdaptiveWeighting {
		return
	}

	ticker := time.NewTicker(time.Hour) // Adjust weights hourly
	defer ticker.Stop()

	for ia.isRunning {
		select {
		case <-ticker.C:
			ia.adjustWeights()
		case <-time.After(100 * time.Millisecond):
			// Check isRunning periodically
		}
	}
}

// adjustWeights adjusts the weighting matrix based on detection effectiveness
func (ia *IdentityAnalyzer) adjustWeights() {
	// Implementation for adaptive weighting based on detection success rates
	// This is a simplified version - could be enhanced with machine learning

	ia.mu.RLock()
	totalGroups := len(ia.similarityGroups)
	highConfidenceGroups := 0

	for _, group := range ia.similarityGroups {
		if group.Confidence > 0.8 {
			highConfidenceGroups++
		}
	}
	ia.mu.RUnlock()

	// Adjust weights based on detection success
	if totalGroups > 0 {
		successRate := float64(highConfidenceGroups) / float64(totalGroups)

		// If success rate is low, adjust weights
		if successRate < 0.7 {
			// Increase weight for most discriminative features
			ia.weightingMatrix.RequestPatternWeight *= 1.1
			ia.weightingMatrix.TimingWeight *= 1.05

			// Normalize weights
			ia.normalizeWeights()
		}
	}
}

// normalizeWeights normalizes the weighting matrix
func (ia *IdentityAnalyzer) normalizeWeights() {
	total := ia.weightingMatrix.RequestPatternWeight +
		ia.weightingMatrix.TimingWeight +
		ia.weightingMatrix.EndpointWeight +
		ia.weightingMatrix.UserAgentWeight +
		ia.weightingMatrix.GeographicWeight +
		ia.weightingMatrix.TechnicalWeight +
		ia.weightingMatrix.NetworkWeight

	if total > 0 {
		ia.weightingMatrix.RequestPatternWeight /= total
		ia.weightingMatrix.TimingWeight /= total
		ia.weightingMatrix.EndpointWeight /= total
		ia.weightingMatrix.UserAgentWeight /= total
		ia.weightingMatrix.GeographicWeight /= total
		ia.weightingMatrix.TechnicalWeight /= total
		ia.weightingMatrix.NetworkWeight /= total
	}
}

// sendAlert sends an alert through the callback
func (ia *IdentityAnalyzer) sendAlert(alertType AlertType, target string, data map[string]interface{}) {
	if ia.alertCallback != nil {
		ia.alertCallback(alertType, target, data)
	}
}

// Public API methods

// GetIdentity retrieves an identity by ID
func (ia *IdentityAnalyzer) GetIdentity(identityID string) (*Identity, bool) {
	ia.mu.RLock()
	defer ia.mu.RUnlock()
	identity, exists := ia.identities[identityID]
	return identity, exists
}

// GetIdentityByIP retrieves an identity by IP address
func (ia *IdentityAnalyzer) GetIdentityByIP(ip string) (*Identity, bool) {
	ia.mu.RLock()
	defer ia.mu.RUnlock()

	for _, identity := range ia.identities {
		for _, identityIP := range identity.IPs {
			if identityIP == ip {
				return identity, true
			}
		}
	}
	return nil, false
}

// GetSimilarityGroup retrieves a similarity group by ID
func (ia *IdentityAnalyzer) GetSimilarityGroup(groupID string) (*SimilarityGroup, bool) {
	ia.mu.RLock()
	defer ia.mu.RUnlock()
	group, exists := ia.similarityGroups[groupID]
	return group, exists
}

// GetScreeningStrictness returns the screening strictness for an IP
func (ia *IdentityAnalyzer) GetScreeningStrictness(ip string) float64 {
	if identity, exists := ia.GetIdentityByIP(ip); exists {
		return identity.ScreeningStrictness
	}
	return 0.5 // Default moderate strictness
}

// RecordAttackEvent records an attack event for an identity
func (ia *IdentityAnalyzer) RecordAttackEvent(ip string, attackType, severity, description string, metadata map[string]interface{}) {
	ia.mu.Lock()
	defer ia.mu.Unlock()

	if identity, exists := ia.GetIdentityByIP(ip); exists {
		event := AttackEvent{
			Type:        attackType,
			Timestamp:   time.Now(),
			Severity:    severity,
			Description: description,
			Metadata:    metadata,
		}

		identity.AttackHistory = append(identity.AttackHistory, event)

		// Recalculate threat score
		identity.ThreatScore = ia.calculateThreatScore(identity)
		ia.updateScreeningStrictness(identity)

		// Send high threat alert if needed
		if identity.ThreatScore > 80.0 {
			ia.sendAlert(HighThreatIdentity, identity.ID, map[string]interface{}{
				"threat_score": identity.ThreatScore,
				"ip":           ip,
				"attack_type":  attackType,
			})
		}
	}
}

// Stop stops the identity analyzer
func (ia *IdentityAnalyzer) Stop() {
	ia.isRunning = false
}
