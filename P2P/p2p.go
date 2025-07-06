package p2p

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

// P2PNetwork manages peer-to-peer communication between VulcanGuard instances
type P2PNetwork struct {
	nodeID       string
	peers        map[string]*Peer
	localCache   *KnowledgeCache
	mu           sync.RWMutex
	broadcastCh  chan *ThreatIntelligence
	receiveCh    chan *ThreatIntelligence
	httpServer   *http.Server
	port         string
	isRunning    bool
	syncInterval time.Duration
}

// Peer represents a remote VulcanGuard instance
type Peer struct {
	ID       string    `json:"id"`
	Address  string    `json:"address"`
	Port     string    `json:"port"`
	LastSeen time.Time `json:"last_seen"`
	Health   string    `json:"health"` // "healthy", "degraded", "down"
	Version  string    `json:"version"`
	Region   string    `json:"region"`
}

// ThreatIntelligence represents shared threat data
type ThreatIntelligence struct {
	ID             string                 `json:"id"`
	Type           string                 `json:"type"` // "blacklist", "pattern", "attack_signature"
	Source         string                 `json:"source"`
	Timestamp      time.Time              `json:"timestamp"`
	ExpiresAt      time.Time              `json:"expires_at"`
	Severity       string                 `json:"severity"` // "low", "medium", "high", "critical"
	IPAddresses    []string               `json:"ip_addresses,omitempty"`
	IPRanges       []string               `json:"ip_ranges,omitempty"`
	AttackPatterns []AttackPattern        `json:"attack_patterns,omitempty"`
	BehavioralSigs []BehavioralSignature  `json:"behavioral_signatures,omitempty"`
	GeographicData *GeographicThreat      `json:"geographic_data,omitempty"`
	Confidence     float64                `json:"confidence"` // 0.0 - 1.0
	Metadata       map[string]interface{} `json:"metadata"`
	Verified       bool                   `json:"verified"`
	ReportedBy     []string               `json:"reported_by"`
}

// AttackPattern represents a detected attack pattern
type AttackPattern struct {
	Name            string   `json:"name"`
	Signature       string   `json:"signature"`
	RequestPattern  string   `json:"request_pattern"`
	UserAgentRegex  string   `json:"user_agent_regex"`
	EndpointTargets []string `json:"endpoint_targets"`
	Frequency       float64  `json:"frequency"`
	Description     string   `json:"description"`
}

// BehavioralSignature represents behavioral threat indicators
type BehavioralSignature struct {
	Name                string  `json:"name"`
	RequestFrequency    float64 `json:"request_frequency"`
	EndpointDiversity   int     `json:"endpoint_diversity"`
	UserAgentCount      int     `json:"user_agent_count"`
	ErrorRate           float64 `json:"error_rate"`
	RegularIntervals    bool    `json:"regular_intervals"`
	GeographicPattern   string  `json:"geographic_pattern"`
	SimilarityThreshold float64 `json:"similarity_threshold"`
}

// GeographicThreat represents geographic threat information
type GeographicThreat struct {
	Countries   []string `json:"countries"`
	Regions     []string `json:"regions"`
	ISPs        []string `json:"isps"`
	ThreatLevel string   `json:"threat_level"`
	Description string   `json:"description"`
}

// KnowledgeCache stores and manages threat intelligence data
type KnowledgeCache struct {
	threats   map[string]*ThreatIntelligence
	blacklist map[string]time.Time // IP -> expiration time
	patterns  map[string]*AttackPattern
	mu        sync.RWMutex
	maxSize   int
	ttl       time.Duration
}

// P2PMessage represents communication between peers
type P2PMessage struct {
	Type      string      `json:"type"` // "threat_intel", "peer_discovery", "health_check"
	Source    string      `json:"source"`
	Target    string      `json:"target"` // empty for broadcast
	Timestamp time.Time   `json:"timestamp"`
	Data      interface{} `json:"data"`
	MessageID string      `json:"message_id"`
}

// NewP2PNetwork creates a new P2P network instance
func NewP2PNetwork(nodeID, port string) *P2PNetwork {
	network := &P2PNetwork{
		nodeID:       nodeID,
		peers:        make(map[string]*Peer),
		localCache:   NewKnowledgeCache(10000, 24*time.Hour),
		broadcastCh:  make(chan *ThreatIntelligence, 1000),
		receiveCh:    make(chan *ThreatIntelligence, 1000),
		port:         port,
		isRunning:    true,
		syncInterval: 5 * time.Minute,
	}

	// Start background workers
	go network.broadcastWorker()
	go network.syncWorker()
	go network.cleanupWorker()

	// Start HTTP server for peer communication
	network.startHTTPServer()

	return network
}

// NewKnowledgeCache creates a new knowledge cache
func NewKnowledgeCache(maxSize int, ttl time.Duration) *KnowledgeCache {
	cache := &KnowledgeCache{
		threats:   make(map[string]*ThreatIntelligence),
		blacklist: make(map[string]time.Time),
		patterns:  make(map[string]*AttackPattern),
		maxSize:   maxSize,
		ttl:       ttl,
	}

	// Start cleanup goroutine
	go cache.cleanup()

	return cache
}

// AddPeer adds a new peer to the network
func (p2p *P2PNetwork) AddPeer(id, address, port string) {
	p2p.mu.Lock()
	defer p2p.mu.Unlock()

	peer := &Peer{
		ID:       id,
		Address:  address,
		Port:     port,
		LastSeen: time.Now(),
		Health:   "unknown",
		Version:  "1.0.0",
	}

	p2p.peers[id] = peer
	log.Printf("Added peer %s at %s:%s", id, address, port)

	// Initiate health check
	go p2p.healthCheckPeer(peer)
}

// ShareThreatIntelligence shares threat intelligence with the network
func (p2p *P2PNetwork) ShareThreatIntelligence(intel *ThreatIntelligence) {
	intel.Source = p2p.nodeID
	intel.Timestamp = time.Now()

	// Add to local cache
	p2p.localCache.AddThreat(intel)

	// Broadcast to network
	select {
	case p2p.broadcastCh <- intel:
		log.Printf("Threat intelligence queued for broadcast: %s", intel.ID)
	default:
		log.Printf("Broadcast queue full, dropping threat intelligence: %s", intel.ID)
	}
}

// broadcastWorker handles broadcasting threat intelligence to peers
func (p2p *P2PNetwork) broadcastWorker() {
	for p2p.isRunning {
		select {
		case intel := <-p2p.broadcastCh:
			p2p.broadcastThreatIntelligence(intel)
		case <-time.After(100 * time.Millisecond):
			// Check isRunning periodically
		}
	}
}

// broadcastThreatIntelligence sends threat intelligence to all healthy peers
func (p2p *P2PNetwork) broadcastThreatIntelligence(intel *ThreatIntelligence) {
	p2p.mu.RLock()
	healthyPeers := make([]*Peer, 0)
	for _, peer := range p2p.peers {
		if peer.Health == "healthy" {
			healthyPeers = append(healthyPeers, peer)
		}
	}
	p2p.mu.RUnlock()

	message := &P2PMessage{
		Type:      "threat_intel",
		Source:    p2p.nodeID,
		Timestamp: time.Now(),
		Data:      intel,
		MessageID: generateMessageID(),
	}

	for _, peer := range healthyPeers {
		go p2p.sendMessageToPeer(peer, message)
	}
}

// sendMessageToPeer sends a message to a specific peer
func (p2p *P2PNetwork) sendMessageToPeer(peer *Peer, message *P2PMessage) {
	url := fmt.Sprintf("http://%s:%s/p2p/message", peer.Address, peer.Port)

	jsonData, err := json.Marshal(message)
	if err != nil {
		log.Printf("Failed to marshal message for peer %s: %v", peer.ID, err)
		return
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Failed to send message to peer %s: %v", peer.ID, err)
		p2p.markPeerUnhealthy(peer.ID)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Peer %s returned error status: %d", peer.ID, resp.StatusCode)
		p2p.markPeerUnhealthy(peer.ID)
	} else {
		p2p.markPeerHealthy(peer.ID)
	}
}

// startHTTPServer starts the HTTP server for peer communication
func (p2p *P2PNetwork) startHTTPServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/p2p/message", p2p.handleP2PMessage)
	mux.HandleFunc("/p2p/health", p2p.handleHealthCheck)
	mux.HandleFunc("/p2p/peers", p2p.handlePeerDiscovery)
	mux.HandleFunc("/p2p/sync", p2p.handleSync)

	server := &http.Server{
		Addr:    ":" + p2p.port,
		Handler: mux,
	}

	p2p.httpServer = server

	go func() {
		log.Printf("P2P server starting on port %s", p2p.port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("P2P server error: %v", err)
		}
	}()
}

// handleP2PMessage handles incoming P2P messages
func (p2p *P2PNetwork) handleP2PMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var message P2PMessage
	if err := json.NewDecoder(r.Body).Decode(&message); err != nil {
		log.Printf("Failed to decode P2P message: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	switch message.Type {
	case "threat_intel":
		p2p.processThreatIntelligence(&message)
	case "peer_discovery":
		p2p.processPeerDiscovery(&message)
	default:
		log.Printf("Unknown P2P message type: %s", message.Type)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// processThreatIntelligence processes received threat intelligence
func (p2p *P2PNetwork) processThreatIntelligence(message *P2PMessage) {
	data, ok := message.Data.(map[string]interface{})
	if !ok {
		log.Printf("Invalid threat intelligence data format")
		return
	}

	// Convert map to ThreatIntelligence struct
	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Printf("Failed to marshal threat data: %v", err)
		return
	}

	var intel ThreatIntelligence
	if err := json.Unmarshal(jsonData, &intel); err != nil {
		log.Printf("Failed to unmarshal threat intelligence: %v", err)
		return
	}

	// Validate and process the threat intelligence
	if p2p.validateThreatIntelligence(&intel) {
		p2p.localCache.AddThreat(&intel)
		log.Printf("Received and processed threat intelligence from %s: %s", message.Source, intel.ID)

		// Forward to local processing channel
		select {
		case p2p.receiveCh <- &intel:
		default:
			log.Printf("Receive channel full, dropping threat intelligence")
		}
	}
}

// processPeerDiscovery processes peer discovery messages
func (p2p *P2PNetwork) processPeerDiscovery(message *P2PMessage) {
	// Extract peer information from the message
	data, ok := message.Data.(map[string]interface{})
	if !ok {
		log.Printf("Invalid peer discovery data format")
		return
	}

	// Process peer information
	if peerID, exists := data["peer_id"].(string); exists {
		if address, addrExists := data["address"].(string); addrExists {
			if port, portExists := data["port"].(string); portExists {
				p2p.AddPeer(peerID, address, port)
				log.Printf("Discovered new peer via P2P: %s at %s:%s", peerID, address, port)
			}
		}
	}
}

// validateThreatIntelligence validates received threat intelligence
func (p2p *P2PNetwork) validateThreatIntelligence(intel *ThreatIntelligence) bool {
	// Basic validation
	if intel.ID == "" || intel.Type == "" || intel.Source == "" {
		return false
	}

	// Check if not expired
	if time.Now().After(intel.ExpiresAt) {
		return false
	}

	// Check confidence threshold
	if intel.Confidence < 0.5 {
		return false
	}

	// Additional validation logic can be added here
	return true
}

// handleHealthCheck handles health check requests
func (p2p *P2PNetwork) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"node_id":    p2p.nodeID,
		"status":     "healthy",
		"timestamp":  time.Now(),
		"peer_count": len(p2p.peers),
		"cache_size": p2p.localCache.Size(),
		"version":    "1.0.0",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// handlePeerDiscovery handles peer discovery requests
func (p2p *P2PNetwork) handlePeerDiscovery(w http.ResponseWriter, r *http.Request) {
	p2p.mu.RLock()
	peers := make([]*Peer, 0, len(p2p.peers))
	for _, peer := range p2p.peers {
		if peer.Health == "healthy" {
			peers = append(peers, peer)
		}
	}
	p2p.mu.RUnlock()

	response := map[string]interface{}{
		"node_id": p2p.nodeID,
		"peers":   peers,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleSync handles synchronization requests
func (p2p *P2PNetwork) handleSync(w http.ResponseWriter, r *http.Request) {
	since := r.URL.Query().Get("since")
	var sinceTime time.Time
	if since != "" {
		if t, err := time.Parse(time.RFC3339, since); err == nil {
			sinceTime = t
		}
	}

	threats := p2p.localCache.GetThreatsSince(sinceTime)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(threats)
}

// syncWorker periodically syncs with peers
func (p2p *P2PNetwork) syncWorker() {
	ticker := time.NewTicker(p2p.syncInterval)
	defer ticker.Stop()

	for p2p.isRunning {
		select {
		case <-ticker.C:
			p2p.syncWithPeers()
		case <-time.After(100 * time.Millisecond):
			// Check isRunning periodically
		}
	}
}

// syncWithPeers syncs threat intelligence with all peers
func (p2p *P2PNetwork) syncWithPeers() {
	p2p.mu.RLock()
	peers := make([]*Peer, 0, len(p2p.peers))
	for _, peer := range p2p.peers {
		if peer.Health == "healthy" {
			peers = append(peers, peer)
		}
	}
	p2p.mu.RUnlock()

	for _, peer := range peers {
		go p2p.syncWithPeer(peer)
	}
}

// syncWithPeer syncs threat intelligence with a specific peer
func (p2p *P2PNetwork) syncWithPeer(peer *Peer) {
	// Get threats since last sync (last 1 hour for simplicity)
	since := time.Now().Add(-time.Hour).Format(time.RFC3339)
	url := fmt.Sprintf("http://%s:%s/p2p/sync?since=%s", peer.Address, peer.Port, since)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		log.Printf("Failed to sync with peer %s: %v", peer.ID, err)
		p2p.markPeerUnhealthy(peer.ID)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Sync failed with peer %s: status %d", peer.ID, resp.StatusCode)
		return
	}

	var threats []*ThreatIntelligence
	if err := json.NewDecoder(resp.Body).Decode(&threats); err != nil {
		log.Printf("Failed to decode sync response from peer %s: %v", peer.ID, err)
		return
	}

	// Process received threats
	for _, threat := range threats {
		if p2p.validateThreatIntelligence(threat) {
			p2p.localCache.AddThreat(threat)
		}
	}

	log.Printf("Synced %d threats with peer %s", len(threats), peer.ID)
	p2p.markPeerHealthy(peer.ID)
}

// healthCheckPeer performs health check on a peer
func (p2p *P2PNetwork) healthCheckPeer(peer *Peer) {
	url := fmt.Sprintf("http://%s:%s/p2p/health", peer.Address, peer.Port)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		log.Printf("Health check failed for peer %s: %v", peer.ID, err)
		p2p.markPeerUnhealthy(peer.ID)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		p2p.markPeerHealthy(peer.ID)
	} else {
		p2p.markPeerUnhealthy(peer.ID)
	}
}

// markPeerHealthy marks a peer as healthy
func (p2p *P2PNetwork) markPeerHealthy(peerID string) {
	p2p.mu.Lock()
	defer p2p.mu.Unlock()

	if peer, exists := p2p.peers[peerID]; exists {
		peer.Health = "healthy"
		peer.LastSeen = time.Now()
	}
}

// markPeerUnhealthy marks a peer as unhealthy
func (p2p *P2PNetwork) markPeerUnhealthy(peerID string) {
	p2p.mu.Lock()
	defer p2p.mu.Unlock()

	if peer, exists := p2p.peers[peerID]; exists {
		if peer.Health == "healthy" {
			peer.Health = "degraded"
		} else {
			peer.Health = "down"
		}
	}
}

// cleanupWorker removes unhealthy peers periodically
func (p2p *P2PNetwork) cleanupWorker() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for p2p.isRunning {
		select {
		case <-ticker.C:
			p2p.cleanupUnhealthyPeers()
		case <-time.After(100 * time.Millisecond):
			// Check isRunning periodically
		}
	}
}

// cleanupUnhealthyPeers removes peers that have been down for too long
func (p2p *P2PNetwork) cleanupUnhealthyPeers() {
	p2p.mu.Lock()
	defer p2p.mu.Unlock()

	threshold := time.Now().Add(-24 * time.Hour)
	for id, peer := range p2p.peers {
		if peer.Health == "down" && peer.LastSeen.Before(threshold) {
			delete(p2p.peers, id)
			log.Printf("Removed unhealthy peer: %s", id)
		}
	}
}

// Knowledge Cache Methods

// AddThreat adds threat intelligence to the cache
func (kc *KnowledgeCache) AddThreat(intel *ThreatIntelligence) {
	kc.mu.Lock()
	defer kc.mu.Unlock()

	// Enforce cache size limit
	if len(kc.threats) >= kc.maxSize {
		kc.evictOldestThreat()
	}

	kc.threats[intel.ID] = intel

	// Add IPs to blacklist
	for _, ip := range intel.IPAddresses {
		kc.blacklist[ip] = intel.ExpiresAt
	}

	// Add patterns
	for _, pattern := range intel.AttackPatterns {
		kc.patterns[pattern.Name] = &pattern
	}
}

// GetThreat retrieves threat intelligence by ID
func (kc *KnowledgeCache) GetThreat(id string) (*ThreatIntelligence, bool) {
	kc.mu.RLock()
	defer kc.mu.RUnlock()

	threat, exists := kc.threats[id]
	return threat, exists
}

// IsBlacklisted checks if an IP is blacklisted
func (kc *KnowledgeCache) IsBlacklisted(ip string) bool {
	kc.mu.RLock()
	defer kc.mu.RUnlock()

	expiration, exists := kc.blacklist[ip]
	if !exists {
		return false
	}

	// Check if blacklist entry has expired
	if time.Now().After(expiration) {
		return false
	}

	return true
}

// GetThreatsSince returns all threats since a given time
func (kc *KnowledgeCache) GetThreatsSince(since time.Time) []*ThreatIntelligence {
	kc.mu.RLock()
	defer kc.mu.RUnlock()

	threats := make([]*ThreatIntelligence, 0)
	for _, threat := range kc.threats {
		if threat.Timestamp.After(since) {
			threats = append(threats, threat)
		}
	}

	return threats
}

// Size returns the number of threats in the cache
func (kc *KnowledgeCache) Size() int {
	kc.mu.RLock()
	defer kc.mu.RUnlock()
	return len(kc.threats)
}

// evictOldestThreat removes the oldest threat from cache
func (kc *KnowledgeCache) evictOldestThreat() {
	var oldestID string
	var oldestTime time.Time

	for id, threat := range kc.threats {
		if oldestID == "" || threat.Timestamp.Before(oldestTime) {
			oldestID = id
			oldestTime = threat.Timestamp
		}
	}

	if oldestID != "" {
		threat := kc.threats[oldestID]
		delete(kc.threats, oldestID)

		// Remove associated blacklist entries
		for _, ip := range threat.IPAddresses {
			delete(kc.blacklist, ip)
		}

		// Remove associated patterns
		for _, pattern := range threat.AttackPatterns {
			delete(kc.patterns, pattern.Name)
		}
	}
}

// cleanup removes expired threats
func (kc *KnowledgeCache) cleanup() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		kc.cleanupExpired()
	}
}

// cleanupExpired removes expired threats and blacklist entries
func (kc *KnowledgeCache) cleanupExpired() {
	kc.mu.Lock()
	defer kc.mu.Unlock()

	now := time.Now()

	// Remove expired threats
	for id, threat := range kc.threats {
		if now.After(threat.ExpiresAt) {
			delete(kc.threats, id)
		}
	}

	// Remove expired blacklist entries
	for ip, expiration := range kc.blacklist {
		if now.After(expiration) {
			delete(kc.blacklist, ip)
		}
	}
}

// Utility functions

// generateMessageID generates a unique message ID
func generateMessageID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// GetReceivedIntelligence returns the channel for received threat intelligence
func (p2p *P2PNetwork) GetReceivedIntelligence() <-chan *ThreatIntelligence {
	return p2p.receiveCh
}

// GetKnowledgeCache returns the local knowledge cache
func (p2p *P2PNetwork) GetKnowledgeCache() *KnowledgeCache {
	return p2p.localCache
}

// Stop stops the P2P network
func (p2p *P2PNetwork) Stop() {
	p2p.isRunning = false
	if p2p.httpServer != nil {
		p2p.httpServer.Close()
	}
}
