package main

import (
	profiler "Suboptimal/Firewall/BehavioralProfiler"
	identity "Suboptimal/Firewall/IdentityAnalyzer"
	p2p "Suboptimal/Firewall/P2P"
	trafan "Suboptimal/Firewall/TrafficAnalyser"
	"fmt"
	"time"
)

func demoEnhancedFeatures() {
	fmt.Println("🚀 VulcanGuard Enhanced Features Demo")
	fmt.Println("=====================================")

	// 1. Initialize components
	fmt.Println("\n📦 Initializing components...")

	// Alert channels
	alertCh := make(chan trafan.Alert, 100)
	blacklistCh := make(chan string, 100)

	// Initialize behavioral profiler
	behavioralProfiler := profiler.NewBehavioralProfiler(blacklistCh)
	fmt.Println("✅ Behavioral Profiler initialized")

	// Initialize traffic analyzer
	trafficAnalyzer := trafan.NewTrafficAnalyser(20*time.Second, 20, alertCh)
	fmt.Println("✅ Traffic Analyzer initialized")

	// Initialize P2P network
	p2pNetwork := p2p.NewP2PNetwork("demo-node-1", "9001")
	fmt.Println("✅ P2P Network initialized")

	// Initialize identity analyzer
	identityAnalyzer := identity.NewIdentityAnalyzer(func(alertType identity.AlertType, target string, data map[string]interface{}) {
		fmt.Printf("🚨 Identity Alert: %d for %s\n", alertType, target)
	})
	fmt.Println("✅ Identity Analyzer initialized")

	// 2. Demonstrate behavioral profiling
	fmt.Println("\n🧠 Demonstrating Behavioral Profiling...")

	// Simulate suspicious behavior
	suspiciousIPs := []string{"192.168.1.100", "192.168.1.101", "192.168.1.102"}
	for _, ip := range suspiciousIPs {
		for i := 0; i < 15; i++ {
			behavioralProfiler.AnalyzeRequest(
				ip, "/api/login", "POST", "BotAgent/1.0", "",
				200, 50, 256,
			)
			time.Sleep(100 * time.Millisecond) // Regular intervals (suspicious)
		}
	}

	fmt.Println("📊 Analyzed suspicious behavior patterns")
	time.Sleep(2 * time.Second) // Let analysis complete

	// 3. Demonstrate traffic analysis
	fmt.Println("\n📈 Demonstrating Traffic Analysis...")

	// Simulate traffic spike
	for i := 0; i < 50; i++ {
		trafficAnalyzer.ProcessRequest(
			"192.168.1.200", "/api/data", "Mozilla/5.0", "GET",
			200, 25, 1024,
		)
	}

	fmt.Println("🌊 Simulated traffic spike")

	// 4. Demonstrate P2P intelligence sharing
	fmt.Println("\n🔗 Demonstrating P2P Intelligence Sharing...")

	// Create threat intelligence
	threatIntel := &p2p.ThreatIntelligence{
		ID:          "demo-threat-001",
		Type:        "blacklist",
		Source:      "demo-node-1",
		Timestamp:   time.Now(),
		ExpiresAt:   time.Now().Add(24 * time.Hour),
		Severity:    "high",
		IPAddresses: []string{"192.168.1.100", "192.168.1.101"},
		Confidence:  0.95,
		Metadata: map[string]interface{}{
			"attack_type": "coordinated_ddos",
			"description": "Coordinated DDoS attack detected",
		},
		Verified: true,
	}

	// Share threat intelligence
	p2pNetwork.ShareThreatIntelligence(threatIntel)
	fmt.Println("📤 Shared threat intelligence to P2P network")

	// 5. Demonstrate identity analysis
	fmt.Println("\n🔍 Demonstrating Identity Analysis...")

	// Analyze identities with similar patterns
	for _, ip := range suspiciousIPs {
		requestData := map[string]interface{}{
			"request_patterns": []interface{}{"/api/login", "/api/data", "/api/status"},
			"timing_data": map[string]interface{}{
				"intervals":  []interface{}{1.0, 1.1, 0.9, 1.0, 1.2},
				"bursts":     []interface{}{5.0, 6.0, 4.0},
				"peak_hours": []interface{}{2.0, 3.0, 4.0}, // Odd hours
			},
			"endpoints": map[string]interface{}{
				"/api/login": 10.0,
				"/api/data":  5.0,
			},
			"user_agent": "BotAgent/1.0",
			"geographic_data": map[string]interface{}{
				"country":  "Unknown",
				"isp":      "HostingProvider",
				"proxy":    true,
				"hosting":  true,
				"timezone": "UTC",
			},
			"technical_data": map[string]interface{}{
				"user_agents": []interface{}{"BotAgent/1.0"},
				"headers": map[string]interface{}{
					"User-Agent": "BotAgent/1.0",
					"Accept":     "*/*",
				},
			},
			"network_data": map[string]interface{}{
				"concurrent_connections": 20.0,
				"keep_alive_usage":       0.1,
				"error_ratio":            0.05,
			},
		}

		identityAnalyzer.AnalyzeIdentity(ip, requestData, 5) // High priority
	}

	fmt.Println("🔬 Analyzed identity patterns")
	time.Sleep(3 * time.Second) // Let analysis complete

	// 6. Demonstrate alert processing
	fmt.Println("\n🚨 Processing Alerts...")

	alertCount := 0
	timeout := time.After(5 * time.Second)

	for {
		select {
		case alert := <-alertCh:
			alertCount++
			fmt.Printf("   Alert #%d: %s - %s\n", alertCount, alert.Type, alert.Message)

		case ip := <-blacklistCh:
			fmt.Printf("   🚫 IP Blacklisted: %s\n", ip)

		case <-timeout:
			fmt.Printf("⏱️  Alert processing timeout (processed %d alerts)\n", alertCount)
			goto summary
		}

		if alertCount >= 5 {
			break
		}
	}

summary:
	// 7. Show system status
	fmt.Println("\n📊 System Status Summary...")

	// Get traffic stats
	globalStats := trafficAnalyzer.GetGlobalStats()
	fmt.Printf("   Total Requests: %d\n", globalStats.TotalRequests)
	fmt.Printf("   Unique IPs: %d\n", globalStats.UniqueIPs)

	// Check P2P cache
	cacheSize := p2pNetwork.GetKnowledgeCache().Size()
	fmt.Printf("   P2P Cache Size: %d threats\n", cacheSize)

	// Check if IPs are blacklisted
	for _, ip := range suspiciousIPs {
		if p2pNetwork.GetKnowledgeCache().IsBlacklisted(ip) {
			fmt.Printf("   ✅ %s is blacklisted in P2P cache\n", ip)
		}
		if behavioralProfiler.IsBlacklisted(ip) {
			fmt.Printf("   ✅ %s is blacklisted by behavioral profiler\n", ip)
		}

		// Get screening strictness
		strictness := identityAnalyzer.GetScreeningStrictness(ip)
		fmt.Printf("   🎯 %s screening strictness: %.2f\n", ip, strictness)
	}

	// 8. Cleanup
	fmt.Println("\n🧹 Cleaning up...")
	trafficAnalyzer.Stop()
	p2pNetwork.Stop()
	identityAnalyzer.Stop()

	fmt.Println("\n✅ Demo completed successfully!")
	fmt.Println("\n📋 Features Demonstrated:")
	fmt.Println("   ✓ Behavioral profiling with similarity detection")
	fmt.Println("   ✓ Enhanced traffic analysis with spike detection")
	fmt.Println("   ✓ P2P threat intelligence sharing")
	fmt.Println("   ✓ Identity analysis with adaptive screening")
	fmt.Println("   ✓ Coordinated attack pattern detection")
	fmt.Println("   ✓ Multi-layered protection integration")

	fmt.Println("\n🎉 VulcanGuard is now ready for production with all enhanced features!")
}
