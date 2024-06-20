//A sample workflow file which demonstrates the worrking of a reverse proxy which does packet filtering , request logging , load balancing
//This file uses preliminary artifacts such as basic loadbalancer and IP blocking policy.
//Needs Improvement: Integration of sticky http sessions and vector caching of session ID and IP addresses using EBPF

package main

import (
	"io"
	"log"
	"net/http"
	"sync"
	"time"
)

// Global variables for simplicity
var (
	blacklist    = make(map[string]time.Time)
	requestCache = make(map[string]int)
	mutex        = &sync.Mutex{}
	loadBalancer LoadBalancer
)

// Backend servers for load balancing
var backends = []string{"http://localhost:8081", "http://localhost:8082"}

func main() {
	loadBalancer = NewLoadBalancer(backends)

	http.HandleFunc("/", handleRequest)
	log.Println("Starting proxy server on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

// intercepts every single request that the reverse proxy encounters and passes it through a basic ip filter and logs the ip-req combination
// to prevent dos and just drop the request and block it
func handleRequest(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr

	// Check if IP is blacklisted
	if isBlacklisted(clientIP) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Log the request
	if !logRequest(clientIP) {
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	// Forward the request to the least loaded backend
	backend := loadBalancer.GetBackend()
	proxyRequest(w, r, backend)
	loadBalancer.ReleaseBackend(backend)
}

// Packet Filtering
func isBlacklisted(ip string) bool {
	mutex.Lock()
	defer mutex.Unlock()

	blockTime, exists := blacklist[ip]
	if exists && time.Now().Before(blockTime) {
		return true
	}
	return false
}

// Logging and Rate Limiting Requests
// Adds an IP to blacklist if req-origin exceeds particular rate limit temporarily
func logRequest(ip string) bool {
	mutex.Lock()
	defer mutex.Unlock()

	requestCount := requestCache[ip]
	requestCache[ip] = requestCount + 1

	if requestCount > 10 {
		if requestCount > 100 {
			blacklist[ip] = time.Now().Add(24 * time.Hour)
		} else {
			blacklist[ip] = time.Now().Add(1 * time.Minute)
		}
		return false
	}

	go resetRequestCount(ip)
	return true
}

func resetRequestCount(ip string) {
	time.Sleep(1 * time.Second)
	mutex.Lock()
	defer mutex.Unlock()
	requestCache[ip]--
}

// Load Balancing
type LoadBalancer struct {
	servers []string
	counts  map[string]int
	mutex   sync.Mutex
}

func NewLoadBalancer(servers []string) LoadBalancer {
	return LoadBalancer{
		servers: servers,
		counts:  make(map[string]int),
	}
}

// Need to integrate Inspektor gadget to get live connection count of pods of node/deployment to in-turn manipulate the services
func (lb *LoadBalancer) GetBackend() string {
	lb.mutex.Lock()
	defer lb.mutex.Unlock()

	// Least Connection Algorithm
	leastLoaded := lb.servers[0]
	for _, server := range lb.servers {
		if lb.counts[server] < lb.counts[leastLoaded] {
			leastLoaded = server
		}
	}
	lb.counts[leastLoaded]++
	return leastLoaded
}

func (lb *LoadBalancer) ReleaseBackend(backend string) {
	lb.mutex.Lock()
	defer lb.mutex.Unlock()
	lb.counts[backend]--
}

// Proxy Request
func proxyRequest(w http.ResponseWriter, r *http.Request, backend string) {
	resp, err := http.DefaultClient.Get(backend + r.URL.Path)
	if err != nil {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}
