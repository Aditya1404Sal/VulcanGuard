package main

import (
	loadb "Suboptimal/Firewall/LoadB"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

var (
	ip_list          []string
	rateLimit        = 30
	trackingDuration = 10 * time.Second
)

type rateLimiter struct {
	requests  map[string][]time.Time
	blackList map[string]bool
	mu        sync.Mutex
}

func newRateLimiter() *rateLimiter {
	rl := &rateLimiter{
		requests:  make(map[string][]time.Time),
		blackList: make(map[string]bool),
	}
	go rl.cleanUp()
	return rl
}

func (rl *rateLimiter) increment(ip string) bool {
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
		log.Printf("IP %s has been blacklisted", ip)
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

func transferIPList(blist map[string]bool, retList []string) {
	for ip := range blist {
		retList = append(retList, ip)
	}
}

func main() {
	// Initialize logging to file
	logFile, err := os.OpenFile("suboptimal-Firewall.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		fmt.Printf("Error opening log file: %v\n", err)
		return
	}
	defer logFile.Close()
	log.SetOutput(logFile)

	// Log the start of the application
	log.Println("suboptimal-Firewall started")
	ip_list = append(ip_list, "127.0.0.1")
	// Empty ip list which will get ip addresses appended to it based on rate limit.
	go Pkfilter_init(ip_list)
	rl := newRateLimiter()
	servers := []loadb.Server{
		loadb.NewServer("https://www.google.com/"),
	}
	// "" putting leastconn will turn the loadbalancer into a least connection type
	lb := loadb.NewLoadbalancer("8080", servers, "")
	handleRedirect := func(w http.ResponseWriter, r *http.Request) {
		clientIP := r.RemoteAddr

		if !rl.increment(clientIP) {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			log.Printf("Rate limit exceeded for IP: %s", clientIP)
			return
		}

		transferIPList(rl.blackList, ip_list)

		log.Printf("Redirecting request from IP: %s", clientIP)
		lb.ServeProxy(w, r)
	}
	http.HandleFunc("/", handleRedirect)
	log.Printf("Serving requests at localhost:%s", lb.Port)
	fmt.Printf("serving requests at localhost:%s \n", lb.Port)
	http.ListenAndServe(":"+lb.Port, nil)
}
