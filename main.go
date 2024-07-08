package main

import (
	loadb "Suboptimal/Firewall/LoadB"
	"fmt"
	"net/http"
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
	for ip, _ := range blist {
		retList = append(retList, ip)
	}
}

func main() {
	// Empty ip list Which will get ip addresses appended to it based on rate limit.
	go Pkfilter_init(ip_list)
	rl := newRateLimiter()
	servers := []loadb.Server{
		loadb.NewServer("https://www.reddit.com"),
	}
	lb := loadb.NewLoadbalancer("8080", servers)
	handleRedirect := func(w http.ResponseWriter, r *http.Request) {

		clientIP := r.RemoteAddr

		if !rl.increment(clientIP) {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		}

		transferIPList(rl.blackList, ip_list)

		lb.ServeProxy(w, r)
	}
	http.HandleFunc("/", handleRedirect)
	fmt.Printf("serving requests at localhost:%s \n", lb.Port)
	http.ListenAndServe(":"+lb.Port, nil)
}
