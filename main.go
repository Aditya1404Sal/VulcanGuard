package main

import (
	loadb "Suboptimal/Firewall/LoadB"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
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

func (rl *rateLimiter) sessionCheck(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if endTime, found := rl.brownList[ip]; found {
		if time.Now().Before(endTime) {
			return false
		} else {
			delete(rl.brownList, ip) // Remove from brown-list after duration expires
			// No point in sending channel here , this needs an invocation which will not be bypassed by the firewall in the first place
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
		log.Printf("IP %s has been brown-listed", ip)
		rl.blacklistCh <- ip
		go startTimer(ip, rl.unblockCh, brownListedDuration)
		return false
	}

	return true
}

func startTimer(ip string, unblockCh chan string, duration time.Duration) {
	time.Sleep(duration)
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
		log.Printf("IP %s has been blacklisted", ip)
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
	logFile, err := os.OpenFile("suboptimal-Firewall.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		fmt.Printf("Error opening log file: %v\n", err)
		return
	}
	defer logFile.Close()
	log.SetOutput(logFile)

	// Log the start of the application
	log.Println("suboptimal-Firewall started")
	unblockCh := make(chan string)
	blacklistCh := make(chan string)
	go PkfilterInit(blacklistCh, unblockCh)
	rl := newRateLimiter(blacklistCh, unblockCh)
	servers := []loadb.Server{
		loadb.NewServer("https://www.youtube.com/"),
		loadb.NewServer("http://localhost:8080"),
	}
	lb := loadb.NewLoadbalancer("8090", servers, "rr")

	handleRedirect := func(w http.ResponseWriter, r *http.Request) {
		clientIP := strings.Split(r.RemoteAddr, ":")[0]
		// Sticky http sessions have a Session-ID Header
		// IP gets Brownlisted : Temporarily blocked
		if sessionID := r.Header.Get("Session-ID"); sessionID != "" {
			ok := rl.sessionCheck(clientIP)
			if !ok {
				http.Error(w, "Session Rate Limit exceeded", http.StatusTooManyRequests)
				log.Printf("Session limit exceeded for IP: %s", clientIP)
				return
			}
		} else {
			if !rl.limitCheck(clientIP) {
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				log.Printf("Rate limit exceeded for IP: %s", clientIP)
				return
			}
		}

		log.Printf("Redirecting request from IP: %s", clientIP)
		lb.ServeProxy(w, r)
	}

	http.HandleFunc("/", handleRedirect)
	log.Printf("Serving requests at localhost:%s", lb.Port)
	fmt.Printf("serving requests at localhost:%s \n", lb.Port)
	http.ListenAndServe(":"+lb.Port, nil)
}
