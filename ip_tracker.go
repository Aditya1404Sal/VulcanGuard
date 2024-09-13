package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type IPInfo struct {
	Query       string  `json:"query"`
	Status      string  `json:"status"`
	Continent   string  `json:"continent"`
	Country     string  `json:"country"`
	RegionName  string  `json:"regionName"`
	City        string  `json:"city"`
	ISP         string  `json:"isp"`
	Org         string  `json:"org"`
	AS          string  `json:"as"`
	Mobile      bool    `json:"mobile"`
	Proxy       bool    `json:"proxy"`
	Hosting     bool    `json:"hosting"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	LastChecked time.Time
}

type EnhancedIPTracker struct {
	ipCache     map[string]*IPInfo
	blackList   map[string]bool
	brownList   map[string]time.Time
	rateLimiter *RateLimiter
	mu          sync.Mutex
	blacklistCh chan string
	unblockCh   chan string
}

type RateLimiter struct {
	requests         map[string][]time.Time
	rateLimit        int
	trackingDuration time.Duration
	mu               sync.Mutex
}

func newRateLimiter(rateLimit int, trackingDuration time.Duration) *RateLimiter {
	rl := &RateLimiter{
		requests:         make(map[string][]time.Time),
		rateLimit:        rateLimit,
		trackingDuration: trackingDuration,
	}
	go rl.cleanUp()
	return rl
}

func (rl *RateLimiter) sessionCheck(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	rl.requests[ip] = append(rl.requests[ip], now)

	cutoff := now.Add(-rl.trackingDuration)
	filteredRequests := []time.Time{}

	for _, t := range rl.requests[ip] {
		if t.After(cutoff) {
			filteredRequests = append(filteredRequests, t)
		}
	}
	rl.requests[ip] = filteredRequests

	return len(rl.requests[ip]) <= rl.rateLimit
}

func startTimer(ip string, unblockCh chan string, duration time.Duration) {
	time.Sleep(duration)
	log.Printf("Access to IP %s has been Granted ✅", ip)
	fmt.Printf("\nAccess to IP %s has been Granted ✅", ip)
	unblockCh <- ip
}

func (rl *RateLimiter) cleanUp() {
	for {
		time.Sleep(rl.trackingDuration)
		rl.mu.Lock()
		for ip, times := range rl.requests {
			cutoff := time.Now().Add(-rl.trackingDuration)
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

func create_ip_info_json(ip string) {
	url := fmt.Sprintf("http://ip-api.com/json/%s", ip)
	resp, err := http.Get(url)
	if err != nil {
		log.Println("Could not retrieve any IP information")
		return
	}
	defer resp.Body.Close()
	currTime := time.Now()
	layout := "2006-01-02_15-04-05"
	formattedTime := currTime.Format(layout)
	filename := fmt.Sprintf("./ip_info/results-%s.json", formattedTime)
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Println("Error creating new IP info file")
		return
	}
	defer file.Close()
	_, err = io.Copy(file, resp.Body)
	if err != nil {
		log.Println("Failed to save data to JSON file")
	}
}

func NewEnhancedIPTracker(blacklistCh, unblockCh chan string, rateLimit int, trackingDuration time.Duration) *EnhancedIPTracker {
	return &EnhancedIPTracker{
		ipCache:     make(map[string]*IPInfo),
		blackList:   make(map[string]bool),
		brownList:   make(map[string]time.Time),
		rateLimiter: newRateLimiter(rateLimit, trackingDuration),
		blacklistCh: blacklistCh,
		unblockCh:   unblockCh,
	}
}

func (eit *EnhancedIPTracker) GetIPInfo(ip string) (*IPInfo, error) {
	eit.mu.Lock()
	defer eit.mu.Unlock()
	if info, exists := eit.ipCache[ip]; exists && time.Since(info.LastChecked) < 24*time.Hour {
		return info, nil
	}
	url := fmt.Sprintf("http://ip-api.com/json/%s", ip)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var ipInfo IPInfo
	if err := json.NewDecoder(resp.Body).Decode(&ipInfo); err != nil {
		return nil, err
	}
	ipInfo.LastChecked = time.Now()
	eit.ipCache[ip] = &ipInfo
	return &ipInfo, nil
}

// New function to check if an IP should be blacklisted based on its country
func (eit *EnhancedIPTracker) CheckBlacklist(ip string) bool {
	eit.mu.Lock()
	defer eit.mu.Unlock()

	ipInfo, err := eit.GetIPInfo(ip)
	if err != nil {
		log.Printf("Error getting IP info for %s: %v\n", ip, err)
		return false
	}
	if ipInfo.Proxy || ipInfo.Hosting {
		return true
	}

	// Global malicious asn's can be acquired by a db call ig ??
	maliciousASNs := []string{"", ""}
	for _, asn := range maliciousASNs {
		if ipInfo.AS == asn {
			return true
		}
	}

	// Check if there are any blacklisted IPs from the same country, ASN, or ISP
	for blacklistedIP := range eit.blackList {
		if blacklistedInfo, exists := eit.ipCache[blacklistedIP]; exists {
			// Check for country similarity
			if blacklistedInfo.Country == ipInfo.Country {
				return true // This IP should be blacklisted due to country
			}
			// Check for ASN similarity
			if blacklistedInfo.AS == ipInfo.AS {
				return true // This IP should be blacklisted due to ASN
			}
			// Check for ISP similarity
			if blacklistedInfo.ISP == ipInfo.ISP {
				return true // This IP should be blacklisted due to ISP
			}
		}
	}
	return false
}

func (eit *EnhancedIPTracker) CheckRequest(r *http.Request) (bool, *IPInfo) {
	ip := strings.Split(r.RemoteAddr, ":")[0]
	ipInfo, err := eit.GetIPInfo(ip)
	if err != nil {
		fmt.Printf("Error getting IP info: %v\n", err)
		return true, nil
	}

	if eit.isBlacklisted(ip) || eit.isBrownlisted(ip) || eit.CheckBlacklist(ip) {
		eit.blackList[ip] = true
		eit.blacklistCh <- ip
		create_ip_info_json(ip)
		return false, ipInfo
	}

	if !eit.rateLimiter.sessionCheck(ip) {
		eit.brownList[ip] = time.Now().Add(25 * time.Second)
		eit.blacklistCh <- ip
		create_ip_info_json(ip)
		go startTimer(ip, eit.unblockCh, 25*time.Second)
		return false, ipInfo
	}

	return true, ipInfo
}

func (eit *EnhancedIPTracker) isBlacklisted(ip string) bool {
	eit.mu.Lock()
	defer eit.mu.Unlock()
	return eit.blackList[ip]
}

func (eit *EnhancedIPTracker) isBrownlisted(ip string) bool {
	eit.mu.Lock()
	defer eit.mu.Unlock()
	if endTime, found := eit.brownList[ip]; found {
		if time.Now().Before(endTime) {
			return true
		}
		delete(eit.brownList, ip)
	}
	return false
}
