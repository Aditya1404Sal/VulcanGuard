package main

import (
	"encoding/json"
	"fmt"
	"net/http"
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
	mu          sync.Mutex
	blacklistCh chan string
	unblockCh   chan string
}

func NewEnhancedIPTracker(blacklistCh, unblockCh chan string) *EnhancedIPTracker {
	return &EnhancedIPTracker{
		ipCache:     make(map[string]*IPInfo),
		blackList:   make(map[string]bool),
		brownList:   make(map[string]time.Time),
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

func (eit *EnhancedIPTracker) CheckRequest(r *http.Request) (bool, *IPInfo) {
	ip := strings.Split(r.RemoteAddr, ":")[0]
	ipInfo, err := eit.GetIPInfo(ip)
	if err != nil {
		fmt.Printf("Error getting IP info: %v\n", err)
		return true, nil
	}

	if eit.isBlacklisted(ip) || eit.isBrownlisted(ip) {
		return false, ipInfo
	}

	if eit.isSuspiciousIP(ipInfo) {
		eit.blackList[ip] = true
		eit.blacklistCh <- ip
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

func (eit *EnhancedIPTracker) isSuspiciousIP(info *IPInfo) bool {
	if info.Proxy || info.Hosting {
		return true
	}
	maliciousASNs := []string{"", ""}
	for _, asn := range maliciousASNs {
		if info.AS == asn {
			return true
		}
	}
	return false
}
