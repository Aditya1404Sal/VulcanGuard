package main

import (
	loadb "Suboptimal/Firewall/LoadB"
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

func main() {
	// Initialize logging to file
	rateLimit := 25
	trackingDuration := 20 * time.Second

	os.Mkdir("./ip_info", 0755)
	logFile, err := os.OpenFile("Firewall.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		fmt.Printf("Error opening log file: %v\n", err)
		return
	}
	defer logFile.Close()
	log.SetOutput(logFile)

	log.Println("\nFirewall Activated 🛡")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	unblockCh := make(chan string)
	blacklistCh := make(chan string)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		PkfilterInit(ctx, blacklistCh, unblockCh)
	}()

	eit := NewEnhancedIPTracker(blacklistCh, unblockCh, rateLimit, trackingDuration)
	et := NewEndpointTracker()
	ta := NewTrafficAnalyzer()

	go et.cleanUpStats()
	go et.cleanUpHourlyStats()
	go ta.AnalyzeTraffic()

	servers := []loadb.Server{
		loadb.NewServer("https://www.youtube.com/"),
		loadb.NewServer("https://wasmcloud.com/"),
		loadb.NewServer("https://x.com/"),
	}
	lb := loadb.NewLoadbalancer("8080", servers, "lc")

	handleRedirect := func(w http.ResponseWriter, r *http.Request) {
		allowed, ipInfo := eit.CheckRequest(r)
		if !allowed {
			http.Error(w, "Request blocked due to suspicious behavior", http.StatusForbidden)
			return
		}

		if !et.TrackRequest(r.URL.Path) {
			http.Error(w, "Endpoint is currently rate-limited", http.StatusTooManyRequests)
			return
		}

		if ipInfo != nil {
			log.Printf("Request from IP: %s, Country: %s, ISP: %s, Proxy: %v, Hosting: %v",
				ipInfo.Query, ipInfo.Country, ipInfo.ISP, ipInfo.Proxy, ipInfo.Hosting)
		}

		lb.ServeProxy(w, r)
	}

	http.HandleFunc("/", handleRedirect)

	serverErrors := make(chan error, 1)
	go func() {
		log.Printf("Serving requests at localhost:%s", lb.Port)
		fmt.Printf("Serving requests at localhost:%s\n", lb.Port)
		serverErrors <- http.ListenAndServe(":"+lb.Port, nil)
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	select {
	case <-sigCh:
		fmt.Println("\nReceived shutdown signal. Stopping...")
	case err := <-serverErrors:
		fmt.Printf("Server error: %v\n", err)
	}

	cancel()
	wg.Wait()

	fmt.Println("All operations stopped. Goodbye! 😭👋")
}
