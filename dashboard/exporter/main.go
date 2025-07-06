package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/gorilla/mux"
	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
	"github.com/influxdata/influxdb-client-go/v2/api"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type VulcanGuardExporter struct {
	redisClient    *redis.Client
	influxClient   influxdb2.Client
	influxWriteAPI api.WriteAPI

	// Prometheus metrics
	totalRequests       prometheus.Counter
	blockedRequests     prometheus.Counter
	allowedRequests     prometheus.Counter
	activeConnections   prometheus.Gauge
	blacklistedIPs      prometheus.Gauge
	requestsByCountry   *prometheus.GaugeVec
	behavioralAnomalies prometheus.Counter
	similarityMatches   prometheus.Counter
	p2pActivePeers      prometheus.Gauge
	p2pSharedThreats    prometheus.Counter
}

type RequestData struct {
	IP        string  `json:"ip"`
	Country   string  `json:"country"`
	City      string  `json:"city"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	Timestamp int64   `json:"timestamp"`
	Blocked   bool    `json:"blocked"`
	Endpoint  string  `json:"endpoint"`
}

type GeolocationData struct {
	Country   string  `json:"country"`
	City      string  `json:"city"`
	Latitude  float64 `json:"lat"`
	Longitude float64 `json:"lon"`
	Requests  int     `json:"requests"`
}

func NewVulcanGuardExporter() *VulcanGuardExporter {
	// Redis connection
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		redisURL = "localhost:6379"
	}

	rdb := redis.NewClient(&redis.Options{
		Addr: redisURL,
	})

	// InfluxDB connection
	influxURL := os.Getenv("INFLUXDB_URL")
	if influxURL == "" {
		influxURL = "http://localhost:8086"
	}

	token := os.Getenv("INFLUXDB_TOKEN")
	org := os.Getenv("INFLUXDB_ORG")
	bucket := os.Getenv("INFLUXDB_BUCKET")

	influxClient := influxdb2.NewClient(influxURL, token)
	writeAPI := influxClient.WriteAPI(org, bucket)

	exporter := &VulcanGuardExporter{
		redisClient:    rdb,
		influxClient:   influxClient,
		influxWriteAPI: writeAPI,

		totalRequests: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "vulcanguard_requests_total",
			Help: "Total number of requests processed",
		}),
		blockedRequests: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "vulcanguard_blocked_requests_total",
			Help: "Total number of blocked requests",
		}),
		allowedRequests: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "vulcanguard_allowed_requests_total",
			Help: "Total number of allowed requests",
		}),
		activeConnections: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "vulcanguard_active_connections",
			Help: "Number of active connections",
		}),
		blacklistedIPs: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "vulcanguard_blacklisted_ips",
			Help: "Number of blacklisted IP addresses",
		}),
		requestsByCountry: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "vulcanguard_requests_by_country",
			Help: "Number of requests by country",
		}, []string{"country"}),
		behavioralAnomalies: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "vulcanguard_behavioral_anomalies_total",
			Help: "Total number of behavioral anomalies detected",
		}),
		similarityMatches: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "vulcanguard_similarity_matches_total",
			Help: "Total number of similarity matches found",
		}),
		p2pActivePeers: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "vulcanguard_p2p_active_peers",
			Help: "Number of active P2P peers",
		}),
		p2pSharedThreats: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "vulcanguard_p2p_shared_threats",
			Help: "Total number of threats shared via P2P",
		}),
	}

	// Register metrics
	prometheus.MustRegister(
		exporter.totalRequests,
		exporter.blockedRequests,
		exporter.allowedRequests,
		exporter.activeConnections,
		exporter.blacklistedIPs,
		exporter.requestsByCountry,
		exporter.behavioralAnomalies,
		exporter.similarityMatches,
		exporter.p2pActivePeers,
		exporter.p2pSharedThreats,
	)

	return exporter
}

func (e *VulcanGuardExporter) updateMetrics() {
	ctx := context.Background()

	// Fetch data from VulcanGuard API
	vulcanguardURL := os.Getenv("VULCANGUARD_API_URL")
	if vulcanguardURL == "" {
		vulcanguardURL = "http://localhost:8888"
	}

	// Get basic metrics
	resp, err := http.Get(vulcanguardURL + "/api/stats")
	if err != nil {
		log.Printf("Error fetching stats: %v", err)
		return
	}
	defer resp.Body.Close()

	var stats map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		log.Printf("Error decoding stats: %v", err)
		return
	}

	// Update Prometheus metrics
	if val, ok := stats["total_requests"].(float64); ok {
		e.totalRequests.Add(val)
	}
	if val, ok := stats["blocked_requests"].(float64); ok {
		e.blockedRequests.Add(val)
	}
	if val, ok := stats["active_connections"].(float64); ok {
		e.activeConnections.Set(val)
	}
	if val, ok := stats["blacklisted_ips"].(float64); ok {
		e.blacklistedIPs.Set(val)
	}

	// Get geolocation data and store in InfluxDB
	geoResp, err := http.Get(vulcanguardURL + "/api/geo-stats")
	if err != nil {
		log.Printf("Error fetching geo stats: %v", err)
		return
	}
	defer geoResp.Body.Close()

	var geoData []GeolocationData
	if err := json.NewDecoder(geoResp.Body).Decode(&geoData); err != nil {
		log.Printf("Error decoding geo stats: %v", err)
		return
	}

	// Store geolocation data in InfluxDB
	for _, geo := range geoData {
		point := influxdb2.NewPointWithMeasurement("geo_requests").
			AddTag("country", geo.Country).
			AddTag("city", geo.City).
			AddField("requests", geo.Requests).
			AddField("lat", geo.Latitude).
			AddField("lon", geo.Longitude).
			SetTime(time.Now())

		e.influxWriteAPI.WritePoint(point)

		// Update Prometheus metrics
		e.requestsByCountry.WithLabelValues(geo.Country).Set(float64(geo.Requests))
	}

	// Store in Redis for real-time access
	geoJSON, _ := json.Marshal(geoData)
	e.redisClient.Set(ctx, "vulcanguard:geo_data", geoJSON, time.Minute*5)
}

func (e *VulcanGuardExporter) metricsHandler(w http.ResponseWriter, r *http.Request) {
	e.updateMetrics()
	promhttp.Handler().ServeHTTP(w, r)
}

func (e *VulcanGuardExporter) geoDataHandler(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	// Get cached geo data from Redis
	geoJSON, err := e.redisClient.Get(ctx, "vulcanguard:geo_data").Result()
	if err != nil {
		http.Error(w, "Failed to get geo data", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Write([]byte(geoJSON))
}

func (e *VulcanGuardExporter) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	response := map[string]string{
		"status": "healthy",
		"time":   time.Now().Format(time.RFC3339),
	}
	json.NewEncoder(w).Encode(response)
}

func main() {
	exporter := NewVulcanGuardExporter()

	r := mux.NewRouter()
	r.HandleFunc("/metrics", exporter.metricsHandler)
	r.HandleFunc("/api/geo-data", exporter.geoDataHandler)
	r.HandleFunc("/health", exporter.healthHandler)

	// Start metrics update goroutine
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			exporter.updateMetrics()
		}
	}()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("VulcanGuard Exporter starting on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}
