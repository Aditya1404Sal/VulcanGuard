package main

import (
	loadb "Suboptimal/Firewall/LoadB"
	"fmt"
	"net/http"
)

func main() {
	Pkfilter_init()
	servers := []loadb.Server{
		loadb.NewServer("server url"),
	}
	lb := loadb.NewLoadbalancer("8080", servers)
	handleRedirect := func(w http.ResponseWriter, r *http.Request) {
		lb.ServeProxy(w, r)
	}
	http.HandleFunc("/", handleRedirect)
	fmt.Printf("serving requests at localhost:%s \n", lb.Port)
	http.ListenAndServe(":"+lb.Port, nil)
	// TODO : add listener to packet filter and integrate a redirect handler for it
	// TODO : Start a goroutine and listener for cache logs and sticky connection
}
