package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/dropbox/goebpf"
)

func PkfilterInit(blacklistCh, unblockCh chan string) {
	// Specify Interface Name
	interfaceName := "lo"

	// Load XDP Into App
	bpf := goebpf.NewDefaultEbpfSystem()
	err := bpf.LoadElf("packetFilter/pkfilter.elf")
	if err != nil {
		log.Fatalf("LoadELF() failed: %s", err)
	}
	blacklist := bpf.GetMapByName("blacklist")
	if blacklist == nil {
		log.Fatalf("eBPF map 'blacklist' not found\n")
	}
	xdp := bpf.GetProgramByName("firewall")
	if xdp == nil {
		log.Fatalln("Program 'firewall' not found in Program")
	}
	err = xdp.Load()
	if err != nil {
		fmt.Printf("xdp.Attach(): %v", err)
	}
	err = xdp.Attach(interfaceName)
	if err != nil {
		log.Fatalf("Error attaching to Interface: %s", err)
	}

	// Listen for new blacklisted IPs
	go func() {
		for ip := range blacklistCh {
			err := BlockIPAddress(ip, blacklist)
			if err != nil {
				log.Printf("Failed to block IP %s: %v", ip, err)
			}
		}
	}()

	go func() {
		for ip := range unblockCh {
			err := UnblockIPAddress(ip, blacklist)
			if err != nil {
				log.Printf("Failed to block IP %s: %v", ip, err)
			}
		}
	}()

	defer xdp.Detach()
	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)
	log.Println("XDP Program Loaded successfully into the Kernel.")
	log.Println("Press CTRL+C to stop.")
	<-ctrlC
}

// The Function That adds the IPs to the blacklist map
func BlockIPAddress(ip string, blacklist goebpf.Map) error {
	err := blacklist.Insert(goebpf.CreateLPMtrieKey(ip), 1)
	if err != nil {
		return err
	}
	return nil
}

func UnblockIPAddress(ip string, blacklist goebpf.Map) error {
	err := blacklist.Delete(goebpf.CreateLPMtrieKey(ip))
	if err != nil {
		return err
	}
	return nil
}
