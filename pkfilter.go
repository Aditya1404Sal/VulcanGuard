package main

import (
	"context"
	"fmt"
	"log"

	"github.com/dropbox/goebpf"
)

func PkfilterInit(ctx context.Context, blacklistCh, unblockCh chan string) {
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

	//Ensure xdp.Detach() is called when the function exits
	defer func() {
		log.Println("\nDetaching XDP program...")
		err := xdp.Detach()
		if err != nil {
			log.Printf("\nError detaching XDP program: %v 😨", err)
			fmt.Printf("\nError detaching XDP program: %v 😨", err)
		} else {
			log.Println("\nXDP program successfully detached 😌")
			fmt.Println("\nXDP program successfully detached 😌")
		}
	}()

	// Listen for new blacklisted IPs
	go func() {
		for {
			select {
			case ip := <-blacklistCh:
				err := BlockIPAddress(ip, blacklist)
				if err != nil {
					log.Printf("Failed to block IP %s: %v 💀", ip, err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		for {
			select {
			case ip := <-unblockCh:
				err := UnblockIPAddress(ip, blacklist)
				if err != nil {
					log.Printf("Failed to unblock IP %s: %v 💀", ip, err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	log.Println("XDP Program Loaded successfully into the Kernel.")
	log.Println("Press CTRL+C to stop.")

	// Wait for context cancellation
	<-ctx.Done()
	log.Println("Received signal to stop. Preparing to detach XDP program...")
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
