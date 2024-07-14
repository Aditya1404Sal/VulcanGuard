package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/dropbox/goebpf"
)

func Pkfilter_init(mapped_ip_list map[string]struct{}) {

	ip_list := make([]string, 0, len(mapped_ip_list)) // Preallocate the slice with capacity

	for key := range mapped_ip_list {
		ip_list = append(ip_list, key)
	}

	// Specify Interface Name
	interfaceName := "lo"
	// IP BlockList

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

	BlockIPAddress(ip_list, blacklist)

	defer xdp.Detach()
	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)
	log.Println("XDP Program Loaded successfuly into the Kernel.")
	log.Println("Press CTRL+C to stop.")
	<-ctrlC

}

// The Function That adds the IPs to the blacklist map
func BlockIPAddress(ipAddreses []string, blacklist goebpf.Map) error {
	for index, ip := range ipAddreses {
		err := blacklist.Insert(goebpf.CreateLPMtrieKey(ip), index)
		if err != nil {
			return err
		}
	}
	return nil
}
