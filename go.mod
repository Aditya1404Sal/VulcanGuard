module Suboptimal/Firewall

go 1.22.0

require github.com/dropbox/goebpf v0.0.0-20240319152541-e5e17f597ca3

require (
	github.com/vishvananda/netlink v1.1.1-0.20200218174631-5f2fc868c2d0 // indirect
	github.com/vishvananda/netns v0.0.0-20200520041808-52d707b772fe // indirect
	golang.org/x/sys v0.0.0-20200722175500-76b94024e4b6 // indirect
)

// New internal modules
require (
	Suboptimal/Firewall/BehavioralProfiler v0.0.0
	Suboptimal/Firewall/IdentityAnalyzer v0.0.0
	Suboptimal/Firewall/P2P v0.0.0
	Suboptimal/Firewall/TrafficAnalyser v0.0.0
)

// Replace with local paths
replace Suboptimal/Firewall/BehavioralProfiler => ./BehavioralProfiler

replace Suboptimal/Firewall/TrafficAnalyser => ./TrafficAnalyser

replace Suboptimal/Firewall/P2P => ./P2P

replace Suboptimal/Firewall/IdentityAnalyzer => ./IdentityAnalyzer
