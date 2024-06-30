# Suboptimal-Firewall

## Overview

**Suboptimal-Firewall** is a comprehensive network management tool designed to test network security and performance. It combines a rate limiter, an eBPF-based XDP (Express Data Path) packet filter, and a round-robin based load balancer to provide a barely working suboptimal firewall solution :D.

# ⚠️ Disclaimer ⚠️
WARNING: suboptimal-Firewall is Heavily Underdeveloped

This project is currently a **parody** and is **NOT SUITABLE** for production environments. It is intended purely for learning and educational purposes (for now). The current version lacks extensive testing and development, which could lead to security vulnerabilities, performance issues, and other critical problems on.

Use at Your Own Risk

The creator of this tool will not be held liable for any damages or negative outcomes resulting from its use. By using this tool, you acknowledge the potential risks and agree that the responsibility for any issues lies solely with you.

Future Development Needed

Significant further work is required to make suboptimal-Firewall a stable and reliable tool. Contributions and feedback are welcome to help improve its functionality and security.

Note: This project is currently a parody and may evolve in the future.


## Features

1. **Rate Limiter**:
   - Controls the rate of incoming traffic to prevent overwhelming the network.
   - Protects against DDoS attacks and ensures fair usage of network resources.

2. **eBPF-based XDP Packet Filter**:
   - Utilizes eBPF (Extended Berkeley Packet Filter) for high-performance packet filtering.
   - Operates at the lowest point in the network stack for minimal latency.
   - Customizable filtering rules to suit specific security needs.

3. **Round Robin Based Load Balancer**:
   - Distributes incoming traffic evenly across multiple servers.
   - Ensures optimal resource utilization and enhances the performance and reliability of services.

## Installation

### Prerequisites

- Linux operating system with kernel version 4.14 or higher.
- `libbpf` library installed.
- GCC or Clang compiler.
- Go version 1.22.0 or higher

### Steps

1. Clone the repository:
   ```sh
   git clone https://github.com/yourusername/suboptimal-Firewall.git
   cd suboptimal-Firewall
   ```

2. Build the project:
   ```sh
   go build 
   ```

3. Run the firewall:
   ```sh
   sudo ./Firewall
   ```

## Configuration

Add a list of backend servers or URLs for Loadbalancing in 
[https://github.com/Aditya1404Sal/Suboptimal-firewall/blob/6336a34363dd23fe10c6f9a3aa0cedbd51a6c73a/main.go#L88]

```conf
[LoadBalancer]
server_list = server1, server2, server3
```

### eBPF-based XDP Packet Filter

Modify the eBPF filtering rules in the `packetFilter/pkfilter.c` file:
```c
SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    // Custom filtering logic
    return XDP_PASS;
}
```


## Usage

### Starting the Firewall

To start the firewall with default settings:
```sh
sudo ./Firewall
```

### Logs and Monitoring

Logs are stored in the root `/` directory. Monitor the firewall status and performance:
```sh
tail -f suboptimal-Firewall.log
```

## Contributing

I welcome contributions to improve suboptimal-Firewall. Please follow these steps to contribute:

1. Fork the repository.
2. Create a new branch: `git checkout -b feature-branch`.
3. Make your changes and commit them: `git commit -m 'Add new feature'`.
4. Push to the branch: `git push origin feature-branch`.
5. Open a pull request.

---