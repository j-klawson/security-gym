# BUILD.md: Isildur Setup Documentation

This document records the exact configuration and provisioning steps for **isildur**, the primary vulnerable research node for `security-gym`. This node is designed to be a static, reproducible "time capsule" for Reinforcement Learning experiments under the Alberta Plan.

## 1. Environment Overview
- **Hostname:** isildur
- **Role:** Vulnerable Target / Log Producer
- **OS:** Debian 11.11 (Bullseye)
- **Architecture:** x86_64 (KVM Guest on Frodo)
- **IP Address:** 192.168.2.201 (Static)

## 2. Hypervisor Configuration (Frodo)
The VM was provisioned on the host **Frodo** (Intel Xeon E5-1620) using `virt-install`.

### Network Bridge
A bridge `br0` was created on the host to allow Isildur to reside directly on the `192.168.2.0/24` subnet.
```text
auto br0
iface br0 inet static
    address 192.168.2.200
    bridge_ports enp1s0

## Virtual Server Provisioning

virt-install \
  --name isildur \
  --ram 4096 \
  --vcpus 2 \
  --os-variant debian11 \
  --network bridge=br0,model=virtio \
  --graphics none \
  --console pty,target_type=serial \
  --location '[http://deb.debian.org/debian/dists/bullseye/main/installer-amd64/](http://deb.debian.org/debian/dists/bullseye/main/installer-amd64/)' \
  --disk size=40,bus=virtio,cache=none \
  --extra-args 'console=ttyS0,115200n8 serial \
    netcfg/get_hostname=isildur \
    netcfg/disable_autoconfig=true \
    netcfg/get_ipaddress=192.168.2.201 \
    netcfg/get_netmask=255.255.255.0 \
    netcfg/get_gateway=192.168.2.1 \
    netcfg/get_nameservers=8.8.8.8 \
    netcfg/confirm_static=true \
    pkgsel/update-policy=none'

## Anti-update Policies

1. APT Timers: Masked apt-daily and apt-daily-upgrade.
2. Periodic Actions: Created /etc/apt/apt.conf.d/999-research-freeze with all intervals set to 0.
3. Repository Lock: Commented out bullseye-security and bullseye-updates in /etc/apt/sources.list.

`apt-mark hold docker.io docker-compose auditd python3-pip python3-pkg-resources linux-image-amd64`

## Software Stack

The following tools were installed to facilitate log collection and vulnerability hosting:

- Docker: Container runtime for isolated vulnerable applications.
- Auditd: Process-level monitoring for ground truth labeling.
- Python 3.11+: For running the security-gym collection daemon.

### Auditd Configuration

Rules added to `/etc/audit/rules.d/security_gym.rules` to track process execution:

`-w /usr/bin/wget -p x -k research_exploit`
`-w /usr/bin/curl -p x -k research_exploit`
`-w /bin/sh -p x -k research_exploit`
`-w /bin/bash -p x -k research_exploit`

## 5. eBPF Kernel Event Collection (V2)

BCC-based eBPF collector attaches to kernel tracepoints (execve, connect, accept, openat, unlinkat) to capture process, network, and file events.

### Installation

```bash
ssh keith@192.168.2.201
sudo apt install bpfcc-tools python3-bpfcc linux-headers-$(uname -r)
sudo apt-mark hold bpfcc-tools python3-bpfcc
```

### Sudoers Rules

Add to `/etc/sudoers.d/researcher_ebpf`:

```
researcher ALL=(root) NOPASSWD: /usr/bin/python3 /tmp/security_gym_ebpf_collector.py *
researcher ALL=(root) NOPASSWD: /usr/bin/pkill -f security_gym_ebpf_collector*
```

### Manual Test

```bash
ssh researcher@192.168.2.201
sudo python3 /tmp/security_gym_ebpf_collector.py --output /tmp/test_ebpf.log &
sleep 10
sudo pkill -f security_gym_ebpf_collector
cat /tmp/test_ebpf.log | head -20
```

### V2 Snapshot

After verifying eBPF collection works, create a new golden state on Frodo:

```
virsh snapshot-create-as isildur --name "ISILDUR_READY_V2" --description "BCC/eBPF kernel event collection"
```

## 6. Active Vulnerabilities

**Log4Shell (CVE-2021-44228)**
Hosted via Docker Compose in `~/research/log4j/`.

- Target Port: 8080
- Log Source: JSON-file driver via Docker logs.

## 7. Snapshot Management

The "Golden State" snapshot was created on Frodo immediately after provisioning:

`virsh snapshot-create-as isildur --name "ISILDUR_READY_V1" --description "Base research state"`

