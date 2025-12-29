# eBPF System Call And File Access Monitor

A powerful kernel level security monitoring tool built with eBPF that provides real time visibility into system calls, file operations and network activity

## Features

- Tracks all execve() calls
- Monitors all open() and openat() operations along with their flags
- Logs all write() calls
- Logs all connect() calls with the destination IP and port number
- Flags suspicious activity of potential malicious activity that may affect sensitive files or directories
- Flags suspicious processes that may run malicious programs such as nmap
- eBPF runs in kernel space and has minimal overhead
- Event are displayed in real time

## Prerequisite
- Restricted to linux based systems
- Ensure your system is updated
- Python3, Python bindings for BCC, eBPF command line tools, header files for your linux system. You can use the following command
```
sudo apt-get install -y python3-bpfcc bpfcc-tools linux-headers-$(uname -r)
```

## Usage
Once this repository is cloned, add permission for execution for ebpf.py file
```bash
chmod +x ebpf.py
```

REMEMBER: eBPF should always run in privileged mode i.e. using 'sudo'

You can access the help menu through(sudo not required)
```bash
./ebpf -h
```

### Basic Usage
This mode logs suspicious activities only.
```bash
sudo ./ebpf.py
```

### Verbose Mode
This flag displays all events i.e. displays all syscalls
```bash
sudo ./ebpf.py -v
``` 
OR
```bash
sudo ./ebpf --verbose
```

### Monitor Specific Process
This will filter all events and monitor display the given PID only
```bash
sudo ./ebpf_monitor.py -p 1234
```

### Disable Suspicious Activity
Show all events but do not flag suspicious activities
```bash
sudo ./ebpf_monitor.py -v --no-detect
```


## Suspicious Activities Criteria

### File Operations
- Writes to `/etc/`, `/root/`, `/boot/`, `/sys/`
- Access to SSH keys in `/.ssh/`
- Modifications to `/var/log/`
- Hidden files with `/.` or `/..` patterns

### Processes
- Network tools: `nc`, `ncat`, `telnet`
- Download tools: `wget`, `curl` (when combined with suspicious paths)
- Cybersecurity tools : 'nmap', 'masscan', 'hydra', 'john', 'sqlmap', 'metasploit', 'msfconsole'

### Network
- Connections to ports - 4444, 5555, 6666, 7777, 31337, 12345, 1337


## 📝 Common Issues

### "Permission denied"
Run with `sudo` - eBPF requires root privileges.

### "Failed to compile BPF program"
Install kernel headers: `sudo apt install linux-headers-$(uname -r)`

### "No module named 'bcc'"
Install BCC: `sudo apt install python3-bpfcc`

### Events not appearing
Some syscalls may use different entry points. Check kernel version compatibility.
