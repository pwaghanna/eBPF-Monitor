#!/bin/bash

set -e

echo "==================================="
echo "Setting up test environment for eBPF Monitor"
echo "==================================="

echo "Detecting OS..."
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo "Cannot detect OS."
    exit 1
fi

echo "Detected OS: $OS"
echo

echo "Checking if running as root..."
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo ./test.sh)"
    exit 1
fi

echo "Root confirmed"
echo

echo "Inspecting installed dependencies..."
case $OS in
    ubuntu|debian)
        echo "Checking dependencies for Ubuntu/Debian..."
        dpkg -l | grep -q python3-bpfcc && echo "✓ python3-bpfcc is installed" || echo "✗ python3-bpfcc is missing"
        dpkg -l | grep -q bpfcc-tools && echo "✓ bpfcc-tools is installed" || echo "✗ bpfcc-tools is missing"
        ;;
    fedora|rhel|centos)
        echo "Checking dependencies for RHEL/Fedora/CentOS..."
        rpm -q bcc-tools && echo "✓ bcc-tools is installed" || echo "✗ bcc-tools is missing"
        ;;
    *)
        echo "Unsupported OS: $OS"
        exit 1
        ;;
esac


echo
echo "Verifying installation..."

if python3 -c "from bcc import BPF" 2>/dev/null; then
    echo "✓ BCC Python bindings are available"
else
    echo "✗ BCC Python bindings are not available"
    exit 1
fi

echo 
echo "making ebpf.py executable..."
chmod +x ebpf.py

echo 
echo "==================================="
echo "Setup Completed!"
echo "==================================="

echo
echo "You can now run the monitor with:"
echo "  sudo ./ebpf.py"
echo
echo "And run tests with:"
echo "  ./test_monitor.sh"
echo
echo "Before running tests, ensure the monitor is active in another terminal."
