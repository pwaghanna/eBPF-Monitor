#!/bin/bash

echo "==================================="
echo "Generating eBPF Monitor Test Event"
echo "==================================="
echo "This will generate various syscalls to test the monitor"
echo
echo "Before running this script, please ensure 'sudo ./ebpf_monitor.py -v' is running in another terminal."
echo

read -p "Press Enter to start generating events..."
echo

echo "[1/5] Testing process execution (execve)"
sleep 1
ls /tmp > /dev/null
echo "hello world"
whoami > /dev/null

echo

echo "[2/5] Testing file operations (open/write)"
sleep 1
echo "pushing test data to /tmp/ebpf_test_file.txt" > /tmp/ebpf_test_file.txt
cat /tmp/ebpf_test_file.txt > /dev/null
echo "pushing more data" >> /tmp/ebpf_test_file.txt

echo

echo "[3/5] Testing file deletion (unlink)"
sleep 1
touch /tmp/ebpf_test_delete.txt
rm /tmp/ebpf_test_delete.txt
rm /tmp/ebpf_test_file.txt 2>/dev/null

echo

echo "[4/5] Testing network connections (connect)"
echo "Testing connection google dns"
sleep 1
timeout 2 nc -zv 8.8.8.8 53 2>/dev/null || true
timeout 2 curl -s https://example.com > /dev/null || true

echo

echo "[5/5] Testing suspicious activity that should be flagged"
sleep 1
echo "Followoing events will trigger suspicious alerts"
echo
sleep 2

cat /etc/shadow 2>/dev/null || echo "permission denied but its ok"

touch /tmp/.hidden_file.txt
rm /tmp/.hidden_file.txt

timeout 1 nc -zv localhost 4444 2>/dev/null || echo "port not open but its ok"


echo
echo "==================================="
echo "Test Complete"
echo "==================================="
echo
echo "Monitor should show - "
echo "  - Green EXEC event"
echo "  - Blue OPEN events"
echo "  - Cyan WRITE events"
echo "  - Magenta DELETE events"
echo "  - Yellow CONNECT events"
echo "  - Red [!] SUSPICIOUS markers"
echo