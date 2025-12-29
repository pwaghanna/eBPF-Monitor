#!/usr/bin/env python3

# from fileinput import filename
from bcc import BPF
import argparse
# import signal
import sys
from datetime import datetime
import socket
import struct
import os
import time

program="""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/socket.h>
#include <linux/in.h>

// Event types that we are monitoring
#define EVENT_EXEC 1
#define EVENT_OPEN 2
#define EVENT_WRITE 3
#define EVENT_DELETE 4
#define EVENT_CONNECT 5

struct event_t {
    u32 pid;
    u32 uid;
    u32 event_type;
    char comm[TASK_COMM_LEN];
    char filename[256];
    u32 flags;
    u32 port_number;
    u32 ip_address;
};

BPF_PERF_OUTPUT(events);

/*
 * Function Name : syscall__execve
 * Description   : Trace execve syscall to monitor process execution events
 * Parameters    : struct pt_regs *ctx - pointer to the pt_regs structure
 *                 const char __user *filename - pointer to the filename being executed
 * Return Value  : int - return status
 */
int syscall__execve(struct pt_regs *ctx, const char __user *filename)
{
    struct event_t event={};

    //Get current pid and tid
    u64 pid_tgid=bpf_get_current_pid_tgid();
    
    //Right shift by 32 to get the pid
    u32 pid=pid_tgid >> 32;
    
    //Get tid by masking lower 32 bits
    u32 tid=(u32)pid_tgid;

    //Assign values to event structure
    event.pid=pid;
    event.uid=bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    event.event_type=EVENT_EXEC;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    bpf_probe_read_user(&event.filename, sizeof(event.filename), (void *)filename);
    
    //Submit event to user space
    events.perf_submit(ctx, &event, sizeof(event));
    
    return 0;
}

/*
 * Function Name : syscall__openat
 * Description   : Trace openat syscall to monitor file open events
 * Parameters    : struct pt_regs *ctx - pointer to the pt_regs structure
 *                 int dfd - directory file descriptor
 *                 const char __user *filename - pointer to the filename being opened
 *                 int flags - flags used in openat syscall
 * Return Value  : int - return status
 */
int syscall__openat(struct pt_regs *ctx, int dfd, const char __user *filename, int flags)
{
     struct event_t event={};

    //Get current pid and tid
    u64 pid_tgid=bpf_get_current_pid_tgid();
    
    //Right shift by 32 to get the pid
    u32 pid=pid_tgid >> 32;
    
    //Get tid by masking lower 32 bits
    u32 tid=(u32)pid_tgid;

    //Assign values to event structure
    event.pid=pid;
    event.uid=bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    event.event_type=EVENT_OPEN;
    event.flags=flags;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user(&event.filename, sizeof(event.filename), (void *)filename);

    //Submit event to user space
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

/*
 * Function Name : syscall__write
 * Description   : Trace write syscall to monitor file write events
 * Parameters    : struct pt_regs *ctx - pointer to the pt_regs structure
 *                 unsigned int fd - file descriptor
 *                 const char __user *buf - pointer to the buffer being written
 *                 size_t count - number of bytes to write
 * Return Value  : int - return status
 */
int syscall__write(struct pt_regs *ctx, unsigned int fd, const char __user *buf, size_t count)
{
    struct event_t event={};

    //Get current pid and tid
    u64 pid_tgid=bpf_get_current_pid_tgid();

    //Right shift by 32 to get the pid
    u32 pid=pid_tgid >> 32;

    //Get tid by masking lower 32 bits
    u32 tid=(u32)pid_tgid;

    //Assign values to event structure
    event.pid=pid;
    event.uid=bpf_get_current_uid_gid() & 0xFFFFFFFF;

    event.event_type=EVENT_WRITE;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user(&event.filename, sizeof(event.filename), (void *)buf);

    //Submit event to user space
    events.perf_submit(ctx, &event, sizeof(event));

    return 0;
}

/*
 * Function Name : syscall__unlinkat
 * Description   : Trace unlinkat syscall to monitor file deletion events
 * Parameters    : struct pt_regs *ctx - pointer to the pt_regs structure
 *                 int dfd - directory file descriptor
 *                 const char __user *pathname - pointer to the filename being deleted
 * Return Value  : int - return status
 */
int syscall__unlinkat(struct pt_regs *ctx, int dfd, const char __user *pathname)
{   
    struct event_t event={};

    //Get current pid and tid
    u64 pid_tgid=bpf_get_current_pid_tgid();

    //Right shift by 32 to get the pid
    u32 pid=pid_tgid >> 32;

    //Get tid by masking lower 32 bits
    u32 tid=(u32)pid_tgid;

    //Assign values to event structure
    event.pid=pid;
    event.uid=bpf_get_current_uid_gid() & 0xFFFFFFFF;

    event.event_type=EVENT_DELETE;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user(&event.filename, sizeof(event.filename), pathname);

    //Submit event to user space
    events.perf_submit(ctx, &event, sizeof(event));

    return 0;


}


/* * Function Name : syscall__connect
 * Description   : Trace connect syscall to monitor network connection events
 * Parameters    : struct pt_regs *ctx - pointer to the pt_regs structure
 *                 int sockfd - socket file descriptor
 *                 struct sockaddr __user *addr - pointer to the socket address
 *                 int addrlen - length of the socket address
 * Return Value  : int - return status
 */

int syscall__connect(struct pt_regs *ctx, int sockfd, struct sockaddr __user *addr, int addrlen)
{
    struct event_t event={};

    //Get current pid and tid
    u64 pid_tgid=bpf_get_current_pid_tgid();

    //Right shift by 32 to get the pid
    u32 pid=pid_tgid >> 32;

    //Get tid by masking lower 32 bits
    u32 tid=(u32)pid_tgid;

    //Assign values to event structure
    event.pid=pid;
    event.uid=bpf_get_current_uid_gid() & 0xFFFFFFFF;

    event.event_type=EVENT_CONNECT;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));  

    //Read sockaddr_in structure from user space for IPv4 addresses
    struct sockaddr_in sa={};
    bpf_probe_read_user(&sa, sizeof(sa), (void *)addr);

    if(sa.sin_family==AF_INET)
    {
        event.ip_address=sa.sin_addr.s_addr;
        event.port_number=ntohs(sa.sin_port);
    }

    //Submit event to user space
    events.perf_submit(ctx, &event, sizeof(event));

    return 0;

}

"""

class Colours:
    RED='\033[91m'
    GREEN='\033[92m'
    YELLOW='\033[93m'
    BLUE='\033[94m'
    MAGENTA='\033[95m'
    CYAN='\033[96m'
    RESET='\033[0m'
    BOLD='\033[1m'

SUSPICIOUS_PATHS=['/etc/', '/root/', '/boot/', '/sys/', '/.ssh/', '/var/log/']
SUSPICIOUS_PROCESSES=['nc', 'netcat', 'wget', 'curl', 'telnet', 'nmap', 'masscan', 'hydra', 'john', 'sqlmap', 'metasploit', 'msfconsole']
SENSITIVE_PORTS=[4444, 5555, 6666, 7777, 31337, 12345, 1337]

class SystemMonitor:

    
    def __init__(self, detect_suspicious=True, filter_pid=None, verbose=False):
        """
        Initialize the SystemMonitor with configuration options.
        
        Parameters:
            detect_suspicious (bool): Enable or disable suspicious activity detection.
            filter_pid (int or None): PID to filter events for, or None for all PIDs.
            verbose (bool): Enable verbose output.
        """
        self.detect_suspicious=detect_suspicious
        self.filter_pid=filter_pid
        self.verbose=verbose
        self.stats={
            'exec':0,
            'open':0,
            'write':0,
            'delete':0,
            'connect':0,
            'suspicious':0
        }
        self.start_time=time.time()
        self.total_events=0

        self.rule_hit={
            'suspicious_paths':0,
            'suspicious_processes':0,
            'sensitive_ports':0,
            'directory_traversal':0
        }

        self.lost_events=0

    def handle_lost_events(self, count):
        """
        Callback function to handle lost events.
        
        Parameters:
            count (int): Number of lost events.
        """
        self.lost_events+=count
    
    def is_suspicious(self, event_type, comm, filename, port):
        """
        Check if an event is suspicious based on predefined criteria.
        
        Parameters:
            event_type (int): Type of the event.
            comm (str): Command name of the process.
            filename (str): Filename involved in the event.
            port (int): Port number involved in the event.
        """

        # If suspicious detection is disabled, return False
        if not self.detect_suspicious:
            return False
    
        # Check for suspicious processes
        if filename:
            filename_str=filename.decode('utf-8', 'replace')

            # Check for suspicious paths
            if event_type in [2, 3, 4]:
                for path in SUSPICIOUS_PATHS:
                    if filename_str.startswith(path):
                        self.rule_hit['suspicious_paths']+=1
                        return True

            # Check for directory traversal patterns
            if '/..' in filename_str or filename_str.startswith('/.'):
                self.rule_hit['directory_traversal']+=1
                return True

        # Check for suspicious processes
        comm_str=comm.decode('utf-8', 'replace')

        if comm_str in SUSPICIOUS_PROCESSES:
            self.rule_hit['suspicious_processes']+=1
            return True

        # Check for sensitive ports

        if event_type==5 and port in SENSITIVE_PORTS:
            self.rule_hit['sensitive_ports']+=1
            return True
        
        return False
    
    def format_event(self, event):
        """
        Format the event data for display.
        
        Parameters:
            event (event_t): The event data structure.
        """

        timestamp=datetime.now().strftime('%H:%M:%S.%f')[:-3]
        comm=event.comm.decode('utf-8', 'replace')
        filename=event.filename.decode('utf-8', 'replace') if event.filename else ''

        event_types={
            1:('EXEC', Colours.GREEN),
            2:('OPEN', Colours.BLUE),
            3:('WRITE', Colours.CYAN),
            4:('DELETE', Colours.MAGENTA),
            5:('CONNECT', Colours.YELLOW),
        }

        event_name, colour=event_types.get(event.event_type, ('UNKNOWN', Colours.RED))

        suspicious=self.is_suspicious(event.event_type, event.comm, event.filename, event.port_number)

        sus_marker=f"{Colours.RED}{Colours.BOLD}[!]SUSPICIOUS{Colours.RESET} " if suspicious else ""

        output=f"{sus_marker}{Colours.BOLD}{timestamp}{Colours.RESET} "
        output+=f"{colour}{event_name:8}{Colours.RESET} "
        output+=f"PID={Colours.BOLD}{event.pid:6}{Colours.RESET} "
        output+=f"UID={event.uid:5} "
        output+=f"COMM={Colours.BOLD}{comm:16}{Colours.RESET} "

        # If event is exec then show command
        if event.event_type==1:
            output+=f"CMD={filename}"

        # If event is open then show file and flags
        elif event.event_type==2:
            flags_str=self.decode_open_flags(event.flags)
            output+=f"FILE={filename} FLAGS={flags_str}"
        
        # If event is write then show fd and bytes written
        elif event.event_type==3:
            output+=f"FD=? BYTES={event.flags}"
        
        # if event is delete then show file
        elif event.event_type==4:
            output+=f"FILE={filename}"
        
        # if event is connect then show address and port
        elif event.event_type==5:
            ip_addr=socket.inet_ntoa(struct.pack('I', event.ip_address))
            output+=f"ADDR={ip_addr}:{event.port_number}"
        

        return output, suspicious


    def decode_open_flags(self, flags):
        """
        Decode open flags into a human-readable string.
        
        Parameters:
            flags (int): The flags used in the open syscall.
        """

        flag_names=[]

        if flags & 0o1:
            flag_names.append('O_WRONLY')
        if flags & 0o2:
            flag_names.append('O_RDWR')
        if flags & 0o100:
            flag_names.append('O_CREAT')
        if flags & 0o200:
            flag_names.append('O_EXCL')
        if flags & 0o400:
            flag_names.append('O_NOCTTY')
        if flags & 0o1000:
            flag_names.append('O_TRUNC')
        if flags & 0o2000:
            flag_names.append('O_APPEND')
        if flags & 0o4000:
            flag_names.append('O_NONBLOCK')
        
        return '|'.join(flag_names) if flag_names else 'O_RDONLY'
    
    def print_event(self, cpu, data, size):
        """
        Callback function to print event data.
        
        Parameters:
            cpu (int): CPU number.
            data (bytes): Raw event data.
            size (int): Size of the event data.
        """

        event=self.bpf["events"].event(data)

        if self.filter_pid and event.pid != self.filter_pid:
            return

        event_type_stats={
            1:'exec',
            2:'open',
            3:'write',
            4:'delete',
            5:'connect'
        }

        self.stats[event_type_stats.get(event.event_type, 'unknown')]+=1
        self.total_events+=1

        output, suspicious=self.format_event(event)

        if suspicious:
            self.stats['suspicious']+=1
        
        if self.verbose or suspicious:
            print(output)

    
    def print_stats(self):
        """
        Print the collected statistics.
        """
        duration=time.time()-self.start_time
        eps=self.total_events/duration if duration>0 else 0

        sus_ratio=(self.stats['suspicious']/self.total_events*100) if self.total_events>0 else 0

        print(f"\n{Colours.BOLD}=== Monitoring Statistics ==={Colours.RESET}")
        print(f"Total EXEC events   : {self.stats['exec']}")
        print(f"Total OPEN events   : {self.stats['open']}")
        print(f"Total WRITE events  : {self.stats['write']}")
        print(f"Total DELETE events : {self.stats['delete']}")
        print(f"Total CONNECT events: {self.stats['connect']}")
        print(f"Suspicious events   : {self.stats['suspicious']}")
        print(f"Suspicious ratio    : {sus_ratio:.2f}% \n")

        print(f"Total events        : {self.total_events}")
        print(f"Duration            : {duration:.2f} seconds")
        print(f"Events per second   : {eps:.2f} eps \n")

        print(f"Lost events         : {self.lost_events}\n")

        print(f"\n{Colours.BOLD}=== Suspicious Activity Details ==={Colours.RESET}")
        print(f"Suspicious paths detected       : {self.rule_hit['suspicious_paths']}")
        print(f"Suspicious processes detected    : {self.rule_hit['suspicious_processes']}")
        print(f"Sensitive ports accessed        : {self.rule_hit['sensitive_ports']}")
        print(f"Directory traversal attempts    : {self.rule_hit['directory_traversal']}")

        print(f"{Colours.BOLD}============================={Colours.RESET}\n")

    
    def run(self):
        """
        Run the system monitor.
        """

        print(f"{Colours.BOLD}{Colours.GREEN}Starting System Monitor... Press Ctrl+C to stop.{Colours.RESET}")
        print(f"Monitoring: exec, open, write, delete, connect syscalls.\n")
        print(f"Suspicious activity detection is {'enabled' if self.detect_suspicious else 'disabled'}\n")
        print(f"Verbose mode is {'enabled' if self.verbose else 'disabled'}\n")

        if self.filter_pid:
            print(f"Filtering events for PID: {self.filter_pid}\n")
        
        self.bpf=BPF(text=program)

        self.bpf.attach_kprobe(event=self.bpf.get_syscall_fnname("execve"), fn_name="syscall__execve")
        self.bpf.attach_kprobe(event=self.bpf.get_syscall_fnname("openat"), fn_name="syscall__openat")
        self.bpf.attach_kprobe(event=self.bpf.get_syscall_fnname("write"), fn_name="syscall__write")
        self.bpf.attach_kprobe(event=self.bpf.get_syscall_fnname("unlinkat"), fn_name="syscall__unlinkat")
        self.bpf.attach_kprobe(event=self.bpf.get_syscall_fnname("connect"), fn_name="syscall__connect")

        # self.bpf["events"].open_perf_buffer(self.print_event)
        self.bpf["events"].open_perf_buffer(self.print_event, lost_cb=self.handle_lost_events)

        try:
            while True:
                self.bpf.perf_buffer_poll(timeout=500)
        except KeyboardInterrupt:
            print(f"\n{Colours.BOLD}{Colours.RED}Stopping System Monitor...{Colours.RESET}")
            self.print_stats()
            sys.exit(0)
    

def main():

    parser=argparse.ArgumentParser(
            description='eBPF System Call and file access monitor',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  sudo ./ebpf_monitor.py                    # Basic monitoring (suspicious only)
  sudo ./ebpf_monitor.py -v                 # Verbose mode (all events)
  sudo ./ebpf_monitor.py -p 1234            # Monitor specific PID
  sudo ./ebpf_monitor.py --no-detect        # Disable suspicious detection
"""
        )

    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output (all events) (default: suspicious only)')
    parser.add_argument('-p', '--pid', type=int, help='Filter events for specific PID')
    parser.add_argument('--no-detect', action='store_true', help='Disable suspicious activity detection')

    args=parser.parse_args()

    if os.geteuid()!=0:
        print(f"{Colours.RED}Error: This script requires root privileges. Please run as root.{Colours.RESET}")
        print(f"Run with sudo")
        sys.exit(1)
        
    monitor=SystemMonitor(
            detect_suspicious=not args.no_detect,
            filter_pid=args.pid,
            verbose=args.verbose
        )

    monitor.run()

if __name__=="__main__":
    main()