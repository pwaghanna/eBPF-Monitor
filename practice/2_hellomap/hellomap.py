#!/usr/bin/python3  
from bcc import BPF
from time import sleep

# This program counts the number of execve syscalls per user ID (UID)

program=r"""
// Define a BPF hash map to count syscalls per UID
BPF_HASH(counter_table);

// BPF program to be attached to syscall that increments counter per UID
int hello(void *ctx)
{
    u64 uid;
    u64 counter=0;
    u64 *p;

    // Get current UID. We do and mask to get only the lower 32 bits
    uid=bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // Lookup UID in the hash map
    p=counter_table.lookup(&uid);

    //if UID found, get current count
    if(p!=0)
    {
        counter=*p;
    }

    // Increment counter to reflect this syscall
    counter++;

    // Update the hash map with new counter value
    counter_table.update(&uid, &counter);

    return 0;
}
"""

# Load BPF program
b=BPF(text=program)

# Get the syscall name for execve
syscall=b.get_syscall_fnname("execve")

# Attach the BPF function to the syscall
b.attach_kprobe(event=syscall, fn_name="hello")

# Alternatively, we can attach to raw tracepoint for sys_enter
# b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

# here we print the UID counters every 2 seconds
while True:
    sleep(2)
    s=""
    for k,v in b["counter_table"].items():
        s+=f"ID {k.value}: {v.value} \t"

    print(s)

