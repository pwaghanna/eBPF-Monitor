#!/usr/bin/python
from bcc import BPF

# Define BPF program
program=r"""
int hello_world(void *ctx) {
    bpf_trace_printk("Hello World, testing BPF!\\n");
    return 0;
}
"""
# Load BPF program
b=BPF(text=program)

# Get the syscall name for execve
syscall=b.get_syscall_fnname("execve")

# Attach the BPF function to the syscall
b.attach_kprobe(event=syscall, fn_name="hello_world")

# Print the trace output
b.trace_print()

# To run this script, use: sudo python helloworld.py

