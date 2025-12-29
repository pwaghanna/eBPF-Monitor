#!/usr/bin/python3
from bcc import BPF

program=r"""
BPF_PERF_OUTPUT(output);

struct data_t{
    int pid;
    int uid;
    char command[16];
    char message[12];
};

int hello(void *ctx)
{
    struct data_t data={};
    char message[12]="Hello World";

    data.pid=bpf_get_current_pid_tgid()>>32;
    data.uid=bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // Get the current command name
    bpf_get_current_comm(&data.command, sizeof(data.command));

    // Read the message into the data structure
    bpf_probe_read_kernel(&data.message, sizeof(data.message), message);

    // Submit the data to user space
    output.perf_submit(ctx, &data, sizeof(data));

    return 0;

}
"""

b=BPF(text=program)

syscall=b.get_syscall_fnname("execve")

b.attach_kprobe(event=syscall, fn_name="hello")

# Define the callback function to process events
def print_event(cpu, data, size):

    # Parse the event data
    data=b["output"].event(data)


    print(f"PID: {data.pid}")
    print(f"UID: {data.uid}")
    print(f"Command: {data.command.decode()}")
    print(f"Message: {data.message.decode()}")

# Open the perf buffer to receive events
b["output"].open_perf_buffer(print_event)

# Poll the perf buffer in a loop
while True:
    b.perf_buffer_poll()