from bcc import BPF
import ctypes as ct

program=r"""
BPF_PROG_ARRAY(syscall, 500);

// This program demonstrates the use of BPF_PROG_ARRAY to
// dynamically dispatch to different eBPF programs based on
// the syscall number. It attaches to the sys_enter tracepoint
// and calls different programs for execve and timer-related syscalls.



// The hello function is the main entry point that gets called
// on sys_enter. It retrieves the syscall number and uses the
// BPF_PROG_ARRAY to call the appropriate eBPF program.
int hello(struct bpf_raw_tracepoint_args *ctx) {

    // Get the syscall number from the context
    int opcode=ctx->args[1];

    // Call the appropriate eBPF program based on the syscall number
    syscall.call(ctx, opcode);

    // Log the syscall number
    bpf_trace_printk("Another syscall: %d", opcode);
    return 0;
}

// eBPF program to handle execve syscall
int hello_exec(void *ctx) 
{
    bpf_trace_printk("Executing a program");
    return 0;
}

// eBPF program to handle timer-related syscalls
int hello_timer(struct bpf_raw_tracepoint_args *ctx)
{
    int opcode=ctx->args[1];

    switch(opcode)
    {
        case 222:
            bpf_trace_printk("Creating a timer");
            break;
        case 226:
            bpf_trace_printk("Deleting a timer");
            break;
        default:
            bpf_trace_printk("Some other timer operation");
            break;
    }

    return 0;
}

// eBPF program to ignore other syscalls
int ignore_opcode(void *ctx)
{
    return 0;
}
"""


b=BPF(text=program)
b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

# Load the eBPF programs
ignore_fn=b.load_func("ignore_opcode", BPF.RAW_TRACEPOINT)
exec_fn=b.load_func("hello_exec", BPF.RAW_TRACEPOINT)
timer_fn=b.load_func("hello_timer", BPF.RAW_TRACEPOINT)

# Get the BPF_PROG_ARRAY table
prog_array=b.get_table("syscall")

# Ignore all syscalls initially
for i in range(len(prog_array)):
    prog_array[ct.c_int(i)]=ct.c_int(ignore_fn.fd) 

# Only enable few syscalls which are of the interest
prog_array[ct.c_int(59)]=ct.c_int(exec_fn.fd)   # execve
prog_array[ct.c_int(222)]=ct.c_int(timer_fn.fd) # timer_create
prog_array[ct.c_int(223)]=ct.c_int(timer_fn.fd) # timer
prog_array[ct.c_int(224)]=ct.c_int(timer_fn.fd) # timer_gettime
prog_array[ct.c_int(225)]=ct.c_int(timer_fn.fd) # timer_settime
prog_array[ct.c_int(226)]=ct.c_int(timer_fn.fd) # timer_delete

# Print the trace output
b.trace_print()