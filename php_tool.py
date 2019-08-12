#! /usr/bin/env python

from __future__ import print_function
from bcc import BPF, USDT
import argparse
import ctypes as ct
import time
import os
import math


# Recuperer le pid en argument
parser = argparse.ArgumentParser(
    description="php_tool",
    formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("pid", type=int, help="process id to attach to")
args = parser.parse_args()

usdt = USDT(pid=args.pid)

# Debut du programme
program = """
struct call_t {
    u64 depth;                  // first bit is direction (0 entry, 1 return)
    u64 pid;                    // (tgid << 32) + pid from bpf_get_current...
    u64 lat;
    char clazz[80];
    char method[80];
};

BPF_PERF_OUTPUT(calls);
BPF_HASH(entry, u64, u64);
BPF_HASH(start, u64, u64);
BPF_HASH(start_func, u64, u64);
"""

# template pour tracer un probe
php_trace_template = """

int NAME(struct pt_regs *ctx) {
    u64 *depth, zero = 0, clazz = 0, method = 0 ;
    struct call_t data = {};
    u64 pid = bpf_get_current_pid_tgid();

    READ_CLASS
    READ_METHOD
    bpf_probe_read(&data.clazz, sizeof(data.clazz), (void *)clazz);
    bpf_probe_read(&data.method, sizeof(data.method), (void *)method);

    #ifndef IS_RETURN
    
    u64 time = bpf_ktime_get_ns();
    start_func.update(&method, &time);

    #endif
    #ifdef IS_RETURN

    u64 *start_ns = start_func.lookup(&method);
    if (!start_ns)
        return 0;
    data.lat = bpf_ktime_get_ns() - *start_ns;
    start_func.delete(&method);

    #endif

    data.pid = pid;
    depth = entry.lookup_or_init(&data.pid, &zero);
    data.depth = DEPTH;
    UPDATE

    calls.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

sys_trace_template = """
TRACEPOINT_PROBE(syscalls, sys_enter_SYSCALL) {
    u64 pid = bpf_get_current_pid_tgid();
    if (pid >> 32 != PID)
        return 0;
    u64 time = bpf_ktime_get_ns();
    start.update(&pid, &time);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_SYSCALL) {
    u64 pid = bpf_get_current_pid_tgid();
    if (pid >> 32 != PID)
        return 0;
    u64 *depth, zero = 0, clazz = 0, method = 0 ;
    u64 *start_ns = start.lookup(&pid);
    if (!start_ns)
        return 0;
    struct call_t data = {};
    data.lat = bpf_ktime_get_ns() - *start_ns;
    data.pid = pid;
    depth = entry.lookup_or_init(&data.pid, &zero);
    data.depth = *depth;
    char str[80] = "SYSCALL";
    bpf_probe_read_str(&data.method, sizeof(data.method), str);
    calls.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

# Fonction pour activer un probe
def enable_probe(probe_name, func_name, read_class, read_method, is_return):
    global program, php_trace_template, usdt
    if is_return:
        program += "#define IS_RETURN 1"
    depth = "*depth + 1" if not is_return else "*depth | (1ULL << 63)"
    update = "++(*depth);" if not is_return else "if (*depth) --(*depth);"
    program += php_trace_template.replace("NAME", func_name)                \
                             .replace("READ_CLASS", read_class)         \
                             .replace("READ_METHOD", read_method)       \
                             .replace("DEPTH", depth)                   \
                             .replace("UPDATE", update)
    usdt.enable_probe_or_bail(probe_name, func_name)

enable_probe("function__entry", "php_entry",
    "bpf_usdt_readarg(4, ctx, &clazz);",
    "bpf_usdt_readarg(1, ctx, &method);", is_return=False)
enable_probe("function__return", "php_return",
    "bpf_usdt_readarg(4, ctx, &clazz);",
    "bpf_usdt_readarg(1, ctx, &method);", is_return=True)

# syscalls
#depth = "*depth + 1" if not is_return else "*depth | (1ULL << 63)"
#update = "++(*depth);" if not is_return else "if (*depth) --(*depth);"

syscalls = ["socket", "socketpair", "bind", "listen", "accept", "accept4", "connect", "getsockname", "getpeername", "sendto", "recvfrom", "setsockopt", "getsockopt", "shutdown", "sendmsg", "sendmmsg", "recvmsg", "recvmmsg", "read", "write", "sendfile64"]
for sys in syscalls:
    program += sys_trace_template.replace("PID", str(args.pid)).replace("SYSCALL", sys)

print(program)
# Charger le programme dans eBPF
bpf = BPF(text=program, usdt_contexts=[usdt])

print("php tool, pid = %s... Ctrl-C to quit." % (args.pid))
print("%-6s %-8s %s" % ("PID", "LAT", "METHOD"))


# Classe pour refleter la struct C
class CallEvent(ct.Structure):
    _fields_ = [
        ("depth", ct.c_ulonglong),
        ("pid", ct.c_ulonglong),
        ("lat", ct.c_ulonglong),
        ("clazz", ct.c_char * 80),
        ("method", ct.c_char * 80)
        ]

# Fonction Print
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(CallEvent)).contents
    depth = event.depth & (~(1 << 63))
    direction = "<- " if event.depth & (1 << 63) else "-> "
    print("%-6d %-8u %-40s" % (
                event.pid >> 32,
                event.lat,
                ("  " * (depth - 1)) + direction + event.clazz.decode('utf-8', 'replace') + "." + event.method.decode('utf-8', 'replace')
            )
        )

bpf["calls"].open_perf_buffer(print_event)
while 1:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
