#! /usr/bin/env python

from __future__ import print_function
from bcc import BPF, USDT
import argparse
import ctypes as ct
import time
import os


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
    char clazz[80];
    char method[80];
};

BPF_PERF_OUTPUT(calls);
BPF_HASH(entry, u64, u64);
"""

# template pour tracer un probe
php_trace_template = """
int NAME(struct pt_regs *ctx) {
    u64 *depth, zero = 0, clazz = 0, method = 0 ;
    struct call_t data = {};

    READ_CLASS
    READ_METHOD
    bpf_probe_read(&data.clazz, sizeof(data.clazz), (void *)clazz);
    bpf_probe_read(&data.method, sizeof(data.method), (void *)method);

    data.pid = bpf_get_current_pid_tgid();
    depth = entry.lookup_or_init(&data.pid, &zero);
    data.depth = DEPTH;
    UPDATE

    calls.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

sys_trace_template = """
TRACEPOINT_PROBE(syscalls, sys_exit_socket) {
    u64 pid = bpf_get_current_pid_tgid();
    u64 pid_exp = 0;
    bpf_probe_read(&pid_exp, sizeof(pid_exp), PID);
    //if (pid != PID)
    //    return 0;
    u64 *depth, zero = 0, clazz = 0, method = 0 ;
    struct call_t data = {};
    data.pid = pid_exp;
    depth = entry.lookup_or_init(&data.pid, &zero);
    data.depth = *depth;
    char str[] = "socket";
    bpf_probe_read_str(&data.method, sizeof(data.method), str);
    calls.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

# Fonction pour activer un probe
def enable_probe(probe_name, func_name, read_class, read_method, is_return):
    global program, php_trace_template, usdt
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
print(sys_trace_template.replace("PID", str(args.pid)))
program += sys_trace_template.replace("PID", str(args.pid))

# Charger le programme dans eBPF
bpf = BPF(text=program, usdt_contexts=[usdt])

print("php tool, pid = %s... Ctrl-C to quit." % (args.pid))
print("%-6s %-8s %s" % ("PID", "TIME(us)", "METHOD"))

# Classe pour refleter la struct C
class CallEvent(ct.Structure):
    _fields_ = [
        ("depth", ct.c_ulonglong),
        ("pid", ct.c_ulonglong),
        ("clazz", ct.c_char * 80),
        ("method", ct.c_char * 80)
        ]

# compteur de temps
start_ts = time.time()

# Fonction Print
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(CallEvent)).contents
    depth = event.depth & (~(1 << 63))
    direction = "<- " if event.depth & (1 << 63) else "-> "
    print("%-6d %-8.3f %-40s" % (
                event.pid >> 32,
                time.time() - start_ts,
                ("  " * (depth - 1)) + direction + event.clazz.decode('utf-8', 'replace') + "." + event.method.decode('utf-8', 'replace')
            )
        )

bpf["calls"].open_perf_buffer(print_event)
while 1:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
