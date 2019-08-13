#! /usr/bin/env python

from __future__ import print_function
from bcc import BPF, USDT
import argparse
import ctypes as ct
import time
import os

class c:
    BLUE = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Recuperer le pid en argument
parser = argparse.ArgumentParser(
    description="php_tool",
    formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("pid", type=int, nargs="+", help="process id to attach to")
parser.add_argument("-M", "--method",
    help="trace only calls to methods starting with this prefix")
parser.add_argument("-C", "--class", dest="clazz",
    help="trace only calls to classes starting with this prefix")
args = parser.parse_args()


# Debut du programme
program = """
struct call_t {
    u64 depth;                  // first bit is direction (0 entry, 1 return)
    u64 pid;                    // (tgid << 32) + pid from bpf_get_current...
    u64 lat;
    u64 type;
    char clazz[80];
    char method[80];
    char file[80];
};

#define SYS 1
#define FUNC 2

BPF_PERF_OUTPUT(calls);
BPF_HASH(entry, u64, u64);
BPF_HASH(start, u64, u64);
BPF_HASH(start_func, u64, u64);
BPF_HASH(dis_sys, u64, u64);
"""

# template pour tracer un probe
php_trace_template = """
int NAME(struct pt_regs *ctx) {
    u64 *depth, zero = 0, clazz = 0, method = 0, file = 0;
    struct call_t data = {};
    u64 pid = bpf_get_current_pid_tgid();

    READ_CLASS
    READ_METHOD
    READ_FILE
    bpf_probe_read(&data.clazz, sizeof(data.clazz), (void *)clazz);
    bpf_probe_read(&data.method, sizeof(data.method), (void *)method);

    bpf_probe_read(&data.file, sizeof(data.file), (void *)file);

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

    data.type = FUNC;
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
    if (PID_CONDITION)
        return 0;
    //if (pid >> 32 != PID)
    //    return 0;
    u64 time = bpf_ktime_get_ns();
    start.update(&pid, &time);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_SYSCALL) {
    u64 pid = bpf_get_current_pid_tgid();
    if (PID_CONDITION)
        return 0;
    //if (pid >> 32 != PID)
    //    return 0;
    u64 *depth, zero = 0, clazz = 0, method = 0 ;
    u64 *start_ns = start.lookup(&pid);
    if (!start_ns)
        return 0;
    struct call_t data = {};
    data.lat = bpf_ktime_get_ns() - *start_ns;
    data.type = SYS;
    data.pid = pid;
    depth = entry.lookup_or_init(&data.pid, &zero);
    data.depth = *depth;
    char method_str[80] = "SYSCALL";
    bpf_probe_read_str(&data.method, sizeof(data.method), method_str);
    char class_str[80] = "sys";
    bpf_probe_read_str(&data.clazz, sizeof(data.clazz), class_str);
    calls.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

prefix_template = """
static inline bool prefix_%s(char *actual) {
    char expected[] = "%s";
    for (int i = 0; i < sizeof(expected) - 1; ++i) {
        if (expected[i] != actual[i]) {
            return false;
        }
    }
    return true;
}
"""

if args.method:
    program += prefix_template % ("method", args.method)

usdt_tab = []

# Fonction pour activer un probe
def enable_probe(probe_name, func_name, read_class, read_method, read_file, is_return):
    global program, php_trace_template, usdt
    if is_return:
        program += "#define IS_RETURN 1"
    depth = "*depth + 1" if not is_return else "*depth | (1ULL << 63)"
    update = "++(*depth);" if not is_return else "if (*depth) --(*depth);"
    #filter_method = "if (!prefix_method(data.method)) { dis_sys.update(); return 0; } "
    program += php_trace_template.replace("NAME", func_name)                \
                             .replace("READ_CLASS", read_class)         \
                             .replace("READ_METHOD", read_method)       \
                             .replace("READ_FILE", read_file)       \
                             .replace("DEPTH", depth)                   \
                             .replace("UPDATE", update)
    for pid in args.pid:
        usdt = USDT(pid=pid)
        usdt_tab.append(usdt)
        usdt.enable_probe_or_bail(probe_name, func_name)

enable_probe("function__entry", "php_entry",
    "bpf_usdt_readarg(4, ctx, &clazz);",
    "bpf_usdt_readarg(1, ctx, &method);",
    "bpf_usdt_readarg(2, ctx, &file);", is_return=False)
enable_probe("function__return", "php_return",
    "bpf_usdt_readarg(4, ctx, &clazz);",
    "bpf_usdt_readarg(1, ctx, &method);",
    "bpf_usdt_readarg(2, ctx, &file);", is_return=True)

# syscalls
#depth = "*depth + 1" if not is_return else "*depth | (1ULL << 63)"
#update = "++(*depth);" if not is_return else "if (*depth) --(*depth);"

syscalls = ["socket", "socketpair", "bind", "listen", "accept", "accept4", "connect", "getsockname", "getpeername", "sendto", "recvfrom", "setsockopt", "getsockopt", "shutdown", "sendmsg", "sendmmsg", "recvmsg", "recvmmsg", "read", "write", "sendfile64"]

condition = ""
for i, pid in enumerate(args.pid):
    condition += "pid >> 32 != %s" % (str(pid))
    if i < len(args.pid) - 1:
        condition += " && "

new_template = sys_trace_template.replace("PID_CONDITION", condition)
for sys in syscalls:
    program += new_template.replace("SYSCALL", sys)

#print(program)
# Charger le programme dans eBPF
bpf = BPF(text=program, usdt_contexts=usdt_tab)

print("php tool, pid = %s... Ctrl-C to quit." % (args.pid))
print("%-6s %-16s %s" % ("PID", "LAT", "METHOD"))

# Classe pour refleter la struct C
class CallEvent(ct.Structure):
    _fields_ = [
        ("depth", ct.c_ulonglong),
        ("pid", ct.c_ulonglong),
        ("lat", ct.c_ulonglong),
        ("type", ct.c_ulonglong),
        ("clazz", ct.c_char * 80),
        ("method", ct.c_char * 80),
        ("file", ct.c_char * 80)
        ]

total_lat = 0
# Fonction Print
def print_event(cpu, data, size):
    global total_lat
    event = ct.cast(data, ct.POINTER(CallEvent)).contents
    depth = event.depth & (~(1 << 63))
    if event.type == 1:
        total_lat += event.lat
        print("%-6d %-16u %-40s" % (event.pid >> 32, event.lat, ("  " * (depth - 1)) + event.clazz.decode("utf-8", "replace") + "." + c.BLUE + event.method.decode("utf-8", "replace") + c.ENDC))    
    else:
        if event.depth & (1 << 63):
            direction = "<- "
            print("%-6d %-16u %-40s" % (event.pid >> 32, total_lat, ("  " * (depth - 1)) + c.RED + "traced syscalls total latence" + c.ENDC))    
            total_lat = 0
        else:
            direction = "-> "
        print("%-6d %-16s %s" % (
                event.pid >> 32,
                str(event.lat) if event.lat > 0 else "-",
                ("  " * (depth - 1)) + direction + event.clazz.decode('utf-8', 'replace') + "." + event.method.decode('utf-8', 'replace') + " " + c.UNDERLINE + "from " + event.file + c.ENDC
            )
        )

bpf["calls"].open_perf_buffer(print_event)
while 1:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
