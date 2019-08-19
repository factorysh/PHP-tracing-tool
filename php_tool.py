#! /usr/bin/env python

from __future__ import print_function
from bcc import BPF, USDT
import argparse
import ctypes as ct
import time
import os
import ipaddress
import socket

# globals
total_lat = 0
usdt_tab = []
syscalls = ["socket", "socketpair", "bind", "listen", "accept", "accept4", "connect", "getsockname", "getpeername", "sendto", "recvfrom", "setsockopt", "getsockopt", "shutdown", "sendmsg", "sendmmsg", "recvmsg", "recvmmsg", "read", "write", "open", "sendfile64"]
#syscalls = []

SYSCALL = 1
PADDING = "  "
BLUE = '\033[95m'
UNDERLINE = '\033[4m'
ENDC = '\033[0m'

# C result class
class CallEvent(ct.Structure):
    _fields_ = [
        ("depth", ct.c_ulonglong),
        ("pid", ct.c_ulonglong),
        ("lat", ct.c_ulonglong),
        ("type", ct.c_ulonglong),
        ("fdw", ct.c_ulonglong),
        ("fdr", ct.c_ulonglong),
        ("addr", ct.c_ulonglong),
        ("clazz", ct.c_char * 80),
        ("method", ct.c_char * 80),
        ("file", ct.c_char * 80),
        ]

# cli arguments
parser = argparse.ArgumentParser(
    description="php_tool",
    formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("pid", type=int, nargs="+", help="process id to attach to")
parser.add_argument("--debug", action="store_true", help="debug mode: print the generated BPF program")
parser.add_argument("--check", action="store_true", help="print the generated BPF program and quit")

args = parser.parse_args()

###############################################################################
# TEMPLATES
###############################################################################

# program template
program = """
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>

struct call_t {
    u64     depth;                  // first bit is direction (0 entry, 1 return)
    u64     pid;                    // (tgid << 32) + pid from bpf_get_current...
    u64     lat;                    // time latency
    u64     type;                   // syscall or php function
    u64     fdw;                    // filedescriptor write
    u64     fdr;                    // filedescriptor read
    u64     addr;                   // addr to connect
    char    clazz[80];              // class name
    char    method[80];             // method name
    char    file[80];               // php file name
};

#define SYS     1
#define FUNC    2
#define DISK    3
#define NET     4

BPF_PERF_OUTPUT(calls);
BPF_HASH(entry, u64, u64);
BPF_HASH(start, u64, u64);
BPF_HASH(start_func, u64, u64);
BPF_HASH(fdw, u64, u64);
BPF_HASH(addr, u64, u64);
"""

# php probes template
php_trace_template = """
int {name}(struct pt_regs *ctx) {{
    u64 *depth, zero = 0, clazz = 0, method = 0, file = 0;
    struct call_t data = {{}};
    u64 pid = bpf_get_current_pid_tgid();

    {read_class}
    {read_method}
    {read_file}
    bpf_probe_read_str(&data.clazz, sizeof(data.clazz), (void *)clazz);
    bpf_probe_read_str(&data.method, sizeof(data.method), (void *)method);
    bpf_probe_read_str(&data.file, sizeof(data.file), (void *)file);
    u64 id = clazz + method + file;
    
    data.type = FUNC;
    data.pid = pid;
    depth = entry.lookup_or_init(&data.pid, &zero);
    data.depth = {depth};
    {update_func}   
    
    if (!(data.depth & (1ULL << 63))) {{
        u64 time = bpf_ktime_get_ns();
        start_func.update(&id, &time);
    }} else {{
        u64 *start_ns = start_func.lookup(&id);
        if (!start_ns) {{
            calls.perf_submit(ctx, &data, sizeof(data));
            start_func.delete(&id);
            return 0;
        }}
        data.lat = bpf_ktime_get_ns() - *start_ns;
        start_func.delete(&method);
    }}

    calls.perf_submit(ctx, &data, sizeof(data));
    return 0;
}}
"""

# syscall tracepoint template
sys_trace_template = """
TRACEPOINT_PROBE(syscalls, sys_enter_{syscall_name}) {{
    u64 pid = bpf_get_current_pid_tgid();
    if ({pid_condition}) {{
        return 0;
    }}
    u64 time = bpf_ktime_get_ns();
    start.update(&pid, &time);
    SYSCALL_ENTER_LOGIC
    return 0;
}}

TRACEPOINT_PROBE(syscalls, sys_exit_{syscall_name}) {{
    u64 pid = bpf_get_current_pid_tgid();
    if ({pid_condition}) {{
        return 0;
    }}

    u64 *depth, zero = 0, clazz = 0, method = 0;

    struct call_t data = {{}};
    data.type = SYS;
    data.pid = pid;
    depth = entry.lookup_or_init(&data.pid, &zero);
    data.depth = *depth;
    char method_str[80] = "{syscall_name}";
    bpf_probe_read_str(&data.method, sizeof(data.method), method_str);

    u64 *start_ns = start.lookup(&pid);
    if (!start_ns) {{
        calls.perf_submit(args, &data, sizeof(data));
        return 0;
    }}
    
    data.lat = bpf_ktime_get_ns() - *start_ns;
    SYSCALL_EXIT_LOGIC
    calls.perf_submit(args, &data, sizeof(data));
    return 0;
}}
"""

###############################################################################
# FUNCTIONS
###############################################################################

def print_event(pid, lat, message, depth):
    print("%-6d %-6s %-40s" % (pid, str(lat), (PADDING * (depth - 1)) + message))

# callback function for open_perf_buffer
def callback(cpu, data, size):
    global total_lat
    event = ct.cast(data, ct.POINTER(CallEvent)).contents
    depth = event.depth & (~(1 << 63))
    # syscalls
    if event.type == SYSCALL:
        total_lat += event.lat
        message = "sys." + BLUE + event.method.decode("utf-8", "replace") + ENDC
        if event.fdw > 0:
            message += " to fd: " + str(event.fdw)
        if event.fdr > 0:
            message += " return fd: " + str(event.fdr)
        if event.addr > 0:
            addr = str(ipaddress.ip_address(event.addr))
            rev = addr.split('.')[::-1]
            addr = '.'.join(rev)
            message += " connect to: " + addr
            try:
                host = socket.gethostbyaddr(addr)
                message += " -> " + host[0]
            except socket.herror or socket.gaierror:
                pass
        print_event(
            event.pid >> 32,
            event.lat,
            message,
            depth
        )    
    # php function
    else:
        if event.depth & (1 << 63):
            direction = "<- "
            if syscalls and total_lat > 0:
                print_event(
                        event.pid >> 32,
                        total_lat,
                        BLUE + "traced syscalls total latence" + ENDC,
                        depth
                )    
                total_lat = 0
        else:
            direction = "-> "
        print_event(
                event.pid >> 32,
                str(event.lat) if event.lat > 0 else "-",
                direction + event.clazz.decode('utf-8', 'replace') + "." \
                    + event.method.decode('utf-8', 'replace') + " " \
                    + UNDERLINE + "from " + event.file + ENDC,
                depth
            )
        if event.depth & (1 << 63) and  event.method == "main" and depth == 1:
            exit()

# function for trace a php probe
def generate_php_probe(probe_name, func_name, read_class, read_method, read_file, is_return):
    global program, php_trace_template, usdt
    #if is_return:
    #    program += "#define IS_RETURN 1"
    depth = "*depth + 1" if not is_return else "*depth | (1ULL << 63)"
    update = "++(*depth);" if not is_return else "if (*depth) --(*depth);"
    values = {
            'name': func_name,
            'read_class': read_class,
            'read_method': read_method,
            'read_file': read_file,
            'depth': depth,
            'update_func': update
            }
    for pid in args.pid:
        usdt = USDT(pid=pid)
        usdt_tab.append(usdt)
        usdt.enable_probe_or_bail(probe_name, func_name)
    return php_trace_template.format(**values)

#
def check_syscall(func):
    def wrapper(*args, **kwargs):
        template = func(*args)
        enter_logic = ""
        exit_logic = ""
        if args[0] == "write" or args[0] == "sendto" or args[0] == "sendmsg":
            enter_logic = """
            u64 fd = args->fd;
            fdw.update(&pid, &fd);
            """
            exit_logic = """
            u64 *fd = fdw.lookup(&pid);
            if (!fd) {
                return 0;
            }
            data.fdw = *fd;
            fdw.delete(&pid);
            """
        elif args[0] == "open" or args[0] == "socket":
            exit_logic = """
            u64 ret = args->ret;
            data.fdr = ret;
            """
        elif args[0] == "connect":
            enter_logic = """
            struct sockaddr_in *useraddr = ((struct sockaddr_in *)(args->uservaddr));
            u64 a = useraddr->sin_addr.s_addr;
            addr.update(&pid, &a);
            """
            exit_logic = """
            u64 *a = addr.lookup(&pid);
            if (!a) {
                return 0;
            }
            data.addr = *a;
            addr.delete(&pid);
            """
        return template.replace("SYSCALL_ENTER_LOGIC", enter_logic).replace("SYSCALL_EXIT_LOGIC", exit_logic)
    return wrapper


# function for trace a syscall
@check_syscall
def generate_syscall_tracepoint(sys_name):
    global program
    # get the pid condition
    pid_condition = ""
    for i, pid in enumerate(args.pid):
        pid_condition += "pid >> 32 != %s" % (str(pid))
        if i < len(args.pid) - 1:
            pid_condition += " && "
    # template
    values = {
            'syscall_name': sys_name,
            'pid_condition': pid_condition
            }
    return sys_trace_template.format(**values)

###############################################################################

# Generate the C program

# trace php function entry and return
program += generate_php_probe("function__entry", "php_entry",
    "bpf_usdt_readarg(4, ctx, &clazz);",
    "bpf_usdt_readarg(1, ctx, &method);",
    "bpf_usdt_readarg(2, ctx, &file);", is_return=False)
program += generate_php_probe("function__return", "php_return",
    "bpf_usdt_readarg(4, ctx, &clazz);",
    "bpf_usdt_readarg(1, ctx, &method);",
    "bpf_usdt_readarg(2, ctx, &file);", is_return=True)

# trace the syscalls in the list
for sys in syscalls:
    program += generate_syscall_tracepoint(sys)

# C PROGRAM READY!

# debug options
if args.check or args.debug:
    print(program)
    if args.check:
        exit()

# inject the C program generated in eBPF
bpf = BPF(text=program, usdt_contexts=usdt_tab)

print("php super tool, pid = %s... Ctrl-C to quit." % (args.pid))
print("%-6s %-6s %s" % ("PID", "LAT", "METHOD"))

bpf["calls"].open_perf_buffer(callback, page_cnt=4096)
while 1:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
