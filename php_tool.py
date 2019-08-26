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
total_net_time = 0
total_disk_time = 0
net_write_volume = 0
disk_write_volume = 0
net_read_volume = 0
disk_read_volume = 0

usdt_tab = []
syscalls = ["socket", "socketpair", "bind", "listen", "accept", "accept4",
            "connect", "getsockname", "getpeername", "sendto", "recvfrom",
            "setsockopt", "getsockopt", "shutdown", "sendmsg", "sendmmsg",
            "recvmsg", "recvmmsg", "read", "write", "open", "openat", "creat",
            "close", "sendfile64"]
#syscalls = []

SYSCALL = 1
DISK = 3
NET = 4
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
        ("fd_type", ct.c_ulonglong),
        ("fdw", ct.c_ulonglong),
        ("fdr", ct.c_ulonglong),
        ("fd_ret", ct.c_ulonglong),
        ("bytes_write", ct.c_ulonglong),
        ("bytes_read", ct.c_ulonglong),
        ("addr", ct.c_ulonglong),
        ("clazz", ct.c_char * 80),
        ("method", ct.c_char * 80),
        ("file", ct.c_char * 80),
        ]


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
    u64     fd_type;                // disk or net filedescriptor
    u64     fdw;                    // filedescriptor write
    u64     fdr;                    // filedescriptor read
    u64     fd_ret;                 // returned filedescriptor
    u64     bytes_write;            // number of write bytes
    u64     bytes_read;             // number of read bytes
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
BPF_HASH(fd, u64, u64);
BPF_HASH(addr, u64, u64);
BPF_HASH(filedescriptors, u64, u64);
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
# DECORATORS
###############################################################################


def replace_syscall_logic(template, enter_logic, exit_logic):
    return template.replace("SYSCALL_ENTER_LOGIC", enter_logic) \
            .replace("SYSCALL_EXIT_LOGIC", exit_logic)


def event_read_on_fd(func):
    """
    intercept when an open filedescriptor is read. get the fd for printing
    and get the type for sort the latence in NET or DISK
    """
    def wrapper(*args, **kwargs):
        template = func(*args)
        if args[0] == "read":
            enter_logic = """
            u64 fdarg = args->fd;
            fd.update(&pid, &fdarg);

            SYSCALL_ENTER_LOGIC
            """
            exit_logic = """
            data.bytes_read = args->ret;
            u64 *fdarg = fd.lookup(&pid);
            if (fdarg) {
                data.fdr = *fdarg;
                fd.delete(&pid);
                u64 *fdt = filedescriptors.lookup(fdarg);
                if (fdt) {
                    data.fd_type = *fdt;
                }
            }

            SYSCALL_EXIT_LOGIC
            """
        else:
            return template
        return template.replace("SYSCALL_ENTER_LOGIC", enter_logic) \
            .replace("SYSCALL_EXIT_LOGIC", exit_logic)
    return wrapper


def event_write_on_fd(func):
    """
    intercept when write on an open filedescriptor. get the fd for printing
    and get the type for sort the latence in NET or DISK
    """
    def wrapper(*args, **kwargs):
        template = func(*args)
        if args[0] == "write" or args[0] == "sendto" or args[0] == "sendmmsg":
            enter_logic = """
            u64 fdarg = args->fd;
            fd.update(&pid, &fdarg);

            SYSCALL_ENTER_LOGIC
            """
            exit_logic = """
            data.bytes_write = args->ret;
            u64 *fdarg = fd.lookup(&pid);
            if (fdarg) {
                data.fdw = *fdarg;
                fd.delete(&pid);
                u64 *fdt = filedescriptors.lookup(fdarg);
                if (fdt) {
                    data.fd_type = *fdt;
                }
            }

            SYSCALL_EXIT_LOGIC
            """
        else:
            return template
        return template.replace("SYSCALL_ENTER_LOGIC", enter_logic) \
            .replace("SYSCALL_EXIT_LOGIC", exit_logic)
    return wrapper


def store_open_fds(func):
    """
    store in a map the filedescriptors when open or socket open it.
    and store the type: NET or DISK
    """
    def wrapper(*args, **kwargs):
        template = func(*args)
        if args[0] == "open" or args[0] == "openat" or args[0] == "creat":
            exit_logic = """
            u64 ret = args->ret;
            u64 flag = DISK;
            filedescriptors.update(&ret, &flag);
            data.fd_ret = ret;

            SYSCALL_EXIT_LOGIC
            """
        elif args[0] == "socket":
            exit_logic = """
            u64 ret = args->ret;
            u64 flag = NET;
            filedescriptors.update(&ret, &flag);
            data.fd_ret = ret;

            SYSCALL_EXIT_LOGIC
            """
        else:
            return template
        return replace_syscall_logic(
            template, "SYSCALL_ENTER_LOGIC", exit_logic)
    return wrapper


def trace_connect_address(func):
    "decorator for trace the address in the connect arg"
    def wrapper(*args, **kwargs):
        template = func(*args)
        if args[0] == "connect":
            enter_logic = """
            struct sockaddr_in *useraddr = ((struct sockaddr_in *)(args->uservaddr));
            u64 a = useraddr->sin_addr.s_addr;
            addr.update(&pid, &a);
            u64 fdarg = args->fd;
            fd.update(&pid, &fdarg);

            SYSCALL_ENTER_LOGIC
            """
            exit_logic = """
            u64 *a = addr.lookup(&pid);
            if (a) {
                data.addr = *a;
                addr.delete(&pid);
            }
            u64 *fdarg = fd.lookup(&pid);
            if (fdarg) {
                data.fdw = *fdarg;
                fd.delete(&pid);
            }

            SYSCALL_EXIT_LOGIC
            """
        elif args[0] == "bind":
            enter_logic = """
            struct sockaddr_in *useraddr = ((struct sockaddr_in *)(args->umyaddr));
            u64 a = useraddr->sin_addr.s_addr;
            addr.update(&pid, &a);
            u64 fdarg = args->fd;
            fd.update(&pid, &fdarg);

            SYSCALL_ENTER_LOGIC
            """
            exit_logic = """
            u64 *a = addr.lookup(&pid);
            if (a) {
                data.addr = *a;
                addr.delete(&pid);
            }
            u64 *fdarg = fd.lookup(&pid);
            if (fdarg) {
                data.fdw = *fdarg;
                fd.delete(&pid);
            }

            SYSCALL_EXIT_LOGIC
            """
        else:
            return template
        return replace_syscall_logic(template, enter_logic, exit_logic)
    return wrapper


def minimal_decorator(func):
    def wrapper(*args, **kwargs):
        template = func(*args)
        return replace_syscall_logic(template, "", "")
    return wrapper

###############################################################################
# FUNCTIONS
###############################################################################


def print_event(pid, lat, message, depth):
    print("%-6d %-10s %-40s" %
          (pid, str(lat), (PADDING * (depth - 1)) + message))

# callback function for open_perf_buffer


def callback(cpu, data, size):
    global total_lat, total_net_time, total_disk_time, net_write_volume, \
        disk_write_volume, net_read_volume, disk_read_volume
    event = ct.cast(data, ct.POINTER(CallEvent)).contents
    depth = event.depth & (~(1 << 63))
    # If the event is a syscall
    if event.type == SYSCALL:

        # Add the syscall latency to the total lat
        total_lat += event.lat

        # If the syscall manipulate a NET filedescriptor (a unix socket)
        if event.fd_type == NET:
            total_net_time += event.lat
            # add the volume of written or read bytes in the total
            if event.bytes_write > 0:
                net_write_volume += event.bytes_write
            elif event.bytes_read > 0:
                net_read_volume += event.bytes_read
        # If the syscall manipulate a DISK filedescriptor
        elif event.fd_type == DISK:
            total_disk_time += event.lat
            # add the volume of written or read bytes in the total
            if event.bytes_write > 0:
                disk_write_volume += event.bytes_write
            elif event.bytes_read > 0:
                disk_read_volume += event.bytes_read

        # if there isn't the --syscalls option
        if not args.syscalls:
            return

        # generate the syscall print message
        message = "sys." + BLUE + event.method.decode("utf-8", "replace") + ENDC
        # if the syscall write on a fd
        if event.fdw > 0:
            message += " write on fd: " + str(event.fdw)
        # if the syscall read a fd
        if event.fdr > 0:
            message += " read fd: " + str(event.fdr)
        # if the syscall return a fd
        if event.fd_ret > 0:
            message += " return fd: " + str(event.fd_ret)

        # take the address for connect syscalls
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

        # print
        print_event(
            event.pid >> 32,
            event.lat,
            message,
            depth
        )
    # php function
    else:
        if event.depth & (1 << 63):
            # return function case
            direction = "<- "
            # print the report of all the syscalls in this function
            if syscalls and total_lat > 0:
                # the total latency
                print_event(
                        event.pid >> 32,
                        total_lat,
                        BLUE + "traced syscalls total latence" + ENDC,
                        depth
                )
            if syscalls and total_net_time > 0:
                # the total net usage time
                print_event(
                    event.pid >> 32, total_net_time, BLUE + (
                        "sys time spent on the network |-> %s bytes written, %s bytes read" %
                        (str(net_write_volume), str(net_read_volume))) + ENDC, depth)
            if syscalls and total_disk_time > 0:
                # the total disk usage time
                print_event(
                    event.pid >> 32, total_disk_time, BLUE + (
                        "sys time spent on the disk |-> %s bytes written, %s bytes read" %
                        (str(disk_write_volume), str(disk_read_volume))) + ENDC, depth)
                # reset
                total_lat = 0
                total_net_lat = 0
                total_disk_lat = 0
                net_write_volume = 0
                disk_write_volume = 0
                net_read_volume = 0
                disk_read_volume = 0
        else:
            # entry function case
            direction = "-> "
        # print the function details
        print_event(
                event.pid >> 32,
                str(event.lat) if event.lat > 0 else "-",
                direction + event.clazz.decode('utf-8', 'replace') + "."
                    + event.method.decode('utf-8', 'replace') + " "
                    + UNDERLINE + "from " + event.file + ENDC,
                depth
            )
        # quit on the last main return
        if event.depth & (1 << 63) and event.method == "main" and depth == 1:
            exit()

# function for trace a php probe


def generate_php_probe(
        probe_name,
        func_name,
        read_class,
        read_method,
        read_file,
        is_return):
    global program, php_trace_template, usdt
    # if is_return:
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

# function for trace a syscall


@minimal_decorator
@trace_connect_address
@event_write_on_fd
@event_read_on_fd
@store_open_fds
def generate_syscall_tracepoint(sys_name, pids):
    # get the pid condition
    pid_condition = ""
    for i, pid in enumerate(pids):
        pid_condition += "pid >> 32 != %s" % (str(pid))
        if i < len(pids) - 1:
            pid_condition += " && "
    # template
    values = {
            'syscall_name': sys_name,
            'pid_condition': pid_condition
            }
    return sys_trace_template.format(**values)

###############################################################################


def c_program(pids):
    "Generate the C program"
    # trace php function entry and return
    program = generate_php_probe("function__entry",
                                "php_entry",
                                "bpf_usdt_readarg(4, ctx, &clazz);",
                                "bpf_usdt_readarg(1, ctx, &method);",
                                "bpf_usdt_readarg(2, ctx, &file);",
                                is_return=False)
    program += generate_php_probe("function__return",
                                "php_return",
                                "bpf_usdt_readarg(4, ctx, &clazz);",
                                "bpf_usdt_readarg(1, ctx, &method);",
                                "bpf_usdt_readarg(2, ctx, &file);",
                                is_return=True)

    # trace the syscalls in the list
    for sys in syscalls:
        program += generate_syscall_tracepoint(sys, pids)
    return program


def main():
    # cli arguments
    parser = argparse.ArgumentParser(
        description="php_tool",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("pid", type=int, nargs="+", help="process id to attach to")
    parser.add_argument(
        "--debug", action="store_true",
        help="debug mode: print the generated BPF program")
    parser.add_argument(
        "--check", action="store_true",
        help="print the generated BPF program and quit")
    parser.add_argument(
        "-S", "--syscalls", action="store_true",
        help="print the syscalls details inside each function")

    args = parser.parse_args()

    program = c_program(args.pid)
    # debug options
    if args.check or args.debug:
        print(program)
        if args.check:
            exit()

    # inject the C program generated in eBPF
    bpf = BPF(text=program, usdt_contexts=usdt_tab)

    print("php super tool, pid = %s... Ctrl-C to quit." % (args.pid))
    print("%-6s %-10s %s" % ("PID", "LAT", "METHOD"))

    # don't forget the page_cnt option for increase the ring buffer size
    bpf["calls"].open_perf_buffer(callback, page_cnt=8192)
    while True:
        try:
            bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()


if __name__ == "__main__":
    main()
