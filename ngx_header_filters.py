#!/usr/bin/python
#
# you need compile nginx using -fno-omit-frame-pointer
# 31-Mar-2017   Simon Liu   Created this.

from __future__ import print_function
from bcc import BPF, USDT
import sys
import ctypes as ct
import os
import os.path

def usage():
    print("USAGE: ngx_header_filters PID")
    exit()
if len(sys.argv) < 2:
    usage()

bpf_text="""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
struct data_t {
        int stack_id;
};
BPF_PERF_OUTPUT(events);
BPF_STACK_TRACE(stack_traces, 1028)

void trace_header_filter(struct pt_regs *ctx) {
    u64 stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID | BPF_F_USER_STACK);
    struct data_t data = {stack_id};
    events.perf_submit(ctx, &data, sizeof(data));
}
"""

pid = int(sys.argv[1])

b = BPF(text=bpf_text)
exec_file = "/proc/{}/exe".format(pid)
if not os.path.exists(exec_file):
    print("Nginx process {} is not running or you do not have enough permissions.\n".format(pid))
    exit()

nginx_path=os.readlink(exec_file)
b.attach_uprobe(name=nginx_path, sym="ngx_http_header_filter", fn_name="trace_header_filter", pid=pid)

stack_traces = b.get_table("stack_traces")
class Data(ct.Structure):
    _fields_ = [
        ("stack_id", ct.c_int),
    ]

def print_event(cpu, data, size):
    data = ct.cast(data, ct.POINTER(Data)).contents
    stack_id = data.stack_id
    stack = list(stack_traces.walk(stack_id))
    start_print = False
    for addr in reversed(stack):
        s = b.sym(addr,pid)
        if s == "ngx_http_send_header":
            start_print = True
        elif start_print:
            print(s)
    print("\n")


# loop with callback to print_event
b["events"].open_perf_buffer(print_event, page_cnt=64)
print("tracing {}\n".format(nginx_path))
while 1:
    b.kprobe_poll()
