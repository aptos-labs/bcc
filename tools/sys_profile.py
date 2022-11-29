#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# profile  Profile CPU usage by sampling stack traces at a timed interval.
#          For Linux, uses BCC, BPF, perf_events. Embedded C.
#
# This is an efficient profiler, as stack traces are frequency counted in
# kernel context, rather than passing every stack to user space for frequency
# counting there. Only the unique stacks and counts are passed to user space
# at the end of the profile, greatly reducing the kernel<->user transfer.
#
# By default CPU idle stacks are excluded by simply excluding PID 0.
#
# REQUIRES: Linux 4.9+ (BPF_PROG_TYPE_PERF_EVENT support). Under tools/old is
# a version of this tool that may work on Linux 4.6 - 4.8.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# THANKS: Alexei Starovoitov, who added proper BPF profiling support to Linux;
# Sasha Goldshtein, Andrew Birchall, and Evgeny Vereshchagin, who wrote much
# of the code here, borrowed from tracepoint.py and offcputime.py; and
# Teng Qin, who added perf support in bcc.
#
# 15-Jul-2016   Brendan Gregg   Created this.
# 20-Oct-2016      "      "     Switched to use the new 4.9 support.
# 26-Jan-2019      "      "     Changed to exclude CPU idle by default.

from __future__ import print_function
from bcc import BPF, PerfType, PerfSWConfig
from bcc.containers import filter_by_containers
from sys import stderr
from time import sleep
import argparse
import signal
import os
import errno

#
# Process Arguments
#

# arg validation
def positive_int(val):
    try:
        ival = int(val)
    except ValueError:
        raise argparse.ArgumentTypeError("must be an integer")

    if ival < 0:
        raise argparse.ArgumentTypeError("must be positive")
    return ival

def positive_int_list(val):
    vlist = val.split(",")
    if len(vlist) <= 0:
        raise argparse.ArgumentTypeError("must be an integer list")

    return [positive_int(v) for v in vlist]

def positive_nonzero_int(val):
    ival = positive_int(val)
    if ival == 0:
        raise argparse.ArgumentTypeError("must be nonzero")
    return ival

def stack_id_err(stack_id):
    # -EFAULT in get_stackid normally means the stack-trace is not available,
    # Such as getting kernel stack trace in userspace code
    return (stack_id < 0) and (stack_id != -errno.EFAULT)

# arguments
examples = """examples:
    ./profile             # profile syscall stack traces at 49 Hertz until Ctrl-C
    ./profile 5           # profile for 5 seconds only
    ./profile -f 5        # output in folded format for flame graphs
    ./profile -p 185      # only profile process with PID 185
    ./profile -L 185      # only profile thread with TID 185
    ./profile --cgroupmap mappath  # only trace cgroups in this BPF map
    ./profile --mntnsmap mappath   # only trace mount namespaces in the map
"""
parser = argparse.ArgumentParser(
    description="Profile CPU stack traces at a timed interval",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
thread_group = parser.add_mutually_exclusive_group()
thread_group.add_argument("-p", "--pid", type=positive_int_list,
    help="profile process with one or more comma separated PIDs only")
thread_group.add_argument("-L", "--tid", type=positive_int_list,
    help="profile thread with one or more comma separated TIDs only")
parser.add_argument("-c", "--count", type=positive_int,
    help="sample period, number of events")
parser.add_argument("-d", "--delimited", action="store_true",
    help="insert delimiter between kernel/user stacks")
parser.add_argument("-f", "--folded", action="store_true",
    help="output folded format, one line per stack (for flame graphs)")
parser.add_argument("--stack-storage-size", default=16384,
    type=positive_nonzero_int,
    help="the number of unique stack traces that can be stored and "
        "displayed (default %(default)s)")
parser.add_argument("duration", nargs="?", default=99999999,
    type=positive_nonzero_int,
    help="duration of trace, in seconds")
parser.add_argument("-C", "--cpu", type=int, default=-1,
    help="cpu number to run profile on")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
parser.add_argument("--cgroupmap",
    help="trace cgroups in this BPF map only")
parser.add_argument("--mntnsmap",
    help="trace mount namespaces in this BPF map only")

# option logic
args = parser.parse_args()
duration = int(args.duration)
debug = 0
need_delimiter = args.delimited and not (args.kernel_stacks_only or
    args.user_stacks_only)

#
# Setup BPF
#

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>
#include <linux/sched.h>

struct key_t {
    u32 pid;
    int user_stack_id;
    char name[TASK_COMM_LEN];
};
BPF_HASH(counts, struct key_t);
BPF_STACK_TRACE(stack_traces, STACK_STORAGE_SIZE);

static int do_syscall_event(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    u32 pid = id;

    if (!(THREAD_FILTER))
        return 0;

    if (container_should_be_filtered()) {
        return 0;
    }

    // create map key
    struct key_t key = {.pid = tgid};
    bpf_get_current_comm(&key.name, sizeof(key.name));

    // get stacks
    key.user_stack_id = USER_STACK_GET;

    counts.increment(key);
    return 0;
}

int syscall__futex(struct pt_regs *ctx) {
    return do_syscall_event(ctx);
}

struct data_t {
    u64 count;
    u64 total_ns;
};

BPF_HASH(start, u64, u64);
BPF_HASH(data, u32, struct data_t);

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

#ifdef FILTER_SYSCALL_NR
    if (args->id != FILTER_SYSCALL_NR)
        return 0;
#endif

#ifdef FILTER_PID
    if (pid != FILTER_PID)
        return 0;
#endif

#ifdef FILTER_TID
    if (tid != FILTER_TID)
        return 0;
#endif

    u64 t = bpf_ktime_get_ns();
    start.update(&pid_tgid, &t);
    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_exit) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

#ifdef FILTER_SYSCALL_NR
    if (args->id != FILTER_SYSCALL_NR)
        return 0;
#endif

#ifdef FILTER_PID
    if (pid != FILTER_PID)
        return 0;
#endif

#ifdef FILTER_TID
    if (tid != FILTER_TID)
        return 0;
#endif

#ifdef FILTER_FAILED
    if (args->ret >= 0)
        return 0;
#endif

#ifdef FILTER_ERRNO
    if (args->ret != -FILTER_ERRNO)
        return 0;
#endif

#ifdef BY_PROCESS
    u32 key = pid_tgid >> 32;
#else
    u32 key = args->id;
#endif

    struct data_t *val, zero = {};
    u64 *start_ns = start.lookup(&pid_tgid);
    if (!start_ns)
        return 0;

    val = data.lookup_or_try_init(&key, &zero);
    if (val) {
        lock_xadd(&val->count, 1);
        lock_xadd(&val->total_ns, bpf_ktime_get_ns() - *start_ns);
    }
    return 0;
}

"""

# set process/thread filter
thread_context = ""
thread_filter = ""
if args.pid is not None:
    thread_context = "PID %s" % args.pid
    thread_filter = " || ".join("tgid == " + str(pid) for pid in args.pid)
elif args.tid is not None:
    thread_context = "TID %s" % args.tid
    thread_filter = " || ".join("pid == " + str(tid) for tid in args.tid)
else:
    thread_context = "all threads"
    thread_filter = '1'
bpf_text = bpf_text.replace('THREAD_FILTER', thread_filter)

# set stack storage size
bpf_text = bpf_text.replace('STACK_STORAGE_SIZE', str(args.stack_storage_size))

# handle stack args
user_stack_get = "stack_traces.get_stackid(ctx, BPF_F_USER_STACK)"

bpf_text = bpf_text.replace('USER_STACK_GET', user_stack_get)
bpf_text = filter_by_containers(args) + bpf_text

sample_context = "Futex System Calls"

# header
if not args.folded:
    print("Sampling at %s of %s" %
        (sample_context, thread_context), end="")
    if args.cpu >= 0:
        print(" on CPU#{}".format(args.cpu), end="")
    if duration < 99999999:
        print(" for %d secs." % duration)
    else:
        print("... Hit Ctrl-C to end.")

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# initialize BPF & perf_events
b = BPF(text=bpf_text)
#Presumably can do the same for more
futex_fnname = b.get_syscall_fnname("futex")
b.attach_kprobe(event=futex_fnname, fn_name="syscall__futex")

# signal handler
def signal_ignore(signal, frame):
    print()

#
# Output Report
#

# collect samples
try:
    sleep(duration)
except KeyboardInterrupt:
    # as cleanup can take some time, trap Ctrl-C:
    signal.signal(signal.SIGINT, signal_ignore)

if not args.folded:
    print()

def aksym(addr):
    if args.annotations:
        return b.ksym(addr) + "_[k]".encode()
    else:
        return b.ksym(addr)

# output stacks
missing_stacks = 0
has_collision = False
counts = b.get_table("counts")
stack_traces = b.get_table("stack_traces")
for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
    # handle get_stackid errors
    if stack_id_err(k.user_stack_id):
        missing_stacks += 1
        has_collision = has_collision or k.user_stack_id == -errno.EEXIST

    user_stack = [] if k.user_stack_id < 0 else \
        stack_traces.walk(k.user_stack_id)

    if args.folded:
        # print folded stack output
        user_stack = list(user_stack)
        line = [k.name.decode('utf-8', 'replace')]
        # if we failed to get the stack is, such as due to no space (-ENOMEM) or
        # hash collision (-EEXIST), we still print a placeholder for consistency
        if stack_id_err(k.user_stack_id):
            line.append("[Missed User Stack]")
        else:
            line.extend([b.sym(addr, k.pid).decode('utf-8', 'replace') for addr in reversed(user_stack)])

        print("%s %d" % (";".join(line), v.value))
    else:
        # print default multi-line stack output
        if need_delimiter and k.user_stack_id >= 0:
                print("    --")
        if stack_id_err(k.user_stack_id):
            print("    [Missed User Stack]")
        else:
            for addr in user_stack:
                print("    %s" % b.sym(addr, k.pid).decode('utf-8', 'replace'))
        print("    %-16s %s (%d)" % ("-", k.name.decode('utf-8', 'replace'), k.pid))
        print("        %d\n" % v.value)

# check missing
if missing_stacks > 0:
    enomem_str = "" if not has_collision else \
        " Consider increasing --stack-storage-size."
    print("WARNING: %d stack traces could not be displayed.%s" %
        (missing_stacks, enomem_str),
        file=stderr)
