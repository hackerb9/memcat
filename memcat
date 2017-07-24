#!/usr/bin/python3

# Dump memory of a process (Linux only).
# Based on Giles's answer from
# https://unix.stackexchange.com/questions/6267/how-to-re-load-all-running-applications-from-swap-space-into-ram/#6271
#
# Error checking added by hackerb9.

import ctypes, re, sys

## Partial interface to ptrace(2), only for PTRACE_ATTACH and PTRACE_DETACH.
c_ptrace = ctypes.CDLL("libc.so.6").ptrace
c_pid_t = ctypes.c_int32 # This assumes pid_t is int32_t
c_ptrace.argtypes = [ctypes.c_int, c_pid_t, ctypes.c_void_p, ctypes.c_void_p]
def ptrace(attach, pid):
    op = ctypes.c_int(16 if attach else 17) #PTRACE_ATTACH or PTRACE_DETACH
    c_pid = c_pid_t(pid)
    null = ctypes.c_void_p()
    err = c_ptrace(op, c_pid, null, null)
    if err != 0: raise (SysError, 'ptrace', err)

## Parse a line in /proc/$pid/maps. Return the boundaries of the chunk
## the read permission character.
def maps_line_range(line):
    m = re.match(r'([0-9A-Fa-f]+)-([0-9A-Fa-f]+) ([-r])(.*)', line)
    return [int(m.group(1), 16), int(m.group(2), 16), m.group(3), line[73:].strip()]

## Dump the readable chunks of memory mapped by a process
def cat_proc_mem(pid):
    ## Apparently we need to ptrace(PTRACE_ATTACH, $pid) to read /proc/$pid/mem
    ptrace(True, int(pid))
    mem_file=None
    try:
        ## Read the memory maps to see what address ranges are readable
        maps_file = open("/proc/" + pid + "/maps", 'r')
        ranges = map(maps_line_range, maps_file.readlines())
        maps_file.close()
        ## Read the readable mapped ranges
        mem_file = open("/proc/" + pid + "/mem", 'rb', 0)
        for r in ranges:
            if r[2] == 'r':
                try:
                    mem_file.seek(r[0])
                except OverflowError as e:
                    # [vsyscall] is located at 2**64 - 10 * 2**20. Why does it fail to seek there? 
                    sys.stderr.write("Warning, cannot seek to %X%s: %s\n" % (r[0], " (%s)" % (r[3]) if r[3] else "", e))
                    continue
                try:
                    chunk = mem_file.read(r[1] - r[0])
                except IOError as e:
                    # Some sections may not be readable, e.g., /dev/dri/card0
                    sys.stderr.write("Warning, cannot read %X - %X%s: %s\n" % (r[0],r[1], " (%s)" % (r[3]) if r[3] else "", e))
                    pass
                sys.stdout.buffer.write(chunk)
    ## Cleanup
    finally:
        if mem_file:  mem_file.close()
        ptrace(False, int(pid))

if __name__ == "__main__":
    for pid in sys.argv[1:]:
        cat_proc_mem(pid)
