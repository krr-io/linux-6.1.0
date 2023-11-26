import os
import sys
import gdb
import time

# TRACE_FILE = "./rr_scripts/replay-trace"
TRACE_FILE = "./rr_scripts/record-trace"
t = gdb.lookup_type('long').pointer()

# class DebugPrintingBreakpoint(gdb.Breakpoint):
#     count = 1
#     def stop(self):
#         # with open(TRACE_FILE, 'a') as f:
#             # pid = gdb.parse_and_eval("$lx_current().pid")
#             # rseq = gdb.parse_and_eval("$lx_current().rseq")
#             # content = "pid {} rseq {}\n".format(pid, rseq)
#             # f.write(content)
#         self.count += 1
#         print(self.count)
#         return False

try:
    os.remove(TRACE_FILE)
except Exception as e:
    print("Failed to remove: {}".format(str(e)))
else:
     print("Remvoed log file")
# gdb.execute("set logging file ./rr_scripts/record-trace")
# gdb.execute("set logging on")

with open(TRACE_FILE, 'a') as f:
    while True:
        gdb.execute("stepi")
        pc = gdb.parse_and_eval("$pc").cast(t)
        f.write("{}\n".format(pc))
        if pc == 0xffffffff81439d94:
            break

gdb.execute("continue")
