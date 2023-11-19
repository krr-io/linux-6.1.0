import sys
import gdb
import os

TRACE_FILE = "./rr_scripts/replay-trace"
# TRACE_FILE = "./rr_scripts/record-trace"

regs = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp"]

single_step = False

t = gdb.lookup_type('long').pointer()

class DebugPrintingBreakpoint(gdb.Breakpoint):
    def stop(self):
        with open(TRACE_FILE, 'a') as f:
            f.write("Start")

            while True:
                gdb.execute("stepi")
                # content = gdb.execute("x/i $pc", to_string=True)
                pc = gdb.parse_and_eval("$pc").cast(t)
                f.write(str(pc) + "\n")
                if pc == 0xffffffff8148d8db:
                    break
                # child_tid = gdb.parse_and_eval("$lx_current().set_child_tid")
                # content = "pid={} ptr={}".format(pid, child_tid)
                # f.write(content + "\n")

        return False

try:
    os.remove(TRACE_FILE)
except Exception as e:
    print("Failed to remove: {}".format(str(e)))


debug = DebugPrintingBreakpoint("*0xffffffff8148d8fd")
# debug = DebugPrintingBreakpoint("*0xffffffff8148d8db")



gdb.execute("continue")
