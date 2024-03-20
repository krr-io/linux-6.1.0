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
        return False

# try:
#     os.remove(TRACE_FILE)
# except Exception as e:
#     print("Failed to remove: {}".format(str(e)))


debug1 = DebugPrintingBreakpoint("*0xffffffff81a00000")
debug2 = DebugPrintingBreakpoint("*0xffffffff81888560")
# debug3 = DebugPrintingBreakpoint("*0xffffffff81888600")
# debug4 = DebugPrintingBreakpoint("*0xffffffff81888690")
# debug5 = DebugPrintingBreakpoint("*0xffffffff81034f7f")
# debug6 = DebugPrintingBreakpoint("*0xffffffff81034f50")
# debug7 = DebugPrintingBreakpoint("*0xffffffff81a00b40")
# debug8 = DebugPrintingBreakpoint("*0xffffffff81887e90")




gdb.execute("continue")
