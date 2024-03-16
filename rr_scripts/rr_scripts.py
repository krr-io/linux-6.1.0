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
        with open(TRACE_FILE, 'a+') as f:
            thread = gdb.execute("thread", to_string=True)
            bt = gdb.execute("bt", to_string=True)
            f.write("{}{}\n\n".format(thread, bt))
        return False

try:
    os.remove(TRACE_FILE)
except Exception as e:
    print("Failed to remove: {}".format(str(e)))


debug1 = DebugPrintingBreakpoint("*0xffffffff816ca18b")
debug2 = DebugPrintingBreakpoint("*0xffffffff81034f0b")
# debug3 = DebugPrintingBreakpoint("*0xffffffff810351cf") 0xffffffff81891e70
debug4 = DebugPrintingBreakpoint("irqentry_exit")
debug5 = DebugPrintingBreakpoint("irqentry_enter")
debug6 = DebugPrintingBreakpoint("ct_irq_exit")
debug7 = DebugPrintingBreakpoint("*0xffffffff81a00ecb")
debug8 = DebugPrintingBreakpoint("*0xffffffff81891e70")


gdb.execute("continue")
