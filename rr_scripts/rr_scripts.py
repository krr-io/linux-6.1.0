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
            v1 = gdb.parse_and_eval("((struct ata_host *)dev_instance)->ports[0]->hsm_task_state")
            v2= gdb.parse_and_eval("((struct ata_host *)dev_instance)->ports[0]->link.active_tag")

            b1 = gdb.parse_and_eval("((struct ata_host *)dev_instance)->ports[1]->hsm_task_state")
            b2= gdb.parse_and_eval("((struct ata_host *)dev_instance)->ports[1]->link.active_tag")
            f.write("0: {}, {} 1: {}, {}\n".format(v1, v2, b1, b2))
        return False

try:
    os.remove(TRACE_FILE)
except Exception as e:
    print("Failed to remove: {}".format(str(e)))


debug1 = DebugPrintingBreakpoint("__ata_sff_interrupt")
# debug2 = DebugPrintingBreakpoint("drivers/ata/libata-sff.c:1597")

gdb.execute("continue")
