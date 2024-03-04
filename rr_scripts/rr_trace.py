import os
import sys
import gdb
import time

TRACE_FILE = "./rr_scripts/replay-trace"
# TRACE_FILE = "./rr_scripts/record-trace"
t = gdb.lookup_type('long').pointer()

class DebugPrintingBreakpoint(gdb.Breakpoint):
    count = 1
    def stop(self):
        with open(TRACE_FILE, 'a') as f:
            bt = gdb.execute("bt", to_string=True)
            content = "bt {}\n\n".format(bt)
            f.write(content)

        return False

try:
    os.remove(TRACE_FILE)
except Exception as e:
    print("Failed to remove: {}".format(str(e)))
else:
     print("Remvoed log file")


DebugPrintingBreakpoint("*0xffffffff8149c2c4")
DebugPrintingBreakpoint("*0xffffffff818a14ce")

gdb.execute("continue")
