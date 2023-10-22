#include <asm/kernel_rr.h>
#include <linux/ptrace.h>

__visible noinstr void rr_record_syscall(struct pt_regs *regs)
{
    return;
}

void rr_record_exception(struct pt_regs *regs, int error_code)
{
    return;
}

void rr_record_cfu(unsigned long from, unsigned long to, int n)
{
    return;
}
