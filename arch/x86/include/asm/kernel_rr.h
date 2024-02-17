#ifndef _ASM_X86_KERNEL_RR_H
#define _ASM_X86_KERNEL_RR_H
#include <linux/sched.h>

#define CTX_SYSCALL 0
#define CTX_INTR 1
#define CTX_SWITCH 2
#define CTX_IDLE 3
#define CTX_LOCKWAIT 4

void init_smp_exec_lock(void);
void rr_acquire_smp_exec(int ctx);
void rr_release_smp_exec(int ctx);
bool rr_is_switch_to_user(struct task_struct *task, bool before);
void rr_bug(int expected, int cur);
void rr_switch(unsigned long next_rip);

#endif	/* _ASM_X86_KERNEL_RR_H */