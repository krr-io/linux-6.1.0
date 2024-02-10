#ifndef _ASM_X86_KERNEL_RR_H
#define _ASM_X86_KERNEL_RR_H
#include <linux/sched.h>

void init_smp_exec_lock(void);
void rr_acquire_smp_exec(void);
void rr_release_smp_exec(void);
bool rr_is_switch_to_user(struct task_struct *task);
void rr_bug(int expected, int cur);

#endif	/* _ASM_X86_KERNEL_RR_H */