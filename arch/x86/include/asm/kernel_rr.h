#ifndef _ASM_X86_KERNEL_RR_H
#define _ASM_X86_KERNEL_RR_H

void init_smp_exec_lock(void);
void rr_acquire_smp_exec(void);
void rr_release_smp_exec(void);

#endif	/* _ASM_X86_KERNEL_RR_H */