/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_KERNEL_RR_H
#define _ASM_X86_KERNEL_RR_H
#include <linux/types.h>
#include <linux/kvm.h>

#define EVENT_TYPE_INTERRUPT 0
#define EVENT_TYPE_EXCEPTION 1
#define EVENT_TYPE_SYSCALL   2
#define EVENT_TYPE_CFU       4
#define EVENT_TYPE_RANDOM    5
#define EVENT_TYPE_GFU       8
#define EVENT_TYPE_STRNLEN   9
#define EVENT_TYPE_RDSEED    10
#define EVENT_TYPE_RELEASE   11

#define CFU_BUFFER_SIZE     4096

#define CTX_SYSCALL 0
#define CTX_INTR 1
#define CTX_SWITCH 2
#define CTX_IDLE 3
#define CTX_LOCKWAIT 4
#define CTX_EXCP    5


typedef struct {
    int id;
    unsigned long value;
    unsigned long inst_cnt;
    unsigned long rip;
} rr_io_input;

typedef struct {
    int id;
    int vector;
    unsigned long ecx;
    int from;
    unsigned long spin_count;
    unsigned long inst_cnt;
    unsigned long rip;
} rr_interrupt;

typedef struct {
    int id;
    unsigned long val;
} rr_gfu;

typedef struct {
    int id;
    unsigned long src_addr;
    unsigned long dest_addr;
    unsigned long len;
    unsigned long rdx;
    __u8 data[CFU_BUFFER_SIZE];
} rr_cfu;

typedef struct {
    int id;
    int exception_index;
    int error_code;
    unsigned long cr2;
    struct kvm_regs regs;
    unsigned long spin_count;
} rr_exception;

typedef struct {
    int id;
    struct kvm_regs regs;
    unsigned long kernel_gsbase, msr_gsbase, cr3;
    unsigned long spin_count;
} rr_syscall;

typedef struct {
    int id;
    unsigned long buf;
    unsigned long len;
    __u8 data[1024];
} rr_random;

typedef struct rr_event_log_guest_t {
    int type;
    int id;
    union {
        rr_interrupt interrupt;
        rr_exception exception;
        rr_syscall  syscall;
        rr_io_input io_input;
        rr_cfu cfu;
        rr_random rand;
        rr_gfu gfu;
    } event;
    unsigned long inst_cnt;
    unsigned long rip;
} rr_event_log_guest;


typedef struct rr_event_guest_queue_header_t {
    unsigned int current_pos;
    unsigned int total_pos;
    unsigned int header_size;
    unsigned int entry_size;
    unsigned int rr_enabled;
    unsigned long current_byte;
    unsigned long total_size;
} rr_event_guest_queue_header;

typedef struct rr_event_entry_header_t {
    int type;
} rr_event_entry_header;

void rr_record_rdseed(unsigned long val);
void *rr_alloc_new_event_entry(unsigned long size, int type);
bool rr_queue_inited(void);
int rr_enabled(void);
void *rr_record_cfu(const void __user *from, void *to, long unsigned int n);
void rr_record_gfu(unsigned long val);
void rr_record_random(void *buf, int len);
void rr_record_strnlen_user(unsigned long val);
void rr_record_strncpy_user(const void __user *from, void *to, long unsigned int n);
void rr_record_release(int cpu_id);


void init_smp_exec_lock(void);
long rr_acquire_smp_exec(int ctx, int disable_irq);
void rr_release_smp_exec(int ctx);
long rr_do_acquire_smp_exec(int disable_irq, int cpu_id, int ctx);
void rr_handle_irqentry(void);
// bool rr_is_switch_to_user(struct task_struct *task, bool before);
void rr_bug(int expected, int cur);
void rr_set_lock_owner(int owner);


#endif /* _ASM_X86_KERNEL_RR_H */
