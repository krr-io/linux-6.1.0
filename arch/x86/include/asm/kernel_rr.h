/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_KERNEL_RR_H
#define _ASM_X86_KERNEL_RR_H
#include <linux/types.h>
#include <linux/kvm.h>

#define EVENT_TYPE_EXCEPTION 1
#define EVENT_TYPE_SYSCALL   2
#define EVENT_TYPE_CFU       4
#define EVENT_TYPE_RANDOM    5
#define EVENT_TYPE_GFU       8

#define CFU_BUFFER_SIZE     4096

// typedef struct {
//     unsigned long value;
// } rr_io_input;

typedef struct {
    unsigned long src_addr;
    unsigned long dest_addr;
    unsigned long len;
    unsigned long rdx;
    __u8 data[CFU_BUFFER_SIZE];
} rr_cfu;

// typedef struct {
//     lapic_log lapic;
// } rr_interrupt;

typedef struct {
    int exception_index;
    int error_code;
    unsigned long cr2;
    struct kvm_regs regs;
} rr_exception;

typedef struct {
    struct kvm_regs regs;
    unsigned long kernel_gsbase, msr_gsbase, cr3;
} rr_syscall;

typedef struct {
    unsigned long buf;
    unsigned long len;
    __u8 data[1024];
} rr_random;

typedef struct rr_event_log_guest_t {
    int type;
    int id;
    union {
        rr_exception exception;
        rr_syscall  syscall;
        rr_cfu cfu;
        rr_random rand;
    } event;
} rr_event_log_guest;


typedef struct rr_event_guest_queue_header_t {
    unsigned int current_pos;
    unsigned int total_pos;
    unsigned int header_size;
    unsigned int entry_size;
    unsigned int rr_enabled;
} rr_event_guest_queue_header;

rr_event_log_guest *rr_alloc_new_event_entry(void);
bool rr_queue_inited(void);
int rr_enabled(void);
void rr_record_cfu(unsigned long from, void *to, long unsigned int n);
void rr_record_gfu(unsigned long val);

#endif /* _ASM_X86_KERNEL_RR_H */
