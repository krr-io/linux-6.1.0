#include <asm/kernel_rr.h>
#include <linux/ptrace.h>

__visible noinstr void rr_record_syscall(struct pt_regs *regs)
{
    rr_event_log_guest *event;

    if (!rr_queue_inited()) {
        return;
    }

    if (!rr_enabled()) {
        return;
    }

    event = rr_alloc_new_event_entry();
    if (event == NULL) {
        return;
    }

    event->type = EVENT_TYPE_SYSCALL;
    event->event.syscall.regs.rax = regs->orig_ax;
    event->event.syscall.regs.rbx = regs->bx;
    event->event.syscall.regs.rcx = regs->cx;
    event->event.syscall.regs.rdx = regs->dx;
    event->event.syscall.regs.rsi = regs->si;
    event->event.syscall.regs.rdi = regs->di;
    event->event.syscall.regs.rsp = regs->sp;
    event->event.syscall.regs.rbp = regs->bp;
    event->event.syscall.regs.r8 = regs->r8;
    event->event.syscall.regs.r9 = regs->r9;
    event->event.syscall.regs.r10 = regs->r10;
    event->event.syscall.regs.r11 = regs->r11;
    event->event.syscall.regs.r12 = regs->r12;
    event->event.syscall.regs.r13 = regs->r13;
    event->event.syscall.regs.r14 = regs->r14;
    event->event.syscall.regs.r15 = regs->r15;

    return;
}

void rr_record_exception(struct pt_regs *regs, int error_code, unsigned long cr2)
{
    rr_event_log_guest *event;

    if (!rr_queue_inited()) {
        return;
    }

    if (!rr_enabled()) {
        return;
    }

    event = rr_alloc_new_event_entry();
    if (event == NULL) {
        return;
    }

    event->type = EVENT_TYPE_EXCEPTION;
    event->event.exception.cr2 = cr2;
    event->event.exception.error_code = error_code;

}

void rr_record_random(void *buf, int len)
{
    rr_event_log_guest *event;

    if (!rr_queue_inited()) {
        return;
    }

    if (!rr_enabled()) {
        return;
    }

    event = rr_alloc_new_event_entry();
    if (event == NULL) {
        return;
    }

    event->type = EVENT_TYPE_RANDOM;
    event->event.rand.len = len;
    memcpy(event->event.rand.data, buf, len);
}

void rr_record_cfu(unsigned long from, void *to, long unsigned int n)
{
    rr_event_log_guest *event;

    if (!rr_queue_inited()) {
        return;
    }

    if (!rr_enabled()) {
        return;
    }

    if (n > CFU_BUFFER_SIZE) {
        BUG();
    }

    event = rr_alloc_new_event_entry();
    if (event == NULL) {
        return;
    }

    event->type = EVENT_TYPE_CFU;
    event->event.cfu.src_addr = from;
    event->event.cfu.dest_addr = (unsigned long)to;
    event->event.cfu.len = n;
    memcpy(event->event.cfu.data, to, n);

    return;
}

void rr_record_gfu(unsigned long val)
{
    rr_event_log_guest *event;

    if (!rr_queue_inited()) {
        return;
    }

    if (!rr_enabled()) {
        return;
    }

    event = rr_alloc_new_event_entry();
    if (event == NULL) {
        return;
    }

    event->type = EVENT_TYPE_GFU;
    event->event.cfu.rdx = val;
}
