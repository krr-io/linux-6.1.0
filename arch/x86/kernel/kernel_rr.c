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
    event->event.syscall.regs.rax = regs->ax;
    event->event.syscall.regs.rbx = regs->bx;

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

    return;
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
