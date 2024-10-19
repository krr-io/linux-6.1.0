#include <asm/pgtable_64_types.h>
#include <asm/kernel_rr.h>
#include <asm/traps.h>
#include <linux/ptrace.h>
#include <asm/msr.h>


static void rr_record_syscall(struct pt_regs *regs, int cpu_id, unsigned long spin_count)
{
    unsigned long flags;
    void *event = NULL;
    rr_syscall *syscall = NULL;

    if (!rr_queue_inited()) {
        return;
    }

    if (!rr_enabled()) {
        return;
    }

    local_irq_save(flags);

    event = rr_alloc_new_event_entry(sizeof(rr_syscall), EVENT_TYPE_SYSCALL);
    if (event == NULL) {
	    panic("Failed to allocate entry");
        //goto finish;
    }

    syscall = (rr_syscall *)event;

    syscall->id = cpu_id;
    syscall->spin_count = 0;
    syscall->regs.rax = regs->orig_ax;
    syscall->regs.rbx = regs->bx;
    syscall->regs.rcx = regs->cx;
    syscall->regs.rdx = regs->dx;
    syscall->regs.rsi = regs->si;
    syscall->regs.rdi = regs->di;
    syscall->regs.rsp = regs->sp;
    syscall->regs.rbp = regs->bp;
    syscall->regs.r8 = regs->r8;
    syscall->regs.r9 = regs->r9;
    syscall->regs.r10 = regs->r10;
    syscall->regs.r11 = regs->r11;
    syscall->regs.r12 = regs->r12;
    syscall->regs.r13 = regs->r13;
    syscall->regs.r14 = regs->r14;
    syscall->regs.r15 = regs->r15;
    syscall->cr3 = __read_cr3(); 
    syscall->spin_count = spin_count;

    local_irq_restore(flags);
}

static void rr_record_exception(struct pt_regs *regs,
                                int vector, int error_code,
                                unsigned long cr2, int cpu_id,
                                unsigned long spin_count)
{

    unsigned long flags;
    void *event;
    rr_exception *exception = NULL;

    if (!rr_queue_inited()) {
        return;
    }

    if (!rr_enabled()) {
        return;
    }

    local_irq_save(flags);

    event = rr_alloc_new_event_entry(sizeof(rr_exception), EVENT_TYPE_EXCEPTION);
    if (event == NULL) {
	    panic("Failed to allocate entry");
        //goto finish;
    }

    exception = (rr_exception *)event;

    exception->id = cpu_id;
    exception->exception_index = vector;
    exception->cr2 = cr2;
    exception->error_code = error_code;
    exception->regs.rax = regs->ax;
    exception->regs.rbx = regs->bx;
    exception->regs.rcx = regs->cx;
    exception->regs.rdx = regs->dx;
    exception->regs.rsi = regs->si;
    exception->regs.rdi = regs->di;
    exception->regs.rsp = regs->sp;
    exception->regs.rbp = regs->bp;
    exception->regs.r8 = regs->r8;
    exception->regs.r9 = regs->r9;
    exception->regs.r10 = regs->r10;
    exception->regs.r11 = regs->r11;
    exception->regs.r12 = regs->r12;
    exception->regs.r13 = regs->r13;
    exception->regs.r14 = regs->r14;
    exception->regs.r15 = regs->r15;
    exception->regs.rflags = regs->flags;
    exception->regs.rip = regs->ip;

    exception->spin_count = spin_count;

    local_irq_restore(flags);
}


void rr_handle_syscall(struct pt_regs *regs)
{
    int cpu_id;
    unsigned long flags;
    long spin_count;

    local_irq_save(flags);

    preempt_disable();
    cpu_id = smp_processor_id();

    spin_count = rr_do_acquire_smp_exec(0, cpu_id, CTX_SYSCALL);

    if (spin_count < 0)
        spin_count = 0;

    rr_record_syscall(regs, cpu_id, spin_count);

    preempt_enable();
    local_irq_restore(flags);
}


void rr_handle_exception(struct pt_regs *regs, int vector, int error_code, unsigned long cr2)
{
    int cpu_id;
    unsigned long flags;
    long spin_count;

    local_irq_save(flags);

    preempt_disable();
    cpu_id = smp_processor_id();

    spin_count = rr_do_acquire_smp_exec(0, cpu_id, CTX_EXCP);

    if (spin_count < 0)
        spin_count = 0;

    rr_record_exception(regs, vector, error_code, cr2, cpu_id, spin_count);

    preempt_enable();
    local_irq_restore(flags);
}


static void rr_record_irqentry(int cpu_id, unsigned long spin_count)
{
    rr_event_log_guest *event;
    rr_interrupt *interrupt;

    if (!rr_queue_inited()) {
        return;
    }

    if (!rr_enabled()) {
        return;
    }

    event = rr_alloc_new_event_entry(sizeof(rr_interrupt), EVENT_TYPE_INTERRUPT);
    if (event == NULL) {
        panic("Failed to allocate");
    }

    interrupt = (rr_interrupt *)event;

    interrupt->id = cpu_id;
    interrupt->from = 3;
    interrupt->spin_count = spin_count;
}


void rr_handle_irqentry(void)
{
    int cpu_id;
    unsigned long flags;
    long spin_count;

    local_irq_save(flags);

    preempt_disable();
    cpu_id = smp_processor_id();

    spin_count = rr_do_acquire_smp_exec(0, cpu_id, CTX_INTR);
    if (spin_count < 0) {
        goto finish;
    }

    rr_record_irqentry(cpu_id, spin_count);

finish:
    preempt_enable();
    local_irq_restore(flags);
}


void *rr_record_cfu(const void __user *from, void *to, long unsigned int n)
{
    unsigned long flags;
    long ret;
    void *event;
    rr_cfu *cfu;
    void *addr;

    if (!rr_queue_inited()) {
        return NULL;
    }

    if (!rr_enabled()) {
        return NULL;
    }

    local_irq_save(flags);

    /* We reserve one more byte here for the buffer so in the replay, the extra byte is filled with
       zero, same as rr_record_strncpy_user */
    rr_begin_cfu(from, to, n);

    event = rr_alloc_new_event_entry(sizeof(rr_cfu) + (n + 1) * sizeof(unsigned char), EVENT_TYPE_CFU);
    if (event == NULL) {
        panic("Failed to allocate");
        goto finish;
    }

    cfu = (rr_cfu *)event;

    cfu->id = 0;
    cfu->src_addr = (unsigned long)from;
    cfu->dest_addr = (unsigned long)to;
    cfu->len = n + 1;
    cfu->data = NULL;

    addr = (void *)((unsigned long)cfu + sizeof(rr_cfu));
    ret = raw_copy_from_user(addr, from, n);

finish:
    local_irq_restore(flags);

    return addr;
}


void *rr_gfu_begin(unsigned long ptr, int size, int align)
{
    unsigned long flags;
    void *event;
    rr_gfu *gfu;

    if (!rr_queue_inited()) {
        return NULL;
    }

    if (!rr_enabled()) {
        return NULL;
    }

    local_irq_save(flags);

    event = rr_alloc_new_event_entry(sizeof(rr_gfu), EVENT_TYPE_GFU);
    if (event == NULL) {
        panic("Failed to allocate entry");
    }

    gfu = (rr_gfu *)event;

    gfu->id = 0;
    gfu->ptr = ptr;
    gfu->size = size;

    local_irq_restore(flags);

    return event;
}

void *rr_cfu_begin(const void __user *from, void *to, long unsigned int n)
{
    unsigned long flags;
    void *event;
    rr_cfu *cfu = NULL;
    unsigned long len;
    void *addr;

    if (!rr_queue_inited()) {
        return NULL;
    }

    if (!rr_enabled()) {
        return NULL;
    }

    local_irq_save(flags);

    len = sizeof(rr_cfu) + (n + 1) * sizeof(unsigned char);
    event = rr_alloc_new_event_entry(len, EVENT_TYPE_CFU);
    if (event == NULL) {
        panic("Failed to allocate entry");
    }

    cfu = (rr_cfu *)event;

    cfu->id = 0;
    cfu->src_addr = (unsigned long)from;
    cfu->dest_addr = (unsigned long)to;
    cfu->len = n + 1;
    cfu->data = NULL;
    addr = (void *)((unsigned long)cfu + sizeof(rr_cfu));

    local_irq_restore(flags);

    return addr;
}

void rr_cfu_end(void *addr, void *to, long unsigned int n)
{
    unsigned long flags;

    if (!rr_queue_inited()) {
        return;
    }

    if (!rr_enabled()) {
        return;
    }

    if (!addr) {
        return;
    }

    local_irq_save(flags);
    memcpy(addr, to, n);
    local_irq_restore(flags);
}

void rr_record_gfu_end(unsigned long val, void *event)
{
    rr_gfu *gfu;

    if (!event)
        return;

    gfu = (rr_gfu *)event;
    gfu->val = val;
}

void rr_record_gfu(unsigned long val, unsigned long ptr)
{
    unsigned long flags;
    void *event;
    rr_gfu *gfu;

    if (!rr_queue_inited()) {
        return;
    }

    if (!rr_enabled()) {
        return;
    }

    local_irq_save(flags);

    event = rr_alloc_new_event_entry(sizeof(rr_gfu), EVENT_TYPE_GFU);
    if (event == NULL) {
        panic("Failed to allocate");
        goto finish;
    }

    gfu = (rr_gfu *)event;

    gfu->id = 0;
    gfu->val = val;
    gfu->ptr = ptr;

finish:
    local_irq_restore(flags);
}


void rr_record_strnlen_user(unsigned long val, unsigned long src)
{
    unsigned long flags;
    void *event;
    rr_cfu *cfu = NULL;

    if (!rr_queue_inited()) {
        return;
    }

    if (!rr_enabled()) {
        return;
    }

    local_irq_save(flags);

    event = rr_alloc_new_event_entry(sizeof(rr_cfu), EVENT_TYPE_STRNLEN);
    if (event == NULL) {
        panic("Failed to allocate");
        goto finish;
    }
    cfu = (rr_cfu *)event;

    cfu->id = 0;
    cfu->len = val;
    cfu->src_addr = src;

finish:
    local_irq_restore(flags);
}

void rr_record_strncpy_user(const void __user *from, void *to, long unsigned int n)
{
    unsigned long flags;
    void *event;
    rr_cfu *cfu = NULL;
    unsigned long len;
    void *addr;

    if (!rr_queue_inited()) {
        return;
    }

    if (!rr_enabled()) {
        return;
    }

    local_irq_save(flags);

    len = sizeof(rr_cfu) + (n + 1) * sizeof(unsigned char);
    event = rr_alloc_new_event_entry(len, EVENT_TYPE_CFU);
    if (event == NULL) {
        panic("Failed to allocate");
        goto finish;
    }

    cfu = (rr_cfu *)event;

    cfu->id = 0;
    cfu->src_addr = (unsigned long)from;
    cfu->dest_addr = (unsigned long)to;
    cfu->len = n + 1;
    cfu->data = NULL;
    addr = (void *)((unsigned long)cfu + sizeof(rr_cfu));

    memcpy(addr, to, n);

finish:
    local_irq_restore(flags);
}

void rr_record_rdseed(unsigned long val)
{
    unsigned long flags;
    void *event;
    rr_gfu *gfu = NULL;

    if (!rr_queue_inited()) {
        return;
    }

    if (!rr_enabled()) {
        return;
    }

    local_irq_save(flags);

    event = rr_alloc_new_event_entry(sizeof(rr_gfu), EVENT_TYPE_RDSEED);
    if (event == NULL) {
        panic("Failed to allocate");
        goto finish;
    }

    gfu = (rr_gfu *)event;

    gfu->id = 0;
    gfu->val = val;

finish:
    local_irq_restore(flags);
}

void rr_record_release(int cpu_id)
{
    rr_event_log_guest *event;

    if (!rr_queue_inited()) {
        return;
    }

    if (!rr_enabled()) {
        return;
    }

    event = rr_alloc_new_event_entry(sizeof(rr_event_log_guest), EVENT_TYPE_RELEASE);
    if (event == NULL) {
        panic("Failed to allocate");
        return;
    }

    event->type = EVENT_TYPE_RELEASE;
    event->id = cpu_id;
}

void rr_begin_cfu(const void __user *from, void *to, long unsigned int n)
{ return; }

unsigned long rr_record_pte_clear(pte_t *xp)
{
    unsigned long flags;
    void *event;
    rr_gfu *gfu = NULL;

    pteval_t p = xchg(&xp->pte, 0);

    if (!rr_queue_inited()) {
        return p;
    }

    if (!rr_enabled()) {
        return p;
    }

    if (!(p & _PAGE_USER)) {
        return p;
    }

    local_irq_save(flags);

    event = rr_alloc_new_event_entry(sizeof(rr_gfu), EVENT_TYPE_PTE);
    if (event == NULL) {
        panic("Failed to allocate entry");
    }

    gfu = (rr_gfu *)event;

    gfu->id = 0;
    gfu->ptr = (unsigned long)xp;
    gfu->val = p;

    local_irq_restore(flags);

    return p;
}

pte_t rr_read_pte(pte_t *pte)
{
    pte_t rr_pte;
    unsigned long flags;
    void *event;
    rr_gfu *gfu;

    rr_pte = *pte;

    if (!rr_queue_inited()) {
        return rr_pte;
    }

    if (!rr_enabled()) {
        return rr_pte;
    }

    if (!(rr_pte.pte & _PAGE_USER)) {
        return rr_pte;
    }

    local_irq_save(flags);

    event = rr_alloc_new_event_entry(sizeof(rr_gfu), EVENT_TYPE_PTE);
    if (event == NULL) {
        panic("Failed to allocate entry");
    }

    gfu = (rr_gfu *)event;

    gfu->id = 0;
    gfu->ptr = (unsigned long)pte;
    gfu->val = rr_pte.pte;

    local_irq_restore(flags);

    return rr_pte;
}

pte_t rr_read_pte_once(pte_t *pte)
{
    pte_t rr_pte;
    unsigned long flags;
    void *event;
    rr_gfu *gfu;

    rr_pte = READ_ONCE(*pte);

    if (!rr_queue_inited()) {
        return rr_pte;
    }

    if (!rr_enabled()) {
        return rr_pte;
    }

    if (!(rr_pte.pte & _PAGE_USER)) {
        return rr_pte;
    }

    local_irq_save(flags);

    event = rr_alloc_new_event_entry(sizeof(rr_gfu), EVENT_TYPE_PTE);
    if (event == NULL) {
        panic("Failed to allocate entry");
    }

    gfu = (rr_gfu *)event;

    gfu->id = 0;
    gfu->ptr = (unsigned long)pte;
    gfu->val = rr_pte.pte;

    local_irq_restore(flags);

    return rr_pte;
}

unsigned long *rr_rdtsc_begin(void)
{
    unsigned long flags;
    void *event;
    rr_io_input *input = NULL;

    if (!rr_queue_inited()) {
        return NULL;
    }

    if (!rr_enabled()) {
        return NULL;
    }

    local_irq_save(flags);

    event = rr_alloc_new_event_entry(sizeof(rr_io_input), EVENT_TYPE_RDTSC);
    if (event == NULL) {
        panic("Failed to allocate entry");
    }

    input = (rr_io_input *)event;

    input->id = 0;

    local_irq_restore(flags);

    return &(input->value);
}
EXPORT_SYMBOL_GPL(rr_rdtsc_begin);
