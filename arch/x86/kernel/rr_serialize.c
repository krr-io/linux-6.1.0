#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/kernel.h> // For printk
#include <linux/smp.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/kvm_para.h>

#include <asm/processor.h>
#include <asm/msr-index.h>
#include <linux/sched/task_stack.h>


static int initialized = 0;
volatile unsigned long lock = 0;
volatile int current_owner;

static inline unsigned long long read_pmc(int counter)
{
    unsigned low, high;
    /*
     * The RDPMC instruction reads the counter specified by the counter
     * parameter into the EDX:EAX registers. The counter number needs to
     * be loaded into the ECX register before the instruction is executed.
     */
    __asm__ volatile ("rdpmc" : "=a" (low), "=d" (high) : "c" (counter));
    return ((unsigned long long)high << 32) | low;
}

long rr_do_acquire_smp_exec(int disable_irq, int cpu_id, int ctx)
{
    unsigned long flags;
    unsigned long spin_count = 0;

    if (!initialized)
        return -1;

    if (current_owner == cpu_id){
        return -1;
    }

    // During spining the exec lock, disable the interrupt,
    // because if we don't do it, there could be an interrupt
    // while spinning, and the interrupt entry will repeatitively
    // spin on this lock again.
    if (disable_irq)
        local_irq_save(flags);

    while (test_and_set_bit(0, &lock)) {
        spin_count++;
    }

    current_owner = cpu_id;
    rr_set_lock_owner(cpu_id);

    if (unlikely(ctx == CTX_LOCKWAIT))
        kvm_hypercall0(KVM_INSTRUCTION_SYNC);

    if (disable_irq)
        local_irq_restore(flags);

    return spin_count;
}

void init_smp_exec_lock(void)
{
    printk(KERN_INFO "Initialized SMP exec lock");

    current_owner = -1;
    initialized = 1;
}

long rr_acquire_smp_exec(int ctx, int disable_irq)
{
    int cpu_id;
    unsigned long spin_count;
    // int cur;

    if (!initialized)
        return 0;

    preempt_disable();
    cpu_id = smp_processor_id();

    spin_count = rr_do_acquire_smp_exec(disable_irq, cpu_id, ctx);

    preempt_enable();

    return spin_count;
}

__maybe_unused void rr_bug(int expected, int cur) {
};

void rr_release_smp_exec(int ctx)
{
    unsigned long flags;
    int cpu_id;

    if (!initialized)
        return;

    local_irq_save(flags);

    preempt_disable();
    cpu_id = smp_processor_id();

    // rr_record_release(cpu_id);

    current_owner = -1;
    rr_set_lock_owner(-1);

    clear_bit(0, &lock);

    preempt_enable();
    local_irq_restore(flags);
}
