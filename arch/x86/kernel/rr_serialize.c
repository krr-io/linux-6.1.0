#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/kernel.h> // For printk
#include <linux/smp.h>
#include <linux/slab.h>

#include <asm/processor.h>
#include <linux/sched/task_stack.h>


static arch_spinlock_t exec_lock = __ARCH_SPIN_LOCK_UNLOCKED;
static int initialized = 0;
volatile int current_owner;

void init_smp_exec_lock(void)
{
    printk(KERN_INFO "Initialized SMP exec lock");
    // smp_wmb();
    current_owner = -1;
    initialized = 1;
}

void rr_acquire_smp_exec(void)
{
    int cpu_id;
    unsigned long flags;

    if (!initialized)
        return;

    preempt_disable();
    cpu_id = smp_processor_id();

    if (current_owner == cpu_id){
        goto out;
    }

    // During spining the exec lock, disable the interrupt,
    // because if we don't do it, there could be an interrupt
    // while spinning, and the interrupt entry will repeatitively
    // spin on this lock again.
    local_irq_save(flags);

    arch_spin_lock(&exec_lock);

    current_owner = cpu_id;

    local_irq_restore(flags);

out:
    preempt_enable();
}

__maybe_unused void rr_bug(int expected, int cur) {
    printk(KERN_ERR "expected %d actual owner %d", expected, cur);
};

void rr_release_smp_exec(void)
{
    if (!initialized)
        return;

    current_owner = -1;

    arch_spin_unlock(&exec_lock);
}

bool rr_is_switch_to_user(struct task_struct *task)
{
    unsigned long rip = KSTK_EIP(task);

    if (rip != 0 && rip <= 0x00007fffffffffff) {
        return true;
    }

    return false;
}
