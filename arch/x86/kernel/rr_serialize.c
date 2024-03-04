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


static arch_spinlock_t exec_lock = __ARCH_SPIN_LOCK_UNLOCKED;
static int initialized = 0;
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

void init_smp_exec_lock(void)
{
    printk(KERN_INFO "Initialized SMP exec lock");
    // smp_wmb();
    current_owner = -1;
    initialized = 1;
}

void rr_acquire_smp_exec(int ctx)
{
    int cpu_id;
    unsigned long flags;
    // unsigned long long counter;
    // int cur;

    if (!initialized)
        return;

    preempt_disable();
    cpu_id = smp_processor_id();
    // cur = current_owner;

    // printk(KERN_INFO "%d acquiring, owner %d", cpu_id, cur);
    if (current_owner == cpu_id){
        goto out;
    }

    // During spining the exec lock, disable the interrupt,
    // because if we don't do it, there could be an interrupt
    // while spinning, and the interrupt entry will repeatitively
    // spin on this lock again.
    local_irq_save(flags);

    // wrmsrl(MSR_CORE_PERF_GLOBAL_CTRL, 0);
    //if (!arch_spin_trylock(&exec_lock)){
    arch_spin_lock(&exec_lock);
    // counter = read_pmc(0x40000001);
    //}

    // read_pmc(4);
    // wrmsrl(MSR_CORE_PERF_GLOBAL_CTRL, 0xc4);

    current_owner = cpu_id;

    local_irq_restore(flags);

out:
    preempt_enable();
}

__maybe_unused void rr_bug(int expected, int cur) {
    printk(KERN_ERR "expected %d actual owner %d", expected, cur);
};

void rr_switch(unsigned long next_rip) {
     printk(KERN_INFO "switch rip 0x%lx", next_rip);
}

void rr_release_smp_exec(int ctx)
{
    // int cpu_id;
    // int cur;
    unsigned long flags;

    if (!initialized)
        return;

    local_irq_save(flags);

    current_owner = -1;

    arch_spin_unlock(&exec_lock);
    local_irq_restore(flags);
}

// bool rr_is_switch_to_user(struct task_struct *task, bool before)
// {
//     unsigned long rip = KSTK_EIP(task);

//     if (user_mode(task_pt_regs(task))) {
//         // rr_switch(rip);
//         if (before)
//             printk(KERN_INFO "before switch rip 0x%lx", rip);
//         else
//             printk(KERN_INFO "after switch rip 0x%lx", rip);

//         return true;
//     }

//     return false;
// }
