#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/kernel.h> // For printk
#include <linux/smp.h>
#include <linux/slab.h>


static arch_spinlock_t exec_lock = __ARCH_SPIN_LOCK_UNLOCKED;
static int initialized = 0;
static atomic_t current_owner;

void init_smp_exec_lock(void)
{
    printk(KERN_INFO "Initialized SMP exec lock");
    atomic_set(&current_owner, -1);
    initialized = 1;
}

void rr_acquire_smp_exec(void)
{
    int cpu_id;

    if (!initialized)
        return;


    preempt_disable();
    cpu_id = smp_processor_id();

    if (atomic_read(&current_owner) == cpu_id){
        goto out;
    }

    arch_spin_lock(&exec_lock);

    atomic_set(&current_owner, cpu_id);
    // printk(KERN_INFO "%d acquired lock", cpu_id);
out:
    preempt_enable();
}

static void rr_bug(void){};

void rr_release_smp_exec(void)
{
    int cur_owner;
    int cpu_id;
    if (!initialized)
        return;

    preempt_disable();
    cur_owner = atomic_read(&current_owner);
    cpu_id = smp_processor_id();
    if (cur_owner != cpu_id) {
        // printk(KERN_ERR "expected %d actual owner %d", cpu_id, cur_owner);
        rr_bug();
        preempt_enable();
        return;
    } else {
        // printk(KERN_ERR "%d released lock", cpu_id);

    }
    preempt_enable();

    atomic_set(&current_owner, -1);
    arch_spin_unlock(&exec_lock);
}
