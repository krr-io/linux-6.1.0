#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/sched.h> // For current and scheduling functions
#include <linux/kernel.h> // For printk
#include <linux/smp.h>
#include <linux/slab.h>

#define MAX_CPU_NUM 8

struct rr_lock {
    struct list_head queue; // Queue of waiters
    spinlock_t lock;        // Spinlock for protecting the structure
    int owner;              // CPU ID of the owner, -1 if no owner
};

struct rr_lock_waiter {
    struct list_head list;
    int cpu_id; // Represents a CPU ID
    bool woken_up;
};

static struct rr_lock_waiter *cpu_waiters[MAX_CPU_NUM];

static struct rr_lock *exec_lock = NULL;


static void rr_lock_init(struct rr_lock *lock) {
    struct rr_lock_waiter *waiter;

    INIT_LIST_HEAD(&lock->queue);
    spin_lock_init(&lock->lock);
    lock->owner = -1; // Initialize to -1 indicating no owner

    for (int i = 0; i < num_online_cpus(); i++) {
        waiter = kmalloc(sizeof(struct rr_lock_waiter), GFP_KERNEL);
        if (!waiter) {
            // Handle allocation failure
        }

        waiter->cpu_id = i;

        cpu_waiters[i] = waiter;
    }
}

static void rr_lock(struct rr_lock *lock) {
    unsigned long flags;
    int cpu_id;
    struct rr_lock_waiter *waiter;
    struct rr_lock_waiter *first_waiter;

    preempt_disable();
    spin_lock_irqsave(&lock->lock, flags);

    cpu_id = smp_processor_id();

    if (lock->owner == cpu_id)
        goto out;

    // Now owner now
    if (lock->owner == -1) {
        lock->owner = cpu_id;
        goto out;
    }

    waiter = cpu_waiters[cpu_id];

    list_add_tail(&waiter->list, &exec_lock->queue);

    while (lock->owner != cpu_id) {
        spin_unlock_irqrestore(&lock->lock, flags);

        cpu_relax();

        spin_lock_irqsave(&lock->lock, flags);
    }

    first_waiter = list_first_entry(&exec_lock->queue, struct rr_lock_waiter, list);

    // I must be the first waiter once reaching here
    BUG_ON(first_waiter->cpu_id != cpu_id);
    list_del(&first_waiter->list); // Remove the head of the queue

out:
    preempt_enable();
    spin_unlock_irqrestore(&lock->lock, flags);
}

static void rr_unlock(struct rr_lock *lock) {
    unsigned long flags;
    int cpu_id;
    struct rr_lock_waiter *first_waiter;

    preempt_disable();
    spin_lock_irqsave(&lock->lock, flags);

    cpu_id = smp_processor_id();

    if (lock->owner != cpu_id)
        goto out;

    if (list_empty(&exec_lock->queue)) {
        lock->owner = -1;
    } else {
        first_waiter = list_first_entry(&exec_lock->queue, struct rr_lock_waiter, list);
        lock->owner = first_waiter->cpu_id;
    }

out:
    preempt_enable();
    spin_unlock_irqrestore(&lock->lock, flags);
}

void init_smp_exec_lock(void)
{
    exec_lock = (struct rr_lock *)kmalloc(sizeof(struct rr_lock), GFP_KERNEL);
    rr_lock_init(exec_lock);
    printk(KERN_INFO "Initialized SMP exec lock");
}

void rr_acquire_smp_exec(void)
{
    if (exec_lock == NULL)
        return;

    rr_lock(exec_lock);
}

void rr_release_smp_exec(void)
{
    if (exec_lock == NULL)
        return;

    rr_unlock(exec_lock);
}
