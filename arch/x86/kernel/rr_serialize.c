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

// static struct rr_lock_waiter *cpu_waiters[MAX_CPU_NUM];

static int cpu_wait_signal[MAX_CPU_NUM];
static atomic_t current_spot;

static struct rr_lock *exec_lock = NULL;


static void rr_lock_init(struct rr_lock *lock) {
    int num_cpus = num_online_cpus();

    INIT_LIST_HEAD(&lock->queue);
    spin_lock_init(&lock->lock);
    lock->owner = -1; // Initialize to -1 indicating no owner

    for (int i = 0; i < num_cpus; i++) {
        cpu_wait_signal[i] = 0;
        atomic_set(&current_spot, 0);
    }

    cpu_wait_signal[num_cpus] = -2;
}

static void rr_lock(struct rr_lock *lock) {
    int cpu_id;
    int spot;

    preempt_disable();

    cpu_id = smp_processor_id();

    if (atomic_read(&current_spot) == cpu_id)
        goto out;

    cpu_wait_signal[cpu_id] = 1;

    while (1) {
        spot = atomic_read(&current_spot);
        if (spot == cpu_id)
            break;
        if (spot == -1) {
            if (atomic_cmpxchg(&current_spot, -1, cpu_id) == -1)
                break;
        }

        cpu_relax();
    }

    cpu_wait_signal[cpu_id] = 0;

out:
    preempt_enable();
}

static void rr_unlock(struct rr_lock *lock) {
    // int cpu_id;
    int i;

    for (i = 0; i < MAX_CPU_NUM; i++) {
        if (cpu_wait_signal[i] == -2) {
            // No one is waiting
            atomic_set(&current_spot, -1);
            break;
        }

        if (cpu_wait_signal[i]) {
            // CPU i is waiting
            atomic_set(&current_spot, i);
        }
    }
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
