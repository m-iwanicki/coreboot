#include "thread.h"

#include <console/console.h>
#include <cpu/power/scom.h>
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static struct {
	struct spin_lock_t lock;
	bool exit_requested;

	void *task_arg;
	void (*task_func)(void *arg);
} job_thread;

extern uint8_t sys_reset_thread_int[];
extern uint8_t sys_reset_thread_int_end[];

void wait_second_thread(void)
{
	bool done = false;

	while (!done) {
		spin_lock(&job_thread.lock);
		done = (job_thread.task_func == NULL);
		spin_unlock(&job_thread.lock);
	}
}

void on_second_thread(void (*func)(void *arg), void *arg)
{
	wait_second_thread();

	spin_lock(&job_thread.lock);
	assert(job_thread.task_func == NULL);
	job_thread.task_func = func;
	job_thread.task_arg = arg;
	spin_unlock(&job_thread.lock);
}

static inline void sync_icache(void)
{
	asm volatile("sync; icbi 0,%0; sync; isync" :: "r" (0) : "memory");
}

/*
 * Need to:
 * 1. Start ignoring HRMOR
 * 2. Store current value of HRMOR
 * 3. Set HRMOR to non-zero value
 * 4. Stop ignoring HRMOR
 * 5. Start a new thread
 * 6. Start ignoring HRMOR
 * 7. Restore previous value of HRMOR
 * 8. Stop ignoring HRMOR
 */

void set_hrmor(uint64_t hrmor);
void reset_hrmor(uint64_t mask);

void start_second_thread(void)
{
#if !CONFIG(BOOTBLOCK_IN_SEEPROM)
	uint64_t hrmor = 0xF8000000ULL;
#else
	uint64_t hrmor = 0xF8200000ULL;
#endif

	printk(BIOS_EMERG, "before set_hrmor\n");
	set_hrmor(hrmor);
	printk(BIOS_EMERG, "after set_hrmor\n");

	memcpy((void *)0x100, sys_reset_thread_int,
	       sys_reset_thread_int_end - sys_reset_thread_int);
	sync_icache();

	/*
	 * No Precondition for Sreset; power management is handled by platform
	 * Clear blocking interrupts
	 */
	/*
	 * SW375288: Reads to C_RAS_MODEREG causes SPR corruption.
	 * For now, the code will assume no other bits are set and only
	 * set/clear mr_fence_interrupts
	 */
	write_rscom_for_chiplet(0, EC00_CHIPLET_ID + 1, 0x20010A9D, 0);

	/* Setup & initiate SReset command for the second thread*/
	write_rscom_for_chiplet(0, EC00_CHIPLET_ID + 1, 0x20010A9C, 0x0080000000000000 >> 4);

	printk(BIOS_EMERG, "before reset_hrmor\n");
	reset_hrmor(hrmor);
	printk(BIOS_EMERG, "after reset_hrmor\n");
}

void stop_second_thread(void)
{
	spin_lock(&job_thread.lock);
	job_thread.exit_requested = 1;
	spin_unlock(&job_thread.lock);
}

static void stop_15_thread(void)
{
	/* Set register to indicate we want a 'stop 15' to ocur (state loss) and perform
	 * the STOP */
	asm volatile("mtspr 855, %0; isync; stop" :: "r" (0x00000000003F00FF));
}

void second_thread(void)
{
	bool done = false;
	while (!done) {
		spin_lock(&job_thread.lock);

		if (job_thread.task_func != NULL) {
			job_thread.task_func(job_thread.task_arg);

			job_thread.task_func = NULL;
			job_thread.task_arg = NULL;
		}

		done = job_thread.exit_requested;
		spin_unlock(&job_thread.lock);
	}
	stop_15_thread();
}
