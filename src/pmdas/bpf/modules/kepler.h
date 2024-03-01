/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __KEPLER_H
#define __KEPLER_H

#define TASK_COMM_LEN 16
#define IRQ_MAX_LEN 10
#define BASE_EVENT_SIZE (size_t)(&((struct event*)0)->args)
#define EVENT_SIZE(e) (BASE_EVENT_SIZE + e->args_size)

typedef __u64 u64;
typedef __u16 u16;

struct event {
	u64 cgroup_id;
	u64 pid;
	u64 process_run_time;
	u64 cpu_cycles;
	u64 cpu_instr;
	u64 cache_miss;
	u64 page_cache_hit;
	u16 vec_nr[IRQ_MAX_LEN];
	char comm[TASK_COMM_LEN];
};

#endif /* __KEPLER_H */
