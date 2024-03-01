/*
 *
 * Copyright (c) 2023 Red Hat.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "module.h"

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <pcp/pmda.h>
#include <sys/queue.h>
#include <pcp/pmwebapi.h>

#include "kepler.skel.h"
#include "kepler.h"

#define PERF_BUFFER_PAGES 64
#define PERF_POLL_TIMEOUT_MS 0

#define INDOM_COUNT 1

static struct env {
    int process_count;
} env = {
    .process_count = 20,
};

static pmdaInstid *kepler_instances;
static struct kepler_bpf *obj;
static struct perf_buffer *pb = NULL;
static int lost_events;
static int queuelength;

/* cache array */
struct tailq_entry {
    struct event event;
    TAILQ_ENTRY(tailq_entry) entries;
};

TAILQ_HEAD(tailhead, tailq_entry) head;

static struct tailq_entry* allocElm(void)
{
    return malloc(sizeof(struct tailq_entry));
}

static void push(struct tailq_entry *elm)
{
    TAILQ_INSERT_TAIL(&head, elm, entries);
    if (queuelength > env.process_count)
    {
        struct tailq_entry *l;
        l = head.tqh_first;
        TAILQ_REMOVE(&head, l, entries);
        free(l);
        queuelength--;
    }
    queuelength++;
}

static bool get_item(unsigned int offset, struct tailq_entry** val)
{
    struct tailq_entry *i;
    unsigned int iter = 0;

    TAILQ_FOREACH_REVERSE(i, &head, tailhead, entries) {
        if (offset == iter) {
            *val = i;
            return true;
        }
        iter++;
    }
    return false;
}

static unsigned int indom_id_mapping[INDOM_COUNT];

enum metric_name {
	COMM,
	PID,
	LOST,
	CGROUPID,
	RUNTIME,
	CPU_CYCLES,
	CPU_INSTR,
	CACHE_MISS,
	PAGE_CACHE_HIT,
	METRIC_COUNT /* last */
};
enum metric_indom { KEPLER_INDOM };

char* metric_names[METRIC_COUNT] = {
    [COMM] = "kepler.comm",
    [PID]  = "kepler.pid",
    [LOST] = "kepler.lost",
    [CGROUPID] = "kepler.cgroup_id",
    [RUNTIME] = "kepler.runtime",
    [CPU_CYCLES] = "kepler.cycles",
    [CPU_INSTR] = "kepler.instr",
    [CACHE_MISS] = "kepler.cache_miss",
    [PAGE_CACHE_HIT] = "kepler.page_cache_hit",
};

char* metric_text_oneline[METRIC_COUNT] = {
    [COMM] = "Command name",
    [PID]  = "Process identifier",
    [LOST] = "Number of lost events",
    [CGROUPID] = "Control Group identifier for each process",
    [RUNTIME] = "Run time of each process",
    [CPU_CYCLES] = "Number of cycles for each process",
    [CPU_INSTR] = "Number of instructions for each process",
    [CACHE_MISS] = "Number of cache misses for each process",
    [PAGE_CACHE_HIT] = "Number of page cache hits for each process",
};

char* metric_text_long[METRIC_COUNT] = {
    [COMM] = "Command name",
    [PID]  = "Process identifier",
    [LOST] = "Number of lost events",
    [CGROUPID] = "Control Group identifier for each process",
    [RUNTIME] = "Run time of each process",
    [CPU_CYCLES] = "Number of cycles for each process",
    [CPU_INSTR] = "Number of instructions for each process",
    [CACHE_MISS] = "Number of cache misses for each process",
    [PAGE_CACHE_HIT] = "Number of page cache hits for each process",
};

static unsigned int kepler_metric_count(void)
{
    return METRIC_COUNT;
}

static char* kepler_metric_name(unsigned int metric)
{
    return metric_names[metric];
}

static unsigned int kepler_indom_count(void)
{
    return INDOM_COUNT;
}

static void kepler_set_indom_serial(unsigned int local_indom_id, unsigned int global_id)
{
    indom_id_mapping[local_indom_id] = global_id;
}

static int kepler_metric_text(int item, int type, char **buffer)
{
    if (type & PM_TEXT_ONELINE) {
        *buffer = metric_text_oneline[item];
    } else {
        *buffer = metric_text_long[item];
    }

    return 0;
}

static void kepler_register(unsigned int cluster_id, pmdaMetric *metrics, pmdaIndom *indoms)
{
    /* bpf.kepler.comm */
    metrics[COMM] = (struct pmdaMetric)
    {
        .m_desc = {
            .pmid  = PMDA_PMID(cluster_id, 0),
            .type  = PM_TYPE_STRING,
            .indom = indom_id_mapping[KEPLER_INDOM],
            .sem   = PM_SEM_INSTANT,
            .units = PMDA_PMUNITS(0, 0, 0, 0, 0, 0),
        }
    };
    /* bpf.kepler.pid */
    metrics[PID] = (struct pmdaMetric)
    {
        .m_desc = {
            .pmid  = PMDA_PMID(cluster_id, 1),
            .type  = PM_TYPE_U32,
            .indom = indom_id_mapping[KEPLER_INDOM],
            .sem   = PM_SEM_DISCRETE,
            .units = PMDA_PMUNITS(0, 0, 0, 0, 0, 0),
        }
    };
    /* bpf.kepler.cgroupid */
    metrics[CGROUPID] = (struct pmdaMetric)
    {
        .m_desc = {
            .pmid  = PMDA_PMID(cluster_id, 2),
            .type  = PM_TYPE_U64,
            .indom = indom_id_mapping[KEPLER_INDOM],
            .sem   = PM_SEM_INSTANT,
            .units = PMDA_PMUNITS(0, 0, 0, 0, 0, 0),
        }
    };
    /* bpf.kepler.lost */
    metrics[LOST] = (struct pmdaMetric)
    {
        .m_desc = {
            .pmid  = PMDA_PMID(cluster_id, 3),
            .type  = PM_TYPE_U32,
            .indom = PM_INDOM_NULL,
            .sem   = PM_SEM_COUNTER,
            .units = PMDA_PMUNITS(0, 0, 1, 0, 0, PM_COUNT_ONE),
        }
    };
    /* bpf.kepler.runtime */
    metrics[RUNTIME] = (struct pmdaMetric)
    {
        .m_desc = {
            .pmid  = PMDA_PMID(cluster_id, 4),
            .type  = PM_TYPE_U64,
            .indom = indom_id_mapping[KEPLER_INDOM],
            .sem   = PM_SEM_COUNTER,
            .units = PMDA_PMUNITS(0, 1, 0, 0, PM_TIME_NSEC, 0),
        }
    };
    /* bpf.kepler.cpu_cycles */
    metrics[CPU_CYCLES] = (struct pmdaMetric)
    {
        .m_desc = {
            .pmid  = PMDA_PMID(cluster_id, 5),
            .type  = PM_TYPE_U64,
            .indom = indom_id_mapping[KEPLER_INDOM],
            .sem   = PM_SEM_COUNTER,
            .units = PMDA_PMUNITS(0, 0, 1, 0, 0, PM_COUNT_ONE),
        }
    };
    /* bpf.kepler.cpu_instr */
    metrics[CPU_INSTR] = (struct pmdaMetric)
    {
        .m_desc = {
            .pmid  = PMDA_PMID(cluster_id, 6),
            .type  = PM_TYPE_U64,
            .indom = indom_id_mapping[KEPLER_INDOM],
            .sem   = PM_SEM_COUNTER,
            .units = PMDA_PMUNITS(0, 0, 1, 0, 0, PM_COUNT_ONE),
        }
    };
    /* bpf.kepler.cache_miss */
    metrics[CACHE_MISS] = (struct pmdaMetric)
    {
        .m_desc = {
            .pmid  = PMDA_PMID(cluster_id, 7),
            .type  = PM_TYPE_U64,
            .indom = indom_id_mapping[KEPLER_INDOM],
            .sem   = PM_SEM_COUNTER,
            .units = PMDA_PMUNITS(0, 0, 1, 0, 0, PM_COUNT_ONE),
        }
    };
    /* bpf.kepler.page_cache_hit */
    metrics[PAGE_CACHE_HIT] = (struct pmdaMetric)
    {
        .m_desc = {
            .pmid  = PMDA_PMID(cluster_id, 8),
            .type  = PM_TYPE_U64,
            .indom = indom_id_mapping[KEPLER_INDOM],
            .sem   = PM_SEM_COUNTER,
            .units = PMDA_PMUNITS(0, 0, 1, 0, 0, PM_COUNT_ONE),
        }
    };

    /* KEPLER_INDOM */
    indoms[KEPLER_INDOM] = (struct pmdaIndom)
    {
        indom_id_mapping[KEPLER_INDOM],
        env.process_count,
        kepler_instances,
    };
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
    struct event *event = data;
    struct tailq_entry *elm = allocElm();

    elm->event.cgroup_id = event->cgroup_id;
    elm->event.pid = event->pid;
    elm->event.process_run_time = event->process_run_time;
    elm->event.cpu_cycles = event->cpu_cycles;
    elm->event.cpu_instr = event->cpu_instr;
    elm->event.cache_miss = event->cache_miss;
    elm->event.page_cache_hit = event->page_cache_hit;
    /* TODO: vec_nr */
    strncpy(elm->event.comm, event->comm, sizeof(event->comm));

    push(elm);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
    lost_events += lost_cnt;
}

static int kepler_init(dict *cfg, char *module_name)
{
    int err;
    char *val;

    if ((val = pmIniFileLookup(cfg, module_name, "process_count")))
        env.process_count = atoi(val);

    obj = kepler_bpf__open();
    if (!obj) {
        pmNotifyErr(LOG_ERR, "failed to open BPF object");
        return 1;
    }
    pmNotifyErr(LOG_INFO, "booting: %s", obj->skeleton->name);

    err = kepler_bpf__load(obj);
    if (err) {
        pmNotifyErr(LOG_ERR, "failed to load BPF object: %d", err);
        return err != 0;
    }

    err = kepler_bpf__attach(obj);
    if (err) {
        pmNotifyErr(LOG_ERR, "failed to attach BPF programs");
        return err != 0;
    }

    /* internal/external instance ids */
    fill_instids(env.process_count, &kepler_instances);

    /* Initialize the tail queue. */
    TAILQ_INIT(&head);

    /* setup event callbacks */
    // Warning: libbpf: map 'processes'  BPF_MAP_TYPE_PERF_EVENT_ARRAY
    pb = perf_buffer__new(bpf_map__fd(obj->maps.processes), PERF_BUFFER_PAGES,
            handle_event, handle_lost_events, NULL, NULL);
    if (!pb) {
        err = -errno;
        pmNotifyErr(LOG_ERR, "failed to open perf buffer: %d", err);
        return err != 0;
    }

    return err != 0;
}

static void kepler_shutdown()
{
    struct tailq_entry *itemp;

    free(kepler_instances);
    perf_buffer__free(pb);
    kepler_bpf__destroy(obj);
    /* Free the entire cache queue. */
    while ((itemp = TAILQ_FIRST(&head))) {
        TAILQ_REMOVE(&head, itemp, entries);
        free(itemp);
    }
}

static void kepler_refresh(unsigned int item)
{
    perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
}

static int kepler_fetch_to_atom(unsigned int item, unsigned int inst, pmAtomValue *atom)
{
    struct tailq_entry *value;

    /* bpf.kepler.lost */
    if (item == LOST) {
        atom->ul = lost_events;
        return PMDA_FETCH_STATIC;
    }

    if (inst == PM_IN_NULL)
        return PM_ERR_INST;

    if (!get_item(inst, &value))
        return PMDA_FETCH_NOVALUES;

    switch (item) {
	case COMM: /* bpf.kepler.comm */
	    atom->cp = value->event.comm;
	    break;
	case PID: /* bpf.kepler.pid */
	    atom->ul = value->event.pid;
	    break;
	case CGROUPID: /* bpf.kepler.cgroupid */
	    atom->ull = value->event.cgroup_id;
	    break;
	case RUNTIME: /* bpf.kepler.runtime */
	    atom->ull = value->event.process_run_time;
	    break;
	case CPU_CYCLES: /* bpf.kepler.cpu_cycles */
	    atom->ull = value->event.cpu_cycles;
	    break;
	case CPU_INSTR: /* bpf.kepler.cpu_instr */
	    atom->ull = value->event.cpu_instr;
	    break;
	case CACHE_MISS: /* bpf.kepler.cache_miss */
	    atom->ull = value->event.cache_miss;
	    break;
	case PAGE_CACHE_HIT: /* bpf.kepler.page_cache_hit */
	    atom->ull = value->event.page_cache_hit;
	    break;
    }

    return PMDA_FETCH_STATIC;
}

struct module bpf_module = {
    .init               = kepler_init,
    .register_metrics   = kepler_register,
    .metric_count       = kepler_metric_count,
    .indom_count        = kepler_indom_count,
    .set_indom_serial   = kepler_set_indom_serial,
    .shutdown           = kepler_shutdown,
    .refresh            = kepler_refresh,
    .fetch_to_atom      = kepler_fetch_to_atom,
    .metric_name        = kepler_metric_name,
    .metric_text        = kepler_metric_text,
};
