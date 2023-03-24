/*
 * Copyright (c) 2023 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/xen/generic.h>
#include <zephyr/xen/public/io/console.h>
#include <zephyr/xen/public/memory.h>
#include <zephyr/xen/public/xen.h>
#include <zephyr/xen/hvm.h>

#include <zephyr/init.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <string.h>
#include <stdio.h>

#include "domain.h"
#include "xenstore_srv.h"
#include <xen_console.h>

LOG_MODULE_REGISTER(xen_domain_console);

/* One page is enough for anyone */
#define XEN_CONSOLE_STACK_SIZE		4096
/* Need low prio to make sure that guest does not lock up us in reader thread */
#define XEN_CONSOLE_PRIO		14
#define EXT_THREAD_STOP_BIT		0

static K_THREAD_STACK_ARRAY_DEFINE(read_thrd_stack, DOM_MAX,
				   XEN_CONSOLE_STACK_SIZE);

static uint32_t used_threads;
static K_MUTEX_DEFINE(global_console_lock);

BUILD_ASSERT(sizeof(used_threads) * CHAR_BIT >= DOM_MAX);

/* Allocate one stack for external reader thread */
static int get_stack_idx(void)
{
	int ret;

	k_mutex_lock(&global_console_lock, K_FOREVER);

	ret = find_lsb_set(~used_threads) - 1;

	/* This might fail only if BUILD_ASSERT above fails also, but
	 * better to be safe than sorry.
	 */
	__ASSERT_NO_MSG(ret >= 0);
	used_threads |= BIT(ret);
	LOG_DBG("Allocated stack with index %d", ret);

	k_mutex_unlock(&global_console_lock);

	return ret;
}

/* Free allocated stack */
static void free_stack_idx(int idx)
{
	__ASSERT_NO_MSG(idx < DOM_MAX);

	k_mutex_lock(&global_console_lock, K_FOREVER);

	__ASSERT_NO_MSG(used_threads & BIT(idx));
	used_threads &= ~BIT(idx);

	k_mutex_unlock(&global_console_lock);
}

/*
 * Need to read from OUT ring in dom0, domU writes logs there
 * TODO: place this in separate driver
 */
static int read_from_ring(struct xencons_interface *intf, char *str, int len)
{
	int recv = 0;
	XENCONS_RING_IDX cons = intf->out_cons;
	XENCONS_RING_IDX prod = intf->out_prod;
	XENCONS_RING_IDX out_idx = 0;

	compiler_barrier();
	__ASSERT((prod - cons) <= sizeof(intf->out), "Invalid input ring buffer");

	while (cons != prod && recv < len) {
		out_idx = MASK_XENCONS_IDX(cons, intf->out);
		str[recv] = intf->out[out_idx];
		recv++;
		cons++;
	}

	compiler_barrier();
	intf->out_cons = cons;

	return recv;
}

static void console_read_thrd(void *dom, void *p2, void *p3)
{
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);
	char buffer[128];
	char out[128];
	const int buflen = 128;
	int recv;
	int nlpos = 0;
	struct xen_domain *domain = (struct xen_domain *)dom;

	compiler_barrier();
	while (!atomic_test_and_clear_bit(&domain->console.stop_thrd,
					  EXT_THREAD_STOP_BIT)) {
		k_sem_take(&domain->console_sem, K_FOREVER);

		do {
			memset(out, 0, buflen);
			memset(buffer, 0, buflen);
			recv = read_from_ring(domain->console.intf,
					      buffer + nlpos,
					      sizeof(buffer) - nlpos - 1);
			if (recv) {
				memcpy(out, buffer, recv);

				/* Transfer output to Zephyr Dom0 console */
				LOG_RAW("%s", buffer);
			}
		} while (recv);
	}
}

static void evtchn_callback(void *priv)
{
	struct xen_domain *domain = (struct xen_domain *)priv;
	k_sem_give(&domain->console_sem);
}

int xen_init_domain_console(struct xen_domain *domain)
{
	int rc = 0;

	rc = bind_interdomain_event_channel(domain->domid,
					    domain->console.evtchn,
					    evtchn_callback, domain);

	if (rc < 0)
		return rc;

	domain->console.local_evtchn = rc;

	k_sem_init(&domain->console_sem, 1, 1);

	LOG_DBG("%s: bind evtchn %u as %u\n", __func__, domain->console.evtchn,
	       domain->console.local_evtchn);

	rc = hvm_set_parameter(HVM_PARAM_CONSOLE_EVTCHN, domain->domid,
			       domain->console.evtchn);

	if (rc) {
		LOG_ERR("Failed to set domain console evtchn param (rc=%d)", rc);
		return rc;
	}

	return rc;
}

int xen_start_domain_console(struct xen_domain *domain)
{
	if (domain->console_tid) {
		LOG_ERR("Console thread is already running for this domain!");
		return -EBUSY;
	}

	domain->console.stack_idx = get_stack_idx();
	k_sem_init(&domain->console_sem, 1, 1);
	atomic_clear_bit(&domain->console.stop_thrd, EXT_THREAD_STOP_BIT);

	domain->console_tid =
		k_thread_create(&domain->console_thrd,
				read_thrd_stack[domain->console.stack_idx],
				XEN_CONSOLE_STACK_SIZE,
				console_read_thrd, domain,
				NULL, NULL, XEN_CONSOLE_PRIO, 0, K_NO_WAIT);

	return 0;
}

int xen_stop_domain_console(struct xen_domain *domain)
{
	int rc;

	if (!domain->console_tid) {
		LOG_ERR("No console thread is running!");
		return -ESRCH;
	}

	atomic_set_bit(&domain->console.stop_thrd, EXT_THREAD_STOP_BIT);
	/* Send event to end read cycle */
	k_sem_give(&domain->console_sem);
	k_thread_join(&domain->console_thrd, K_FOREVER);
	domain->console_tid = NULL;
	free_stack_idx(domain->console.stack_idx);

	unbind_event_channel(domain->console.local_evtchn);
	rc = evtchn_close(domain->console.local_evtchn);

	if (rc)
	{
		LOG_ERR("Unable to close event channel#%u",
			domain->console.local_evtchn);
		return rc;
	}

	return 0;
}
