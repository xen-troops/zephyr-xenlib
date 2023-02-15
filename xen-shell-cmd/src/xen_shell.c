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
#include <string.h>
#include <stdio.h>

#include "domain.h"
#include "xenstore_srv.h"

#define XSS_CONSOLE_STACK_SIZE_PER_DOM 8192
K_KERNEL_STACK_DEFINE(read_thrd_stack, XSS_CONSOLE_STACK_SIZE_PER_DOM * DOM_MAX);
static size_t stack_slots[DOM_MAX] = { 0 };

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

void console_read_thrd(void *dom, void *p2, void *p3)
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
	while (!domain->console_thrd_stop) {
		k_sem_take(&domain->console_sem, K_FOREVER);

		do {
			memset(out, 0, buflen);
			memset(buffer, 0, buflen);
			recv = read_from_ring(domain->intf, buffer + nlpos,
					      sizeof(buffer) - nlpos - 1);
			if (recv) {
				memcpy(out, buffer, recv);

				/* Transfer output to Zephyr Dom0 console */
				printk("%s", buffer);
			}
		} while (recv);
	}
}

void evtchn_callback(void *priv)
{
	struct xen_domain *domain = (struct xen_domain *)priv;
	k_sem_give(&domain->console_sem);
}

int init_domain_console(struct xen_domain *domain)
{
	int rc = 0;

	rc = bind_interdomain_event_channel(domain->domid, domain->console_evtchn,
					       evtchn_callback, domain);

	if (rc < 0)
		return rc;

	domain->local_console_evtchn = rc;

	k_sem_init(&domain->console_sem, 1, 1);

	printk("%s: bind evtchn %d as %d\n", __func__, domain->console_evtchn,
	       domain->local_console_evtchn);

	rc = hvm_set_parameter(HVM_PARAM_CONSOLE_EVTCHN, domain->domid, domain->console_evtchn);

	if (rc) {
		printk("Failed to set domain console evtchn param, rc= %d\n", rc);
		return rc;
	}

	return rc;
}

int start_domain_console(struct xen_domain *domain)
{
	size_t slot = 0;

	if (domain->console_tid) {
		printk("Console thread is already running for this domain!\n");
		return -EBUSY;
	}

	for (; slot < DOM_MAX && stack_slots[slot] != 0; ++slot);

	if (slot >= DOM_MAX) {
		printk("Unable to find memory for console stack (%ld >= MAX:%d)\n", slot, DOM_MAX);
		return 1;
	}

	stack_slots[slot] = domain->domid;
	k_sem_init(&domain->console_sem, 1, 1);
	domain->console_thrd_stop = false;
	domain->console_tid =
		k_thread_create(&domain->console_thrd, read_thrd_stack + XSS_CONSOLE_STACK_SIZE_PER_DOM * slot,
				K_KERNEL_STACK_SIZEOF(read_thrd_stack) / DOM_MAX, console_read_thrd, domain,
				NULL, NULL, 7, 0, K_NO_WAIT);

	return 0;
}

int stop_domain_console(struct xen_domain *domain)
{
	int rc;
	size_t slot = 0;

	if (!domain->console_tid) {
		printk("No console thread is running!\n");
		return -ESRCH;
	}

	domain->console_thrd_stop = true;
	/* Send event to end read cycle */
	k_sem_give(&domain->console_sem);
	k_thread_join(&domain->console_thrd, K_FOREVER);
	domain->console_tid = NULL;

	for (; slot < DOM_MAX && stack_slots[slot] != domain->domid; ++slot);

	if (slot < DOM_MAX) {
		stack_slots[slot] = 0;
	}

	unbind_event_channel(domain->local_console_evtchn);
	rc = evtchn_close(domain->local_console_evtchn);

	if (rc)
	{
		printk("Unable to close event channel: %d\n", domain->local_console_evtchn);
		return rc;
	}

	return 0;
}
