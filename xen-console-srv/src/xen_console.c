/*
 * Copyright (c) 2023 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/init.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/shell/shell.h>
#include <zephyr/sys/barrier.h>
#include <zephyr/xen/generic.h>
#include <zephyr/xen/hvm.h>

#include <xen/public/io/console.h>
#include <xen/public/memory.h>
#include <xen/public/xen.h>

#include <string.h>
#include <stdio.h>

#include "domain.h"
#include "xenstore_srv.h"
#include <xen_console.h>
#include <mem-mgmt.h>

LOG_MODULE_REGISTER(xen_domain_console);

/* One page is enough for anyone */
#define XEN_CONSOLE_STACK_SIZE		4096
/* Need low prio to make sure that guest does not lock up us in reader thread */
#define XEN_CONSOLE_PRIO		14
#define EXT_THREAD_STOP_BIT		0
#define INT_THREAD_STOP_BIT		1

/* Size is chosen based on educated guess. It should be power of two. */
#define XEN_CONSOLE_BUFFER_SZ		8192

#define ESCAPE_CHARACTER		0x1d /* CTR+] */

static K_THREAD_STACK_ARRAY_DEFINE(read_thrd_stack, CONFIG_DOM_MAX,
				   XEN_CONSOLE_STACK_SIZE);
#ifdef CONFIG_XEN_SHELL
static K_THREAD_STACK_DEFINE(display_thrd_stack, XEN_CONSOLE_STACK_SIZE);
#endif /* CONFIG_XEN_SHELL */

static uint32_t used_threads;
static K_MUTEX_DEFINE(global_console_lock);
/* There we store pointer to an attached console */
static struct xen_domain_console *current_console;

BUILD_ASSERT(sizeof(used_threads) * CHAR_BIT >= CONFIG_DOM_MAX);
BUILD_ASSERT(XEN_CONSOLE_BUFFER_SZ &&
	     (XEN_CONSOLE_BUFFER_SZ & (XEN_CONSOLE_BUFFER_SZ - 1)) == 0);

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
	__ASSERT_NO_MSG(idx < CONFIG_DOM_MAX);

	k_mutex_lock(&global_console_lock, K_FOREVER);

	__ASSERT_NO_MSG(used_threads & BIT(idx));
	used_threads &= ~BIT(idx);

	k_mutex_unlock(&global_console_lock);
}

/* Write one character to the internal console ring.
 * Should be called with console->lock held.
 */
static void console_feed_int_ring(struct xen_domain_console *console, char ch)
{
	size_t buf_pos = console->int_prod++ & (XEN_CONSOLE_BUFFER_SZ - 1);

	console->int_buf[buf_pos] = ch;

	/* Special case for the already full buffer */
	if (unlikely((console->int_prod & (XEN_CONSOLE_BUFFER_SZ - 1)) ==
		     (console->int_cons & (XEN_CONSOLE_BUFFER_SZ - 1)))) {
		console->lost_chars++;
		console->int_cons++;
	}

	if (console->on_feed_cb) {
		console->on_feed_cb(ch, console->on_feed_cb_data);
	}
}

#ifdef CONFIG_XEN_SHELL
/* Write data to DomU
 * Please note that ring buffers named in accordance to DomU point of view:
 * intf->in is DomU input and our output;
 */
static void write_to_ext_ring(struct xencons_interface *intf,
			      char *data, int len)
{
	XENCONS_RING_IDX cons = intf->in_cons;
	XENCONS_RING_IDX prod = intf->in_prod;
	XENCONS_RING_IDX idx = 0;
	size_t free_space;

	z_barrier_dsync_fence_full();		/* Read counters, then write data */
	if ((prod - cons) > sizeof(intf->in)) {
		LOG_WRN("Invalid state of console input ring. Resetting.");
		intf->in_prod = cons;
		return;
	}

	free_space = sizeof(intf->in) - (prod-cons);
	if (free_space < len) {
		len = free_space;
		/* We can't block and we can't even print a warning */
	}
	while (len) {
		idx = MASK_XENCONS_IDX(prod, intf->out);
		intf->in[idx] = *data;
		prod++;
		data++;
		len--;
	}

	z_barrier_dsync_fence_full();		/* Write data, then update counter */
	intf->in_prod = prod;
}
#endif /* CONFIG_XEN_SHELL */

/* Read from domU ring buffer into a local ring buffer.
 * Please note that ring buffers named in accordance to DomU point of view:
 * intf->out is DomU output and our input;
 */
static int read_from_ext_ring(struct xencons_interface *intf,
			      struct xen_domain_console *console)

{
	int recv = 0;
	XENCONS_RING_IDX cons = intf->out_cons;
	XENCONS_RING_IDX prod = intf->out_prod;
	XENCONS_RING_IDX out_idx = 0;

	z_barrier_dsync_fence_full();		/* Read counters, then data */
	if ((prod - cons) > sizeof(intf->out)) {
		LOG_WRN("Invalid state of console output ring. Resetting.");
		intf->out_cons = prod;
		return 0;
	}

	while (cons != prod) {
		out_idx = MASK_XENCONS_IDX(cons, intf->out);
		console_feed_int_ring(console, intf->out[out_idx]);
		recv++;
		cons++;
	}

	z_barrier_dsync_fence_full();		/* Read data then update counter */
	intf->out_cons = cons;

	return recv;
}

static void console_read_thrd(void *con, void *p2, void *p3)
{
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);
	struct xen_domain_console *console = con;

	while (!atomic_test_and_clear_bit(&console->stop_thrd,
					  EXT_THREAD_STOP_BIT)) {
		k_sem_take(&console->ext_sem, K_FOREVER);
		/* Need to call read_from_ext_ring() till there are no
		 * data to read, because there can be race between us
		 * and writer in DomU
		 */
		k_mutex_lock(&console->lock, K_FOREVER);
		while (read_from_ext_ring(console->intf, console))
			;
		k_mutex_unlock(&console->lock);
		/* Notify display thread (if any) */
		k_sem_give(&console->int_sem);
	}
}

static void evtchn_callback(void *priv)
{
	struct xen_domain_console *console = priv;

	k_sem_give(&console->ext_sem);
}

static int xen_init_domain_console(struct xen_domain *domain)
{
	int rc = 0;
	struct xen_domain_console *console;

	console = &domain->console;
	rc = xenmem_map_region(domain->domid, 1,
			       XEN_PHYS_PFN(GUEST_MAGIC_BASE) +
			       CONSOLE_PFN_OFFSET,
			       (void **)&console->intf);
	if (rc < 0) {
		LOG_ERR("Failed to map console ring for domain#%u (rc=%d)",
			domain->domid, rc);
		return rc;
	}

	console->int_buf = k_malloc(XEN_CONSOLE_BUFFER_SZ);
	if (!console->int_buf) {
		LOG_ERR("Failed to allocate domain console buffer");
		rc = -ENOMEM;
		goto unmap_ring;
	}
	console->int_prod = 0;
	console->int_cons = 0;
	console->on_feed_cb = NULL;
	console->on_feed_cb_data = NULL;

	/* If we are attaching to a console for a second time, we need
	 * to join the previous thread. We need to initialize this
	 * variable to true, so then attach handler can reset it to false
	 */
	console->first_attach = true;

	rc = bind_interdomain_event_channel(domain->domid,
					    console->evtchn,
					    evtchn_callback, console);

	if (rc < 0) {
		goto err_free;
	}

	console->local_evtchn = rc;

	k_sem_init(&console->ext_sem, 1, 1);
	k_sem_init(&console->int_sem, 1, 1);
	k_mutex_init(&console->lock);

	LOG_DBG("%s: bind evtchn %u as %u\n", __func__, console->evtchn,
	       console->local_evtchn);

	rc = hvm_set_parameter(HVM_PARAM_CONSOLE_EVTCHN, domain->domid,
			       console->evtchn);
	if (rc) {
		LOG_ERR("Failed to set domain console evtchn param (rc=%d)", rc);
		goto err_unbind;
	}

	return 0;

err_unbind:
	unbind_event_channel(console->local_evtchn);
	evtchn_close(console->local_evtchn);

err_free:
	k_free(console->int_buf);

unmap_ring:
	xenmem_unmap_region(1, console->intf);

	return rc;
}

int xen_start_domain_console(struct xen_domain *domain)
{
	int rc;
	struct xen_domain_console *console;

	if (!domain) {
		LOG_ERR("No domain passed to attach_domain_console");
		return -ESRCH;
	}

	if (domain->f_dom0less) {
		LOG_ERR("dom0less domain#%u console operation not supported", domain->domid);
		return -ENOTSUP;
	}

	console = &domain->console;
	if (console->ext_tid) {
		LOG_ERR("Console thread is already running for this domain!");
		return -EBUSY;
	}

	rc = xen_init_domain_console(domain);
	if (rc) {
		LOG_ERR("Unable to init domain#%u console (rc=%d)", domain->domid, rc);
		return rc;
	}

	console->stack_idx = get_stack_idx();
	k_sem_init(&console->ext_sem, 1, 1);
	atomic_clear_bit(&console->stop_thrd, EXT_THREAD_STOP_BIT);

	console->ext_tid =
		k_thread_create(&console->ext_thrd,
				read_thrd_stack[console->stack_idx],
				XEN_CONSOLE_STACK_SIZE,
				console_read_thrd, console,
				NULL, NULL, XEN_CONSOLE_PRIO, 0, K_NO_WAIT);

	return 0;
}

int xen_stop_domain_console(struct xen_domain *domain)
{
	int rc, err = 0;
	struct xen_domain_console *console;

	if (!domain) {
		LOG_ERR("No domain passed to attach_domain_console");
		return -ESRCH;
	}

	if (domain->f_dom0less) {
		LOG_ERR("dom0less domain#%u console operation not supported", domain->domid);
		return -ENOTSUP;
	}

	console = &domain->console;

	if (!console->ext_tid) {
		LOG_ERR("No console thread is running!");
		return -ESRCH;
	}

	atomic_set_bit(&console->stop_thrd, EXT_THREAD_STOP_BIT);
	atomic_set_bit(&console->stop_thrd, INT_THREAD_STOP_BIT);

	/* Send event to end read cycle */
	k_sem_give(&console->ext_sem);
	k_thread_join(&console->ext_thrd, K_FOREVER);
	console->ext_tid = NULL;
	free_stack_idx(console->stack_idx);

	k_mutex_lock(&global_console_lock, K_FOREVER);
	/* Stop attached console if any */
	if (current_console == console) {
		k_sem_give(&console->int_sem);
		k_mutex_unlock(&global_console_lock);
		k_thread_join(&console->int_thrd, K_FOREVER);
	} else {
		k_mutex_unlock(&global_console_lock);
	}

	k_free(console->int_buf);

	unbind_event_channel(console->local_evtchn);

	rc = evtchn_close(console->local_evtchn);
	if (rc) {
		LOG_ERR("Unable to close event channel#%u",
			console->local_evtchn);
		err = rc;
	}

	rc = xenmem_unmap_region(1, console->intf);
	if (rc < 0) {
		LOG_ERR("Failed to unmap domain#%u console ring (rc=%d)",
			domain->domid, rc);
		err = rc;
	}

	return err;
}

#ifdef CONFIG_XEN_SHELL

static void console_display_thrd(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p3);
	struct xen_domain_console *console = p1;
	const struct shell *shell = p2;
	size_t buf_pos, prod_buf_pos;
	int size;

	shell_info(shell, "Attached to a domain console");

	while (!atomic_test_and_clear_bit(&console->stop_thrd,
					  INT_THREAD_STOP_BIT)) {
		k_sem_take(&console->int_sem, K_FOREVER);

		k_mutex_lock(&console->lock, K_FOREVER);
		/* Display info about missed characters */
		if (console->lost_chars) {
			shell_warn(shell,
				   "Domain console overrun detected. %zi bytes was lost",
				   console->lost_chars);
			console->lost_chars = 0;
		}

		while (console->int_cons < console->int_prod) {
			buf_pos = (console->int_cons) &
				(XEN_CONSOLE_BUFFER_SZ - 1);
			prod_buf_pos = (console->int_prod) &
				(XEN_CONSOLE_BUFFER_SZ - 1);
			/* int_buf is a circular buffer so we need to check for
			 * the wrap around condition to print it safely.
			 * In the case of the wrap around condition, we first
			 * print from the buf_pos to the end of the buffer,
			 * and then continue printing from the beginning of the buffer.
			 */
			if (buf_pos < prod_buf_pos) {
				size = prod_buf_pos - buf_pos;
			} else {
				size = XEN_CONSOLE_BUFFER_SZ - buf_pos;
			}
			shell_fprintf(shell, SHELL_NORMAL, "%.*s", size,
						&console->int_buf[buf_pos]);
			console->int_cons += size;
		}
		k_mutex_unlock(&console->lock);
	}

	k_mutex_lock(&global_console_lock, K_FOREVER);
	current_console = NULL;
	k_mutex_unlock(&global_console_lock);

	shell_info(shell, "Detached from console");
}

static void console_shell_cb(const struct shell *shell,
			     uint8_t *data, size_t len)
{
	struct xen_domain_console *console;

	k_mutex_lock(&global_console_lock, K_FOREVER);
	console = current_console;
	k_mutex_unlock(&global_console_lock);

	if (!console) {
		/* This may happen if xen_stop_domain_console() was
		 * called when console is still attached */
		shell_set_bypass(shell, NULL);
		return;
	}

	if (len == 1 && data[0] == ESCAPE_CHARACTER) {
		/* Detach console */
		atomic_set_bit(&console->stop_thrd, INT_THREAD_STOP_BIT);
		k_sem_give(&console->int_sem);
		shell_set_bypass(shell, NULL);
		return;
	}

	write_to_ext_ring(console->intf, data, len);
	notify_evtchn(console->local_evtchn);
}

int xen_attach_domain_console(const struct shell *shell,
			      struct xen_domain *domain)
{
	struct xen_domain_console *console;

	if (!domain) {
		LOG_ERR("No domain passed to attach_domain_console");
		return -ESRCH;
	}

	if (domain->f_dom0less) {
		LOG_ERR("dom0less domain#%u console operation not supported", domain->domid);
		return -ENOTSUP;
	}

	console = &domain->console;
	k_mutex_lock(&global_console_lock, K_FOREVER);
	if (current_console) {
		/* Actually, this should never happen */
		shell_error(shell, "Shell is already attached to console");
		k_mutex_unlock(&global_console_lock);
		put_domain(domain);
		return -EEXIST;
	}
	current_console = console;
	k_mutex_unlock(&global_console_lock);

	if (!console->first_attach) {
		k_thread_join(&console->int_thrd, K_FOREVER);
	}

	console->first_attach = false;
	atomic_clear_bit(&console->stop_thrd, INT_THREAD_STOP_BIT);

	k_thread_create(&console->int_thrd,
			display_thrd_stack,
			XEN_CONSOLE_STACK_SIZE,
			console_display_thrd, console,
			(void *)shell, NULL, XEN_CONSOLE_PRIO, 0, K_NO_WAIT);

	shell_set_bypass(shell, console_shell_cb);

	put_domain(domain);
	return 0;
}

#endif /* CONFIG_XEN_SHELL */

int set_console_feed_cb(struct xen_domain *domain, on_console_feed_cb_t cb, void *cb_data)
{
	struct xen_domain_console *console;

	if (!domain) {
		LOG_ERR("No domain passed to %s", __func__);
		return -ESRCH;
	}

	console = &domain->console;

	k_mutex_lock(&console->lock, K_FOREVER);

	console->on_feed_cb = cb;
	console->on_feed_cb_data = cb_data;

	k_mutex_unlock(&console->lock);

	return 0;
}
