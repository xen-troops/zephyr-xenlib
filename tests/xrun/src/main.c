/*
 * Copyright (C) 2023 Renesas Electronics Corporation.
 * Copyright (C) 2023 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <domain.h>
#include <string.h>
#include <zephyr/types.h>
#include <stdbool.h>
#include <zephyr/ztest.h>
#include <zephyr/data/json.h>

#include <xrun.h>
char *test_json_contents;
char *test_dtb_contents;
char *test_image_name;
char *test_dtb_name;
struct xen_domain_cfg g_cfg;

ZTEST(lib_xrun_test, test_json_spec_def)
{
	char json[] = "{"
		"\"ociVersion\" : \"1.0.1\", "
		"\"vm\" : { "
		"\"hypervisor\": { "
		"\"path\": \"xen\", "
		"\"parameters\": [\"pvcalls=true\"] "
		"}, "
		"\"kernel\": { "
		"\"path\" : \"/lfs/unikernel.bin\", "
		"\"parameters\" : [ \"port=8124\", \"hello world\" ]"
		"}, "
		"\"hwConfig\": { "
		"\"deviceTree\": \"/lfs/uni.dtb\", "
		"\"vcpus\": 2, "
		"\"memKB\": 4097, "
		"\"dtdevs\": [ \"dev1\", \"dev2\" ], "
		"\"iomems\": [ "
		"{ \"firstGFN\": 40000, "
		"\"firstMFN\": 40002, "
		"\"nrMFNs\": 1 }, "
		"{ \"firstGFN\": 50000, "
		"\"firstMFN\": 50002, "
		"\"nrMFNs\": 2 } "
		"], "
		"\"irqs\": [ 1, 2 ] "
		"} "
		"} "
		"}";

	int ret;
	uint32_t val;

	test_json_contents = json;
	test_dtb_contents = "dtb";
	test_dtb_name = "uni.dtb";
	test_image_name = "unikernel.bin";

	ret = xrun_run("/test", 0, "test");
	zassert_equal(ret, 0, "Error calling xrun_run");

	zassert_equal(g_cfg.mem_kb, 4097, "mem_kb wasn't decoded correctly");
	zassert_equal(g_cfg.max_vcpus, 2, "max_vcpus wasn't decoded correctly");

	zassert_equal(g_cfg.nr_dtdevs, 2,
		      "dtdevs wasn't decoded correctly");

	zassert_true(!strcmp(g_cfg.dtdevs[0], "dev1"),
		     "Dtdevs not decoded correctly");
	zassert_true(!strcmp(g_cfg.dtdevs[1], "dev2"),
		     "Dtdevs not decoded correctly");

	zassert_equal(g_cfg.nr_irqs, 2,
		      "nr_irqs wasn't decoded correctly");
	zassert_equal(g_cfg.irqs[0], 1, "irqs wasn't decoded correctly");
	zassert_equal(g_cfg.irqs[1], 2, "irqs wasn't decoded correctly");

	zassert_equal(g_cfg.nr_iomems, 2,
		      "nr_iomems wasn't decoded correctly");

	val = g_cfg.iomems[0].first_gfn;
	zassert_equal(val, 40000, "iomems wasn't decoded correctly");

	val = g_cfg.iomems[0].first_mfn;
	zassert_equal(val, 40002, "iomems wasn't decoded correctly");

	val = g_cfg.iomems[0].nr_mfns;
	zassert_equal(val, 1, "iomems wasn't decoded correctly");

	val = g_cfg.iomems[1].first_gfn;
	zassert_equal(val, 50000, "iomems wasn't decoded correctly");

	val = g_cfg.iomems[1].first_mfn;
	zassert_equal(val, 50002,
		      "iomems wasn't decoded correctly Got:%u",
		      val);

	val = g_cfg.iomems[1].nr_mfns;
	zassert_equal(val, 2,
		      "iomems wasn't decoded correctly Got:%u",
		      val);

	zassert_true(!strcmp(g_cfg.dtb_start, test_dtb_contents),
		     "Dtb file not decoded correctly");

	zassert_true(!strcmp(g_cfg.cmdline, "port=8124 hello world"),
		     "Dtb file not decoded correctly");

	ret = xrun_kill("test");
	zassert_equal(ret, 0, "Error calling xrun_run");
}

ZTEST(lib_xrun_test, test_json_spec_no_cmdline)
{
	char json[] = "{"
		"\"ociVersion\" : \"1.0.1\", "
		"\"vm\" : { "
		"\"hypervisor\": { "
		"\"path\": \"xen\", "
		"\"parameters\": [\"pvcalls=true\"] "
		"}, "
		"\"kernel\": { "
		"\"path\" : \"/lfs/unikernel.bin\", "
		"\"parameters\" : []"
		"}, "
		"\"hwConfig\": { "
		"\"deviceTree\": \"/lfs/uni.dtb\", "
		"\"vcpus\": 1, "
		"\"memKB\": 4096, "
		"\"dtdevs\": [ \"dev1\", \"dev2\" ], "
		"\"iomems\": [ "
		"{ \"firstGFN\": 40000, "
		"\"firstMFN\": 40002, "
		"\"nrMFNs\": 1 }, "
		"{ \"firstGFN\": 50000, "
		"\"firstMFN\": 50002, "
		"\"nrMFNs\": 2 } "
		"], "
		"\"irqs\": [ 1, 2 ] "
		"} "
		"} "
		"}";

	int ret;

	test_json_contents = json;
	test_dtb_contents = "dtb";
	test_dtb_name = "uni.dtb";
	test_image_name = "unikernel.bin";

	ret = xrun_run("/test", 0, "test");
	zassert_equal(ret, 0, "Error calling xrun_run");

	zassert_equal(g_cfg.mem_kb, 4096, "mem_kb wasn't decoded correctly");
	zassert_equal(g_cfg.max_vcpus, 1,
		      "max_vcpus wasn't decoded correctly");

	zassert_true(!strcmp(g_cfg.dtb_start, test_dtb_contents),
		     "Dtb file not decoded correctly");

	zassert_equal(g_cfg.cmdline, NULL, "Dtb file not decoded correctly");

	ret = xrun_kill("test");
	zassert_equal(ret, 0, "Error calling xrun_run");
}

ZTEST(lib_xrun_test, test_json_spec_no_dtb)
{
	char json[] = "{"
		"\"ociVersion\" : \"1.0.1\", "
		"\"vm\" : { "
		"\"hypervisor\": { "
		"\"path\": \"xen\", "
		"\"parameters\": [\"pvcalls=true\"] "
		"}, "
		"\"kernel\": { "
		"\"path\" : \"/lfs/unikernel.bin\", "
		"\"parameters\" : []"
		"}, "
		"\"hwConfig\": { "
		"\"deviceTree\": \"\", "
		"\"vcpus\": 1, "
		"\"memKB\": 4096, "
		"\"dtdevs\": [ \"dev1\", \"dev2\" ], "
		"\"iomems\": [ "
		"{ \"firstGFN\": 40000, "
		"\"firstMFN\": 40002, "
		"\"nrMFNs\": 1 }, "
		"{ \"firstGFN\": 50000, "
		"\"firstMFN\": 50002, "
		"\"nrMFNs\": 2 } "
		"], "
		"\"irqs\": [ 1, 2 ] "
		"} "
		"} "
		"}";

	int ret;

	test_json_contents = json;
	test_dtb_contents = "dtb";
	test_dtb_name = "uni.dtb";
	test_image_name = "unikernel.bin";

	ret = xrun_run("/test", 0, "test");
	zassert_equal(ret, 0, "Error calling xrun_run");

	zassert_equal(g_cfg.mem_kb, 4096, "mem_kb wasn't decoded correctly");
	zassert_equal(g_cfg.max_vcpus, 1, "max_vcpus wasn't decoded correctly");

	zassert_equal(g_cfg.dtb_start, NULL, "Dtb file not decoded correctly");

	zassert_equal(g_cfg.cmdline, NULL, "Dtb file not decoded correctly");

	ret = xrun_kill("test");
	zassert_equal(ret, 0, "Error calling xrun_run");
}

struct xrun_thread_info {
	int id_start;
	int id_end;
	k_tid_t tid;

};

static void xrun_starter(void *p1, void *p2, void *p3)
{
	struct xrun_thread_info *info = p1;
	int i, ret;
	char buf[25];

	for (i = info->id_start; i < info->id_end; i++) {
		snprintf(buf, 25, "test%d", i);
		ret = xrun_run("/test", 0, buf);
		zassert_equal(ret, 0, "Error calling xrun_run");
	}
}

static void xrun_stopper(void *p1, void *p2, void *p3)
{
	struct xrun_thread_info *info = p1;
	int i, ret;
	char buf[25];

	for (i = info->id_start; i < info->id_end; i++) {
		snprintf(buf, 25, "test%d", i);
		ret = xrun_kill(buf);
		zassert_equal(ret, 0, "Error calling xrun_run");
	}
}

#define STACK_SIZE (384)
#define THREADS_NUM 4

static struct xrun_thread_info tinfo[THREADS_NUM];
static struct k_thread tthread[THREADS_NUM];
static K_THREAD_STACK_ARRAY_DEFINE(tstack, THREADS_NUM, STACK_SIZE);

ZTEST(lib_xrun_test, test_start_stop_thread)
{
	char json[] = "{"
		"\"ociVersion\" : \"1.0.1\", "
		"\"vm\" : { "
		"\"hypervisor\": { "
		"\"path\": \"xen\", "
		"\"parameters\": [\"pvcalls=true\"] "
		"}, "
		"\"kernel\": { "
		"\"path\" : \"/lfs/unikernel.bin\", "
		"\"parameters\" : []"
		"}, "
		"\"hwConfig\": { "
		"\"deviceTree\": \"/lfs/uni.dtb\", "
		"\"vcpus\": 1, "
		"\"memKB\": 4096, "
		"\"dtdevs\": [ \"dev1\", \"dev2\" ], "
		"\"iomems\": [ "
		"{ \"firstGFN\": 40000, "
		"\"firstMFN\": 40002, "
		"\"nrMFNs\": 1 }, "
		"{ \"firstGFN\": 50000, "
		"\"firstMFN\": 50002, "
		"\"nrMFNs\": 2 } "
		"], "
		"\"irqs\": [ 1, 2 ] "
		"} "
		"} "
		"}";

	test_json_contents = json;
	test_dtb_contents = "dtb";
	test_dtb_name = "uni.dtb";
	test_image_name = "unikernel.bin";

	tinfo[0].id_start = 0;
	tinfo[0].id_end = 100;
	tinfo[0].tid = k_thread_create(&tthread[0], tstack[0], STACK_SIZE,
				       (k_thread_entry_t)xrun_starter,
				       &tinfo[0], NULL, NULL, K_PRIO_PREEMPT(5),
				       K_INHERIT_PERMS, K_NO_WAIT);
	tinfo[1].id_start = 100;
	tinfo[1].id_end = 200;
	tinfo[1].tid = k_thread_create(&tthread[1], tstack[1], STACK_SIZE,
				       (k_thread_entry_t)xrun_starter,
				       &tinfo[1], NULL, NULL, K_PRIO_PREEMPT(5),
				       K_INHERIT_PERMS, K_NO_WAIT);

	k_thread_join(tinfo[0].tid, K_FOREVER);
	tinfo[2].id_start = 0;
	tinfo[2].id_end = 100;
	tinfo[2].tid = k_thread_create(&tthread[2], tstack[2], STACK_SIZE,
				       (k_thread_entry_t)xrun_stopper,
				       &tinfo[2], NULL, NULL, K_PRIO_PREEMPT(5),
				       K_INHERIT_PERMS,
				       K_NO_WAIT);
	k_thread_join(tinfo[1].tid, K_FOREVER);
	tinfo[3].id_start = 100;
	tinfo[3].id_end = 200;
	tinfo[3].tid = k_thread_create(&tthread[3], tstack[3], STACK_SIZE,
				       (k_thread_entry_t)xrun_stopper,
				       &tinfo[3], NULL, NULL, K_PRIO_PREEMPT(5),
				       K_INHERIT_PERMS,
				       K_NO_WAIT);
	k_thread_join(tinfo[2].tid, K_FOREVER);
	k_thread_join(tinfo[3].tid, K_FOREVER);
}

ZTEST(lib_xrun_test, test_json_no_iomems)
{
	char json[] = "{"
		"\"ociVersion\" : \"1.0.1\", "
		"\"vm\" : { "
		"\"hypervisor\": { "
		"\"path\": \"xen\", "
		"\"parameters\": [\"pvcalls=true\"] "
		"}, "
		"\"kernel\": { "
		"\"path\" : \"/lfs/unikernel.bin\", "
		"\"parameters\" : [ \"port=8124\", \"hello world\" ]"
		"}, "
		"\"hwConfig\": { "
		"\"deviceTree\": \"/lfs/uni.dtb\", "
		"\"vcpus\": 2, "
		"\"memKB\": 4097, "
		"\"dtdevs\": [ \"dev1\", \"dev2\" ], "
		"\"iomems\": [ ], "
		"\"irqs\": [ 1, 2 ] "
		"} "
		"} "
		"}";

	int ret;

	test_json_contents = json;
	test_dtb_contents = "dtb";
	test_dtb_name = "uni.dtb";
	test_image_name = "unikernel.bin";

	ret = xrun_run("/test", 0, "test");
	zassert_equal(ret, 0, "Error calling xrun_run");

	zassert_equal(g_cfg.mem_kb, 4097, "mem_kb wasn't decoded correctly");
	zassert_equal(g_cfg.max_vcpus, 2, "max_vcpus wasn't decoded correctly");

	zassert_equal(g_cfg.nr_dtdevs, 2,
		      "dtdevs wasn't decoded correctly");

	zassert_true(!strcmp(g_cfg.dtdevs[0], "dev1"),
		     "Dtdevs not decoded correctly");
	zassert_true(!strcmp(g_cfg.dtdevs[1], "dev2"),
		     "Dtdevs not decoded correctly");

	zassert_equal(g_cfg.nr_irqs, 2,
		      "nr_irqs wasn't decoded correctly");
	zassert_equal(g_cfg.irqs[0], 1, "irqs wasn't decoded correctly");
	zassert_equal(g_cfg.irqs[1], 2, "irqs wasn't decoded correctly");

	zassert_equal(g_cfg.nr_iomems, 0,
		      "nr_iomems wasn't decoded correctly");
	zassert_equal(g_cfg.iomems, NULL,
		      "iomems wasn't decoded correctly");

	zassert_true(!strcmp(g_cfg.dtb_start, test_dtb_contents),
		     "Dtb file not decoded correctly");

	zassert_true(!strcmp(g_cfg.cmdline, "port=8124 hello world"),
		     "Dtb file not decoded correctly");

	ret = xrun_kill("test");
	zassert_equal(ret, 0, "Error calling xrun_run");
}

ZTEST(lib_xrun_test, test_json_no_dtdevs)
{
	char json[] = "{"
		"\"ociVersion\" : \"1.0.1\", "
		"\"vm\" : { "
		"\"hypervisor\": { "
		"\"path\": \"xen\", "
		"\"parameters\": [\"pvcalls=true\"] "
		"}, "
		"\"kernel\": { "
		"\"path\" : \"/lfs/unikernel.bin\", "
		"\"parameters\" : [ \"port=8124\", \"hello world\" ]"
		"}, "
		"\"hwConfig\": { "
		"\"deviceTree\": \"/lfs/uni.dtb\", "
		"\"vcpus\": 2, "
		"\"memKB\": 4097, "
		"\"dtdevs\": [ ], "
		"\"iomems\": [ ], "
		"\"irqs\": [ 1, 2 ] "
		"} "
		"} "
		"}";

	int ret;

	test_json_contents = json;
	test_dtb_contents = "dtb";
	test_dtb_name = "uni.dtb";
	test_image_name = "unikernel.bin";

	ret = xrun_run("/test", 0, "test");
	zassert_equal(ret, 0, "Error calling xrun_run");

	zassert_equal(g_cfg.mem_kb, 4097, "mem_kb wasn't decoded correctly");
	zassert_equal(g_cfg.max_vcpus, 2, "max_vcpus wasn't decoded correctly");

	zassert_equal(g_cfg.nr_dtdevs, 0, "dtdevs wasn't decoded correctly");

	zassert_equal(g_cfg.nr_irqs, 2, "nr_irqs wasn't decoded correctly");
	zassert_equal(g_cfg.irqs[0], 1, "irqs wasn't decoded correctly");
	zassert_equal(g_cfg.irqs[1], 2, "irqs wasn't decoded correctly");

	zassert_equal(g_cfg.nr_iomems, 0, "nr_iomems wasn't decoded correctly");
	zassert_equal(g_cfg.iomems, NULL, "iomems wasn't decoded correctly");

	zassert_true(!strcmp(g_cfg.dtb_start, test_dtb_contents),
		     "Dtb file not decoded correctly");
	zassert_true(!strcmp(g_cfg.cmdline, "port=8124 hello world"),
		     "Dtb file not decoded correctly");

	ret = xrun_kill("test");
	zassert_equal(ret, 0, "Error calling xrun_run");
}

ZTEST(lib_xrun_test, test_json_no_irqs)
{
	char json[] = "{"
		"\"ociVersion\" : \"1.0.1\", "
		"\"vm\" : { "
		"\"hypervisor\": { "
		"\"path\": \"xen\", "
		"\"parameters\": [\"pvcalls=true\"] "
		"}, "
		"\"kernel\": { "
		"\"path\" : \"/lfs/unikernel.bin\", "
		"\"parameters\" : [ \"port=8124\", \"hello world\" ]"
		"}, "
		"\"hwConfig\": { "
		"\"deviceTree\": \"/lfs/uni.dtb\", "
		"\"vcpus\": 2, "
		"\"memKB\": 4097, "
		"\"dtdevs\": [ ], "
		"\"iomems\": [ ], "
		"\"irqs\": [ ] "
		"} "
		"} "
		"}";

	int ret;

	test_json_contents = json;
	test_dtb_contents = "dtb";
	test_dtb_name = "uni.dtb";
	test_image_name = "unikernel.bin";

	ret = xrun_run("/test", 0, "test");
	zassert_equal(ret, 0, "Error calling xrun_run");

	zassert_equal(g_cfg.mem_kb, 4097, "mem_kb wasn't decoded correctly");
	zassert_equal(g_cfg.max_vcpus, 2, "max_vcpus wasn't decoded correctly");

	zassert_equal(g_cfg.nr_dtdevs, 0, "dtdevs wasn't decoded correctly");

	zassert_equal(g_cfg.nr_irqs, 0, "nr_irqs wasn't decoded correctly");

	zassert_equal(g_cfg.nr_iomems, 0, "nr_iomems wasn't decoded correctly");
	zassert_equal(g_cfg.iomems, NULL, "iomems wasn't decoded correctly");

	zassert_true(!strcmp(g_cfg.dtb_start, test_dtb_contents),
		     "Dtb file not decoded correctly");

	zassert_true(!strcmp(g_cfg.cmdline, "port=8124 hello world"),
		     "Dtb file not decoded correctly");

	ret = xrun_kill("test");
	zassert_equal(ret, 0, "Error calling xrun_run");
}

ZTEST(lib_xrun_test, test_json_no_vcpus)
{
	char json[] = "{"
		"\"ociVersion\" : \"1.0.1\", "
		"\"vm\" : { "
		"\"hypervisor\": { "
		"\"path\": \"xen\", "
		"\"parameters\": [\"pvcalls=true\"] "
		"}, "
		"\"kernel\": { "
		"\"path\" : \"/lfs/unikernel.bin\", "
		"\"parameters\" : [ \"port=8124\", \"hello world\" ]"
		"}, "
		"\"hwConfig\": { "
		"\"deviceTree\": \"/lfs/uni.dtb\", "
		"\"dtdevs\": [ ], "
		"\"iomems\": [ ], "
		"\"irqs\": [ ] "
		"} "
		"} "
		"}";

	int ret;

	test_json_contents = json;
	test_dtb_contents = "dtb";
	test_dtb_name = "uni.dtb";
	test_image_name = "unikernel.bin";

	ret = xrun_run("/test", 0, "test");
	zassert_equal(ret, 0, "Error calling xrun_run");

	zassert_equal(g_cfg.mem_kb, 4096,
		      "mem_kb wasn't decoded correctly val = %d",
		      g_cfg.mem_kb);
	zassert_equal(g_cfg.max_vcpus, 1,
		      "max_vcpus wasn't decoded correctly val = %d",
		      g_cfg.max_vcpus);

	zassert_equal(g_cfg.nr_dtdevs, 0, "dtdevs wasn't decoded correctly");

	zassert_equal(g_cfg.nr_irqs, 0, "nr_irqs wasn't decoded correctly");

	zassert_equal(g_cfg.nr_iomems, 0, "nr_iomems wasn't decoded correctly");
	zassert_equal(g_cfg.iomems, NULL, "iomems wasn't decoded correctly");

	zassert_true(!strcmp(g_cfg.dtb_start, test_dtb_contents),
		     "Dtb file not decoded correctly");

	zassert_true(!strcmp(g_cfg.cmdline, "port=8124 hello world"),
		     "Dtb file not decoded correctly");

	ret = xrun_kill("test");
	zassert_equal(ret, 0, "Error calling xrun_run");
}

ZTEST(lib_xrun_test, test_json_no_fields)
{
	char json[] = "{"
		"\"ociVersion\" : \"1.0.1\", "
		"\"vm\" : { "
		"\"hypervisor\": { "
		"\"path\": \"xen\", "
		"\"parameters\": [\"pvcalls=true\"] "
		"}, "
		"\"kernel\": { "
		"\"path\" : \"/lfs/unikernel.bin\", "
		"\"parameters\" : [ \"port=8124\", \"hello world\" ]"
		"}, "
		"\"hwConfig\": { "
		"\"deviceTree\": \"/lfs/uni.dtb\" "
		"} "
		"} "
		"}";

	int ret;

	test_json_contents = json;
	test_dtb_contents = "dtb";
	test_dtb_name = "uni.dtb";
	test_image_name = "unikernel.bin";

	ret = xrun_run("/test", 0, "test");
	zassert_equal(ret, 0, "Error calling xrun_run");

	zassert_equal(g_cfg.mem_kb, 4096,
		      "mem_kb wasn't decoded correctly val = %d",
		      g_cfg.mem_kb);
	zassert_equal(g_cfg.max_vcpus, 1,
		      "max_vcpus wasn't decoded correctly val = %d",
		      g_cfg.max_vcpus);

	zassert_equal(g_cfg.nr_dtdevs, 0, "dtdevs wasn't decoded correctly");

	zassert_equal(g_cfg.nr_irqs, 0, "nr_irqs wasn't decoded correctly");

	zassert_equal(g_cfg.nr_iomems, 0, "nr_iomems wasn't decoded correctly");
	zassert_equal(g_cfg.iomems, NULL, "iomems wasn't decoded correctly");

	zassert_true(!strcmp(g_cfg.dtb_start, test_dtb_contents),
		     "Dtb file not decoded correctly");

	zassert_true(!strcmp(g_cfg.cmdline, "port=8124 hello world"),
		     "Dtb file not decoded correctly");

	ret = xrun_kill("test");
	zassert_equal(ret, 0, "Error calling xrun_run");
}

ZTEST(lib_xrun_test, test_json_no_dtdevs_iomems)
{
	char json[] = "{"
		"\"ociVersion\" : \"1.0.1\", "
		"\"vm\" : { "
		"\"hypervisor\": { "
		"\"path\": \"xen\", "
		"\"parameters\": [\"pvcalls=true\"] "
		"}, "
		"\"kernel\": { "
		"\"path\" : \"/lfs/unikernel.bin\", "
		"\"parameters\" : [ \"port=8124\", \"hello world\" ]"
		"}, "
		"\"hwConfig\": { "
		"\"deviceTree\": \"/lfs/uni.dtb\", "
		"\"irqs\": [ ] "
		"} "
		"} "
		"}";

	int ret;

	test_json_contents = json;
	test_dtb_contents = "dtb";
	test_dtb_name = "uni.dtb";
	test_image_name = "unikernel.bin";

	ret = xrun_run("/test", 0, "test");
	zassert_equal(ret, 0, "Error calling xrun_run");

	zassert_equal(g_cfg.mem_kb, 4096,
		      "mem_kb wasn't decoded correctly val = %d",
		      g_cfg.mem_kb);
	zassert_equal(g_cfg.max_vcpus, 1,
		      "max_vcpus wasn't decoded correctly val = %d",
		      g_cfg.max_vcpus);

	zassert_equal(g_cfg.nr_dtdevs, 0, "dtdevs wasn't decoded correctly");

	zassert_equal(g_cfg.nr_irqs, 0, "nr_irqs wasn't decoded correctly");

	zassert_equal(g_cfg.nr_iomems, 0, "nr_iomems wasn't decoded correctly");
	zassert_equal(g_cfg.iomems, NULL, "iomems wasn't decoded correctly");

	zassert_true(!strcmp(g_cfg.dtb_start, test_dtb_contents),
		     "Dtb file not decoded correctly");

	zassert_true(!strcmp(g_cfg.cmdline, "port=8124 hello world"),
		     "Dtb file not decoded correctly");

	ret = xrun_kill("test");
	zassert_equal(ret, 0, "Error calling xrun_run");
}

ZTEST_SUITE(lib_xrun_test, NULL, NULL, NULL, NULL, NULL);
