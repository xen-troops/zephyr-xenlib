/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2021-2023 EPAM Systems
 *
 * zImage helper structures and defines
 */
#ifndef __XENLIB_XEN_ZIMAGE_H__
#define __XENLIB_XEN_ZIMAGE_H__

#include <zephyr/kernel.h>

#define ZIMAGE64_MAGIC_V0	0x14000008
/* ASCII ARM\x64 */
#define ZIMAGE64_MAGIC_V1	0x644d5241

struct zimage64_hdr {
	uint32_t magic0;
	uint32_t res0;
	uint64_t text_offset;
	uint64_t res1;
	uint64_t res2;
	uint64_t res3;
	uint64_t res4;
	uint64_t res5;
	uint32_t magic1;
	uint32_t res6;
} __packed;

#endif /* __XENLIB_XEN_ZIMAGE_H__ */
