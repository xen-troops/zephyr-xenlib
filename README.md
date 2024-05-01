# zephyr-xenlib

This is a library for Zephyr OS that provides a set of APIs to interact with Xen hypervisor.

![Xen Project Logo](https://downloads.xenproject.org/Branding/Logos/Green+Black/xen_project_logo_dualcolor_165x69.png)

Xen is a free and open-source type-1 hypervisor, providing services that allow multiple computer operating systems to execute on the same computer hardware concurrently.

## Example

Here is an example of how to start a VM using the library, it uses external prebuilt images for the IPL and DTB for
the VM:

```c
#include <domain.h>
#include <string.h>
#include <xen_dom_mgmt.h>
#include <zephyr/xen/public/domctl.h>

extern char __img_ipl_start[];
extern char __img_ipl_end[];
extern char __dtb_ipl_start[];
extern char __dtb_ipl_end[];

static int load_ipl_image(uint8_t* buf, size_t bufsize, uint64_t image_load_offset, void* image_info)
{
    ARG_UNUSED(image_info);
    memcpy(buf, __img_ipl_start + image_load_offset, bufsize);
    return 0;
}

static ssize_t get_ipl_image_size(void* image_info, uint64_t* size)
{
    ARG_UNUSED(image_info);
    *size = __img_ipl_end - __img_ipl_start;
    return 0;
}


static struct xen_domain_cfg domd_cfg = {
    .name = "domd",
    .machine_dt_compat = "renesas,r8a779f0",
    .mem_kb = 0x100000, /* 1Gb */

    .flags = (XEN_DOMCTL_CDF_hvm | XEN_DOMCTL_CDF_hap | XEN_DOMCTL_CDF_iommu),
    .max_evtchns = 10,
    .max_vcpus = 4,
    .gnt_frames = 32,
    .max_maptrack_frames = 1,

    .iomems = NULL,
    .nr_iomems = 0,

    .irqs = NULL,
    .nr_irqs = 0,

    .gic_version = XEN_DOMCTL_CONFIG_GIC_V3,
    .tee_type = XEN_DOMCTL_CONFIG_TEE_OPTEE,

    .dtdevs = NULL,
    .nr_dtdevs = 0,

    .dt_passthrough = NULL,
    .nr_dt_passthrough = 0,
    .load_image_bytes = load_ipl_image,
    .get_image_size = get_ipl_image_size,
    .image_info = NULL,

    .dtb_start = __dtb_ipl_start,
    .dtb_end = __dtb_ipl_end,
};

int main(void)
{
    return domain_create(&domd_cfg, 1);
};
```
## Documentation

The library provides a set of APIs to interact with Xen hypervisor, most notable APIs are defined and documented in the following headers:

- `domain.h`: Domain config definitions.
- `xen_dom_mgmt.h`: APIs to manage domains.
- `xen-dom-xs.h`: APIs to interact with Xenstore.

## Building

To add the library to your Zephyr application, add the following to your `west.yml`:

```yaml
manifest:
  remotes:
    - name: xen-troops
      url-base: https://github.com/xen-troops

  projects:
    - name: zephyr-xenlib
      remote: xen-troops
      revision: "main"
```

## Configuration

Minimal configuration required to use the library is to enable the following Kconfig options:

```Kconfig
config XEN
config XEN_STORE_SRV
config XEN_LIBFDT
config XEN_DOMAIN_MANAGEMENT
config XEN_CONSOLE_SRV
```
For more information on the configuration options, please refer to the `Kconfig` file.
