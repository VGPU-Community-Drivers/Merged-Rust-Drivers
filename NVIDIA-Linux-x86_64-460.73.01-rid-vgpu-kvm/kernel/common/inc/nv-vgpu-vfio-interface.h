/* _NVRM_COPYRIGHT_BEGIN_
 *
 * Copyright 2016-2018 by NVIDIA Corporation.  All rights reserved.  All
 * information contained herein is proprietary and confidential to NVIDIA
 * Corporation.  Any use, reproduction, or disclosure without the written
 * permission of NVIDIA Corporation is prohibited.
 *
 * _NVRM_COPYRIGHT_END_
 */

#ifndef _NV_VGPU_VFIO_INTERFACE_H_
#define _NV_VGPU_VFIO_INTERFACE_H_

#include <linux/pci.h>
#include <linux/device.h>
#include "nvstatus.h"
#include "nv-hypervisor.h"

typedef NV_STATUS (*vgpu_vfio_probe_t)(struct pci_dev *, NvU32, NvU32 *);
typedef void (*vgpu_vfio_remove_t)(struct pci_dev *);
typedef NV_STATUS (*vgpu_vfio_inject_interrupt_t)(void *);

/*
 * structure to be registered to RM using which it
 * will call into nvidia-vgpu-vfio module.
 * RM will use this structure to call into
 * nvidia-vgpu-vfio module
 */
typedef struct
{
    vgpu_vfio_probe_t probe;
    vgpu_vfio_remove_t  remove;
    vgpu_vfio_inject_interrupt_t inject_interrupt;
} vgpu_vfio_ops_t;

typedef NV_STATUS (*vgpu_vfio_vgpu_create_t) (struct pci_dev *dev, const NvU8 *uuid,
                                              NvU32 vgpu_type_id, NvU16 *vgpu_id,
                                              NvU32 *gpu_pci_id, NvU32 gpu_pci_bdf);
typedef NV_STATUS (*vgpu_vfio_vgpu_destroy_t) (const NvU8 *uuid, NvU16 vgpu_id);
typedef NV_STATUS (*vgpu_vfio_start_t) (const NvU8 *uuid, void *wait_queue, NvS32 *return_status,
                                        NvU8 *vm_name, NvU32 qemu_pid);
typedef NV_STATUS (*vgpu_vfio_bar_info_t) (struct pci_dev *dev, const NvU8 *, NvU64 *,
                                           NvU32 bar_index, void *, void **);
typedef NV_STATUS (*vgpu_vfio_get_description) (struct pci_dev *, NvU32, char *);
typedef NV_STATUS (*vgpu_vfio_get_name) (struct pci_dev *, NvU32, char *);
typedef NV_STATUS (*vgpu_vfio_get_instance) (struct pci_dev *, NvU32, char *);
typedef NV_STATUS (*vgpu_vfio_sparse_mmap_t) (struct pci_dev *, const NvU8 *, NvU64 **, NvU64 **, NvU32 *);
typedef void (*vgpu_vfio_update_request_t) (const NvU8 *, NvU64 *, NvU64 *, VGPU_DEVICE_STATE, const char *);

/*
 * nvidia-vgpu-vfio module uses this structure to
 * call into RM
 */
typedef struct
{
    const char *version_string;
    vgpu_vfio_vgpu_create_t vgpu_create;
    vgpu_vfio_vgpu_destroy_t vgpu_delete;
    vgpu_vfio_bar_info_t vgpu_bar_info;
    vgpu_vfio_start_t vgpu_start;
    vgpu_vfio_get_description get_description;
    vgpu_vfio_get_instance get_instances;
    vgpu_vfio_get_name get_name;
    vgpu_vfio_sparse_mmap_t get_sparse_mmap;
    vgpu_vfio_update_request_t update_request;
} rm_vgpu_vfio_ops_t;

/*
 * function exposed by RM and called by nvidia-vgpu-vfio
 * module to initialize vgpu_vfio_ops_t strucure
 */
NV_STATUS nvidia_vgpu_vfio_set_ops(vgpu_vfio_ops_t *vgpu_vfio_ops);

/*
 * function exposed by RM and called by nvidia-vgpu-vfio
 * module to initialize rm_vgpu_vfio_ops_t strucure
 */
NV_STATUS nvidia_vgpu_vfio_get_ops(rm_vgpu_vfio_ops_t *ops);

NV_STATUS nvidia_vgpu_vfio_probe(struct pci_dev *);
void nvidia_vgpu_vfio_remove(struct pci_dev *, NvBool);

#define NV_MSIX_CAP_BASE                0x000880c8
#define NV_MSIX_CAP_FUNCTION_MASKALL    0x40000000

void nvidia_isr_msix_prologue(nv_linux_state_t *nvl);
void nvidia_isr_msix_epilogue(nv_linux_state_t *nvl);
#endif /* _NV_VGPU_VFIO_INTERFACE_H_ */
