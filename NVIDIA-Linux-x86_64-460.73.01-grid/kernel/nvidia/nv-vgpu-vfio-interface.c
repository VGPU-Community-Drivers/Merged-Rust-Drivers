/* _NVRM_COPYRIGHT_BEGIN_
 *
 * Copyright 2016-2020 by NVIDIA Corporation.  All rights reserved.  All
 * information contained herein is proprietary and confidential to NVIDIA
 * Corporation.  Any use, reproduction, or disclosure without the written
 * permission of NVIDIA Corporation is prohibited.
 *
 * _NVRM_COPYRIGHT_END_
 */

#include "nv-linux.h"
#include "nv-vgpu-vfio-interface.h"
#include "nv-misc.h"
#include "os-interface.h"
#include "nvstatus.h"
#include "nv-hypervisor.h"
#include "nv.h"

static vgpu_vfio_ops_t *vgpu_vfio_ops;

static NV_STATUS nvidia_vgpu_delete(const NvU8 *uuid, NvU16 vgpu_id)
{
    nvidia_stack_t *sp = NULL;
    NV_STATUS status = NV_OK;

    if (nv_kmem_cache_alloc_stack(&sp) != 0)
        return NV_ERR_NO_MEMORY;

    status = nv_vgpu_delete(sp, uuid, vgpu_id);

    nv_kmem_cache_free_stack(sp);
    return status;
}

static NV_STATUS nvidia_vgpu_create(struct pci_dev *pci_dev, const NvU8 *uuid,
                                    NvU32 vgpu_type_id, NvU16 *vgpu_id,
                                    NvU32 *gpu_pci_id, NvU32 gpu_pci_bdf)
{
    NV_STATUS status = NV_OK;
    nvidia_stack_t *sp = NULL;
    nv_state_t *nv;
    nv_linux_state_t *nvl = pci_get_drvdata(pci_dev);

    if (!nvl || (nvl->pci_dev != pci_dev))
        return NV_ERR_OBJECT_NOT_FOUND;

    nv = NV_STATE_PTR(nvl);

    if (nv_kmem_cache_alloc_stack(&sp) != 0)
        return NV_ERR_NO_MEMORY;

    status = nv_vgpu_create_request(sp, nv, uuid, vgpu_type_id,
                                    vgpu_id, gpu_pci_bdf);

    nv_kmem_cache_free_stack(sp);

    if (status != NV_OK)
        nv_printf(NV_DBG_ERRORS, "NVRM: Failed to add vgpu create request: 0x%x\n", status);
    else
        *gpu_pci_id = nv->gpu_id;

    return status;
}

static NV_STATUS nvidia_vgpu_bar_info(struct pci_dev *pci_dev, const NvU8 *uuid,
                                      NvU64 *size, NvU32 region_index,
                                      void *vgpu_dev_ref, void **host_vgpu_dev)
{
    NV_STATUS status;
    nvidia_stack_t *sp = NULL;
    nv_state_t *nv;
    nv_linux_state_t *nvl = pci_get_drvdata(pci_dev);

    if (!nvl || (nvl->pci_dev != pci_dev))
        return NV_ERR_OBJECT_NOT_FOUND;

    nv = NV_STATE_PTR(nvl);

    if (nv_kmem_cache_alloc_stack(&sp) != 0)
        return NV_ERR_NO_MEMORY;

    status = nv_vgpu_get_bar_info(sp, nv, uuid, size, region_index,
                                  vgpu_dev_ref, host_vgpu_dev);

    nv_kmem_cache_free_stack(sp);

    if (status != NV_OK)
        nv_printf(NV_DBG_ERRORS, "NVRM: %pUl Failed to get bar info: status: 0x%x "
                                 "region_index: %d\n", uuid, status, region_index);

    return status;
}

static NV_STATUS nvidia_vgpu_start(const NvU8 *uuid, void *wait_queue, NvS32 *return_status,
                                   NvU8 *vm_name, NvU32 qemu_pid)
{
    NV_STATUS status;
    nvidia_stack_t *sp = NULL;

    if (nv_kmem_cache_alloc_stack(&sp) != 0)
        return NV_ERR_NO_MEMORY;

    status = nv_vgpu_start(sp, uuid, wait_queue, return_status, vm_name,
                           qemu_pid);

    nv_kmem_cache_free_stack(sp);

    if (status != NV_OK)
        nv_printf(NV_DBG_ERRORS, "NVRM: Failed to start vGPU: 0x%x\n", status);

    return status;
}

static NV_STATUS nvidia_vgpu_get_info(struct pci_dev *pci_dev, NvU32 vgpu_type_id,
                                      char *buf, VGPU_TYPE_INFO type_info)
{
    NV_STATUS status;
    nvidia_stack_t *sp = NULL;
    nv_state_t *nv;
    nv_linux_state_t *nvl = NULL;
    struct pci_dev *parent_device;


#ifdef NV_PCI_SRIOV_SUPPORT
    if (pci_dev->is_virtfn)
        parent_device = pci_dev->physfn;
    else
#endif /* NV_PCI_SRIOV_SUPPORT */

        parent_device = pci_dev;

    nvl = pci_get_drvdata(parent_device);

    if (!nvl || (nvl->pci_dev != parent_device))
        return NV_ERR_OBJECT_NOT_FOUND;

    nv = NV_STATE_PTR(nvl);

    if (nv_kmem_cache_alloc_stack(&sp) != 0)
        return NV_ERR_NO_MEMORY;

    status = nv_vgpu_get_type_info(sp, nv, vgpu_type_id, buf, type_info, pci_dev->devfn);

    nv_kmem_cache_free_stack(sp);

    return status;
}

static NV_STATUS nvidia_vgpu_get_name(struct pci_dev *pci_dev, NvU32 vgpu_type_id, char *buf)
{
    return nvidia_vgpu_get_info(pci_dev, vgpu_type_id, buf, VGPU_TYPE_NAME);
}

static NV_STATUS nvidia_vgpu_get_description(struct pci_dev *pci_dev, NvU32 vgpu_type_id, char *buf)
{
    return nvidia_vgpu_get_info(pci_dev, vgpu_type_id, buf, VGPU_TYPE_DESCRIPTION);
}

static NV_STATUS nvidia_vgpu_get_instances(struct pci_dev *pci_dev, NvU32 vgpu_type_id, char *buf)
{
    return nvidia_vgpu_get_info(pci_dev, vgpu_type_id, buf, VGPU_TYPE_INSTANCES);
}

static NV_STATUS nvidia_vgpu_get_sparse_mmap(struct pci_dev *pci_dev, const NvU8 *uuid,
                                             NvU64 **offsets, NvU64 **sizes,
                                             NvU32 *num_areas)
{
    NV_STATUS status;
    nvidia_stack_t *sp = NULL;
    nv_state_t *nv;
    nv_linux_state_t *nvl = pci_get_drvdata(pci_dev);

    if (!nvl || (nvl->pci_dev != pci_dev))
        return NV_ERR_OBJECT_NOT_FOUND;

    nv = NV_STATE_PTR(nvl);

    if (nv_kmem_cache_alloc_stack(&sp) != 0)
        return NV_ERR_NO_MEMORY;

    status = nv_vgpu_get_sparse_mmap(sp, nv, uuid, offsets, sizes, num_areas);

    nv_kmem_cache_free_stack(sp);

    if (status != NV_OK)
        nv_printf(NV_DBG_ERRORS, "NVRM: %pUl Failed to check sparse mmap: status: 0x%x\n",
                  uuid, status);
    return status;
}

static void nvidia_vgpu_update_request(const NvU8 *uuid, NvU64 *offsets,
                                       NvU64 *sizes, VGPU_DEVICE_STATE deviceState,
                                       const char *config_params)
{
    NV_STATUS status;
    nvidia_stack_t *sp = NULL;

    if (nv_kmem_cache_alloc_stack(&sp) != 0)
        return;

    status = nv_vgpu_update_request(sp, uuid, deviceState, offsets, sizes, config_params);

    nv_kmem_cache_free_stack(sp);

    if (status != NV_OK)
        nv_printf(NV_DBG_ERRORS, "NVRM: %pUl Failed to update request vGPU: status: 0x%x\n",
                  uuid, status);
}

NV_STATUS nvidia_vgpu_vfio_set_ops(vgpu_vfio_ops_t *ops)
{
    vgpu_vfio_ops = ops;
    return NV_OK;
}
EXPORT_SYMBOL(nvidia_vgpu_vfio_set_ops);

NV_STATUS nvidia_vgpu_vfio_get_ops(rm_vgpu_vfio_ops_t *ops)
{
    if (strcmp(ops->version_string, NV_VERSION_STRING) != 0)
    {
        ops->version_string = NV_VERSION_STRING;
        return NV_ERR_GENERIC;
    }

    ops->vgpu_create = nvidia_vgpu_create;
    ops->vgpu_delete = nvidia_vgpu_delete;
    ops->vgpu_bar_info = nvidia_vgpu_bar_info;
    ops->vgpu_start = nvidia_vgpu_start;
    ops->get_name = nvidia_vgpu_get_name;
    ops->get_description = nvidia_vgpu_get_description;
    ops->get_instances = nvidia_vgpu_get_instances;
    ops->get_sparse_mmap = nvidia_vgpu_get_sparse_mmap;
    ops->update_request = nvidia_vgpu_update_request;

    return NV_OK;
}
EXPORT_SYMBOL(nvidia_vgpu_vfio_get_ops);

static void revive_vfs(struct pci_dev *pci_dev)
{
    nv_linux_state_t *nvl;
    nvidia_stack_t *sp = NULL;

    vgpu_vf_pci_info vf_pci_info[MAX_VF_COUNT_PER_GPU];
    unsigned int i;

    for (i = 0; i < MAX_VF_COUNT_PER_GPU; i++)
    {
        vf_pci_info[i].isNvidiaAttached = NV_FALSE;
        vf_pci_info[i].isMdevAttached   = NV_FALSE;
    }

    if (nv_kmem_cache_alloc_stack(&sp) != 0)
    {
        return;
    }

    nvl = pci_get_drvdata(pci_dev);

    if (nvl)
    {
        NV_STATUS status = nv_vgpu_process_vf_info(sp, NV_STATE_PTR(nvl),
                                                   NV_VGPU_GET_VF_INFO,
                                                   0, 0, 0, 0,
                                                   NV_FALSE,
                                                   (void *) vf_pci_info);
        if (status != NV_OK)
        {
            nv_printf(NV_DBG_ERRORS,"NVRM: Failed to get VF info from PF 0x%x\n", status);

            nv_kmem_cache_free_stack(sp);
            return;
        }

        for (i = 0; i < MAX_VF_COUNT_PER_GPU; i++)
        {
            if (vf_pci_info[i].isNvidiaAttached && !vf_pci_info[i].isMdevAttached)
            {
                unsigned int devfn;
                struct pci_dev *vf_pci_dev;

                devfn = PCI_DEVFN(vf_pci_info[i].slot, vf_pci_info[i].function);
                vf_pci_dev = NV_GET_DOMAIN_BUS_AND_SLOT(vf_pci_info[i].domain, vf_pci_info[i].bus, devfn);

                if (vf_pci_dev)
                {
                    pci_dev_put(vf_pci_dev);
                    if (vgpu_vfio_ops && vgpu_vfio_ops->probe)
                    {
                        nv_printf(NV_DBG_INFO, "NVRM: %s: Reviving dormant VF %04x:%02x:%02x.%x after re-probing PF\n",
                                  __FUNCTION__,
                                  NV_PCI_DOMAIN_NUMBER(vf_pci_dev),
                                  NV_PCI_BUS_NUMBER(vf_pci_dev),
                                  NV_PCI_SLOT_NUMBER(vf_pci_dev),
                                  PCI_FUNC(vf_pci_dev->devfn));
                        nvidia_vgpu_vfio_probe(vf_pci_dev);
                    }
                }
            }
        }
    }
    nv_kmem_cache_free_stack(sp);
}

NV_STATUS nvidia_vgpu_vfio_probe(struct pci_dev *pci_dev)
{
    NV_STATUS status = 0;
    nvidia_stack_t *sp = NULL;
    nv_state_t *nv;
    struct pci_dev *parent_device;
    nv_linux_state_t *nvl;
    NvU32 *vgpu_type_ids, num_vgpu_types;
    NvBool isMdevAttached = NV_FALSE;


#ifdef NV_PCI_SRIOV_SUPPORT
    if (pci_dev->is_virtfn)
        parent_device = pci_dev->physfn;
    else
#endif /* NV_PCI_SRIOV_SUPPORT */

        parent_device = pci_dev;

    nvl = pci_get_drvdata(parent_device);

    if (!nvl || (nvl->pci_dev != parent_device))
        return NV_ERR_OBJECT_NOT_FOUND;

    nv = NV_STATE_PTR(nvl);

    if (nv_kmem_cache_alloc_stack(&sp) != 0)
        return NV_ERR_NO_MEMORY;

    if (vgpu_vfio_ops && vgpu_vfio_ops->probe)
    {
        status = nv_vgpu_get_type_ids(sp, nv, &num_vgpu_types, &vgpu_type_ids, pci_dev->is_virtfn);
        if (status == NV_OK)
        {
            if (num_vgpu_types != 0)
            {
                status = vgpu_vfio_ops->probe(pci_dev, num_vgpu_types, vgpu_type_ids);
                if (status == NV_OK)
                {
                    isMdevAttached = NV_TRUE;

                    if (parent_device == pci_dev)
                    {
                        if ((status = nv_gpu_bind_event(sp)) != NV_OK)
                        {
                            /* Arg 2 == NV_TRUE means that the PCI device should be removed */
                            nvidia_vgpu_vfio_remove(pci_dev, NV_TRUE);
                        }
                    }
                }
                os_free_mem(vgpu_type_ids);
            }
            else if (parent_device == pci_dev)
                status = nv_gpu_bind_event(sp);
        }
    }


#ifdef NV_PCI_SRIOV_SUPPORT
    if (pci_dev->is_virtfn)
    {
        status = nv_vgpu_process_vf_info(sp, nv,
                                         NV_VGPU_SAVE_VF_INFO,
                                         NV_PCI_DOMAIN_NUMBER(pci_dev),
                                         NV_PCI_BUS_NUMBER(pci_dev),
                                         NV_PCI_SLOT_NUMBER(pci_dev),
                                         PCI_FUNC(pci_dev->devfn),
                                         isMdevAttached,
                                         NULL);
        if (status != NV_OK)
        {
            nv_printf(NV_DBG_ERRORS,"NVRM: Failed to store VF info 0x%x\n",
                      status);
        }
    }

#endif /* NV_PCI_SRIOV_SUPPORT */


    nv_kmem_cache_free_stack(sp);

#ifdef NV_PCI_SRIOV_SUPPORT
    if (!(pci_dev->is_virtfn))
    {
        revive_vfs(pci_dev);
    }
#endif /* NV_PCI_SRIOV_SUPPORT */

    return status;
}

static void remove_vfs(struct pci_dev *pci_dev)
{
    nv_linux_state_t *nvl;
    nvidia_stack_t *sp = NULL;

    vgpu_vf_pci_info vf_pci_info[MAX_VF_COUNT_PER_GPU];
    unsigned int i;

    for (i = 0; i < MAX_VF_COUNT_PER_GPU; i++)
    {
        vf_pci_info[i].isNvidiaAttached = NV_FALSE;
        vf_pci_info[i].isMdevAttached   = NV_FALSE;
    }

    if (nv_kmem_cache_alloc_stack(&sp) != 0)
    {
        return;
    }

    nvl = pci_get_drvdata(pci_dev);

    if (nvl)
    {
        NV_STATUS status = nv_vgpu_process_vf_info(sp, NV_STATE_PTR(nvl),
                                                   NV_VGPU_GET_VF_INFO,
                                                   0, 0, 0, 0,
                                                   NV_FALSE,
                                                   (void *) vf_pci_info);
        if (status != NV_OK)
        {
            nv_printf(NV_DBG_ERRORS,"NVRM: Failed to get VF info from PF 0x%x\n", status);

            nv_kmem_cache_free_stack(sp);
            return;
        }

        for (i = 0; i < MAX_VF_COUNT_PER_GPU; i++)
        {
            if (vf_pci_info[i].isNvidiaAttached && vf_pci_info[i].isMdevAttached)
            {
                unsigned int devfn;
                struct pci_dev *vf_pci_dev;

                devfn = PCI_DEVFN(vf_pci_info[i].slot, vf_pci_info[i].function);
                vf_pci_dev = NV_GET_DOMAIN_BUS_AND_SLOT(vf_pci_info[i].domain, vf_pci_info[i].bus, devfn);

                if (vf_pci_dev)
                {
                    pci_dev_put(vf_pci_dev);
                    if (vgpu_vfio_ops && vgpu_vfio_ops->remove)
                    {
                        nv_printf(NV_DBG_INFO, "NVRM: %s: Removing VF %04x:%02x:%02x.%x before PF\n",
                                  __FUNCTION__,
                                  NV_PCI_DOMAIN_NUMBER(vf_pci_dev),
                                  NV_PCI_BUS_NUMBER(vf_pci_dev),
                                  NV_PCI_SLOT_NUMBER(vf_pci_dev),
                                  PCI_FUNC(vf_pci_dev->devfn));
                        /* Arg 2 == NV_FALSE means that the PCI device should not be removed */
                        nvidia_vgpu_vfio_remove(vf_pci_dev, NV_FALSE);
                    }
                }
            }
        }
    }
    nv_kmem_cache_free_stack(sp);
}

void nvidia_vgpu_vfio_remove(struct pci_dev *pci_dev, NvBool pci_remove)
{
#ifdef NV_PCI_SRIOV_SUPPORT
    if (!pci_dev->is_virtfn)
    {
        remove_vfs(pci_dev);
    }
#endif /* NV_PCI_SRIOV_SUPPORT */

    if (vgpu_vfio_ops && vgpu_vfio_ops->remove)
        vgpu_vfio_ops->remove(pci_dev);


#ifdef NV_PCI_SRIOV_SUPPORT
    if (pci_dev->is_virtfn)
    {
        nv_linux_state_t *nvl;
        nvidia_stack_t *sp = NULL;

        if (nv_kmem_cache_alloc_stack(&sp) != 0)
            return;

        nvl = pci_get_drvdata(pci_dev->physfn);

        if (nvl)
        {
            /* Remove PCI flag only if removal was initiated by kernel */
            NvU8 cmd = pci_remove ? NV_VGPU_REMOVE_VF_PCI_INFO : NV_VGPU_REMOVE_VF_MDEV_INFO;

            NV_STATUS status = nv_vgpu_process_vf_info(sp, NV_STATE_PTR(nvl),
                                                       cmd,
                                                       NV_PCI_DOMAIN_NUMBER(pci_dev),
                                                       NV_PCI_BUS_NUMBER(pci_dev),
                                                       NV_PCI_SLOT_NUMBER(pci_dev),
                                                       PCI_FUNC(pci_dev->devfn),
                                                       NV_FALSE,
                                                       NULL);
            if (status != NV_OK)
                nv_printf(NV_DBG_ERRORS,"NVRM: Failed to delete VF info from PF 0x%x\n",
                          status);
        }
        nv_kmem_cache_free_stack(sp);
    }
#endif /* NV_PCI_SRIOV_SUPPORT */

}

void nvidia_isr_msix_prologue(nv_linux_state_t *nvl)
{
    nv_state_t *nv = NV_STATE_PTR(nvl);
    NvU32 *msix_ctrl = (int *)((char *)(nv->regs->map) + NV_MSIX_CAP_BASE);
    NvU32 msix_ctrl_temp;

    // Increment the per device global variable to track nested interrupts.
    atomic_inc(&nvl->msix_ref_cnt);

    // Mask MSIX interrupts only if it was not masked earlier by a lower IRQL interrupt.
    msix_ctrl_temp = *msix_ctrl;
    if (!(msix_ctrl_temp & NV_MSIX_CAP_FUNCTION_MASKALL))
        *msix_ctrl = msix_ctrl_temp | NV_MSIX_CAP_FUNCTION_MASKALL;

    // Enable interrupts on this CPU, to allow any higher priority interrupt to preempt us.
    local_irq_enable();

    // Do an MMIO read to flush any in-flight interrupts.
    msix_ctrl_temp = *msix_ctrl;
}

void nvidia_isr_msix_epilogue(nv_linux_state_t *nvl)
{
    nv_state_t *nv = NV_STATE_PTR(nvl);
    NvU32 *msix_ctrl = (int *)((char *)(nv->regs->map) + NV_MSIX_CAP_BASE);

    // Unmask the MSIX interrupts after servicing both the nested ISRs.
    if (atomic_dec_and_test(&nvl->msix_ref_cnt))
        *msix_ctrl &= ~NV_MSIX_CAP_FUNCTION_MASKALL;
}

#if defined(NV_VGPU_KVM_BUILD)
NV_STATUS NV_API_CALL os_call_vgpu_vfio(void *pvgpu_vfio_info, NvU32 cmd)
{
    NV_STATUS          status = NV_OK;
    vgpu_vfio_info    *pinfo  = (vgpu_vfio_info *)pvgpu_vfio_info;
    nv_linux_state_t  *nvl;
    struct pci_dev    *pci_dev = NULL;

    switch (cmd)
    {
        case CMD_VGPU_VFIO_WAKE_WAIT_QUEUE:
            wake_up_interruptible((wait_queue_head_t *)pinfo->waitQueue);
            break;
        case CMD_VGPU_VFIO_INJECT_INTERRUPT:
            status = vgpu_vfio_ops->inject_interrupt(pinfo->vgpuVfioRef);
            break;
        case CMD_VGPU_VFIO_REGISTER_MDEV:
            // If probe received for VF, fetch it's pci_dev struct from its BDF
            if (pinfo->is_virtfn)
            {
                unsigned int devfn = PCI_DEVFN(pinfo->slot, pinfo->function);
                pci_dev = NV_GET_DOMAIN_BUS_AND_SLOT(pinfo->domain, pinfo->bus, devfn);
                if (pci_dev == NULL)
                {
                    nv_printf(NV_DBG_ERRORS,
                              "NVRM: Failed to fetch VF details\n");
                    status = NV_ERR_OBJECT_NOT_FOUND;
                    break;
                }
                pci_dev_put(pci_dev);
            }
            else
            {
                nvl = NV_GET_NVL_FROM_NV_STATE(((nv_state_t *)pinfo->nv));
                pci_dev = nvl->pci_dev;
            }

            if (vgpu_vfio_ops && vgpu_vfio_ops->probe)
                status = vgpu_vfio_ops->probe(pci_dev, pinfo->numVgpuTypes,
                                              pinfo->vgpuTypeIds);

            if (status != NV_OK)
                nv_printf(NV_DBG_ERRORS,
                          "NVRM: Failed to register device to vGPU VFIO module 0x%x\n",
                          status);
            break;
        case CMD_VGPU_VFIO_PRESENT:
            status = NV_OK;
            break;
        default:
            nv_printf(NV_DBG_ERRORS, "NVRM: Invalid vGPU VFIO command");
            return NV_ERR_INVALID_ARGUMENT;
    }

    return status;
}
#endif

