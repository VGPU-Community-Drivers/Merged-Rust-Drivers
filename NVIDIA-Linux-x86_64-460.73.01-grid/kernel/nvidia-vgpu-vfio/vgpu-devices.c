/*
 * Copyright (c) 2019-2020, NVIDIA CORPORATION. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/err.h>
#include "nvstatus.h"
#include "nv-misc.h"
#include "nv-linux.h"
#include "vgpu-devices.h"

#if defined(NV_VGPU_KVM_BUILD)

int major_num = 0;

struct file_operations vgpu_dev_ops = {
    .owner  = THIS_MODULE,
    .open = nv_vgpu_dev_open,
    .release = nv_vgpu_dev_close,
    .unlocked_ioctl = nv_vgpu_dev_ioctl,
    .poll = nv_vgpu_dev_poll,
    .mmap = nv_vgpu_dev_mmap,
};

NV_STATUS nv_create_vgpu_chardev(vgpu_dev_t *vgpu_dev)
{
    int ret = 0;
    dev_t devno = MKDEV(major_num, vgpu_dev->vgpu_id);

    cdev_init(&vgpu_dev->cdev, &vgpu_dev_ops);
    vgpu_dev->cdev.owner = THIS_MODULE;

    ret = cdev_add(&vgpu_dev->cdev, devno, 1);
    if (ret != 0)
    {
        NV_VGPU_DEV_LOG(VGPU_ERR, vgpu_dev->mdev,
                        "Failed to add character device to system: %d \n", ret);
        return NV_ERR_OPERATING_SYSTEM;
    }

    return NV_OK;
}

void nv_remove_vgpu_chardev(vgpu_dev_t *vgpu_dev)
{
    cdev_del(&vgpu_dev->cdev);
}

NV_STATUS nv_alloc_chardev_region(void)
{
    int ret;
    dev_t dev;

    //allocate major and minor number
    ret = alloc_chrdev_region(&dev, 0, NV_MAX_VGPU_ID, "nvidia-vgpu-vfio");
    if (ret < 0)
    {
        NV_VGPU_LOG(VGPU_ERR, "Failed to allocate chrdev region: %d \n", ret);
        return NV_ERR_OPERATING_SYSTEM;
    }
    major_num = MAJOR(dev);
    return NV_OK;
}

void nv_unregister_chardev_region(void)
{
    if (major_num != 0)
    {
        unregister_chrdev_region(MKDEV(major_num, 0),
                                 NV_MAX_VGPU_ID);
    }
}

int nv_vgpu_dev_open(struct inode *inode, struct file *filp)
{
    vgpu_dev_t *vgpu_dev = NULL;
    vgpu_file_private_t *vgpu_fp = NULL;

    vgpu_dev = container_of(inode->i_cdev, vgpu_dev_t, cdev);
    if (vgpu_dev == NULL)
        return -EINVAL;

    NV_KMALLOC(vgpu_fp, sizeof(vgpu_file_private_t));
    if (vgpu_fp == NULL)
        return -ENOMEM;

    down(&vgpu_dev->dev_lock);

    vgpu_dev->vgpu_task = current;
    INIT_LIST_HEAD(&vgpu_fp->next);
    list_add(&vgpu_fp->next, &vgpu_dev->file_private_list);
    vgpu_fp->vgpu_dev = vgpu_dev;
    vgpu_fp->event = NULL;
    filp->private_data = vgpu_fp;
    INIT_LIST_HEAD(&vgpu_dev->dirty_pfn_reported_list);

    up(&vgpu_dev->dev_lock);

    return 0;
}

NV_STATUS nv_vfio_vgpu_event_create(vgpu_file_private_t *vgpu_fp, NvU32 event_type)
{
    vgpu_dev_t *vgpu_dev = vgpu_fp->vgpu_dev;
    vgpu_event_t *vgpu_event = NULL;
    NV_STATUS status = NV_OK;

    if (vgpu_dev == NULL)
        return NV_ERR_INVALID_DATA;

    if (vgpu_fp->event != NULL)
    {
        status = NV_ERR_INVALID_EVENT;
        goto create_event_err;
    }

    if (event_type >= NV_VFIO_VGPU_EVENT_MAX_COUNT)
    {
        status = NV_ERR_INVALID_ARGUMENT;
        goto create_event_err; 

    }

    NV_KMALLOC(vgpu_event, sizeof(vgpu_event_t));
    if (vgpu_event == NULL)
    {
        status = NV_ERR_NO_MEMORY;
        goto create_event_err;
    }

    init_waitqueue_head(&vgpu_event->wait);
    NV_SPIN_LOCK_INIT(&vgpu_event->lock);
    vgpu_event->type = event_type;
    vgpu_event->pending = NV_FALSE;
    vgpu_fp->event = vgpu_event;

#if defined(NV_VFIO_DEVICE_MIGRATION_INFO_PRESENT)
    if (event_type == NV_VFIO_VGPU_EVENT_MIGRATION_STATE) {
  #if defined(NV_VFIO_DEVICE_MIGRATION_HAS_START_PFN)
        vgpu_dev->migration_enabled = NV_TRUE;
        NV_VGPU_DEV_LOG(VGPU_ERR, vgpu_dev->mdev,
                        "vGPU migration enabled with v3.2 Kernel UAPI\n");
  #elif defined(NV_KVM_MIGRATION_UAPI)
        vgpu_dev->migration_enabled = NV_TRUE;
        NV_VGPU_DEV_LOG(VGPU_ERR, vgpu_dev->mdev,
                        "vGPU migration enabled with upstreamed Kernel UAPI\n");
  #else
        NV_VGPU_DEV_LOG(VGPU_ERR, vgpu_dev->mdev,
                        "vGPU migration disabled\n");
  #endif
    }
#else
        NV_VGPU_DEV_LOG(VGPU_ERR, vgpu_dev->mdev,
                        "vGPU migration disabled\n");
#endif

create_event_err:
    if (status != NV_OK)
        NV_VGPU_DEV_LOG(VGPU_ERR, vgpu_dev->mdev,
                        "Event creation failed. id: 0x%x status: 0x%x\n",
                        event_type, status);

    return status;
}

NV_STATUS nv_vfio_vgpu_event_destroy(vgpu_file_private_t *vgpu_fp, NvU32 event_type)
{
    NV_STATUS status = NV_OK;
    vgpu_dev_t *vgpu_dev = vgpu_fp->vgpu_dev;

    if (vgpu_dev == NULL)
        return NV_ERR_INVALID_DATA;

    if (vgpu_fp->event == NULL)
    {
        status = NV_ERR_OBJECT_NOT_FOUND;
        goto destroy_event_err;
    }

    if (event_type != vgpu_fp->event->type)
    {
        status = NV_ERR_INVALID_EVENT;
        goto destroy_event_err;
    }

    NV_KFREE(vgpu_fp->event, sizeof(vgpu_event_t));
    vgpu_fp->event = NULL;

destroy_event_err:
    if (status != NV_OK)
        NV_VGPU_DEV_LOG(VGPU_ERR, vgpu_dev->mdev,
                        "Event destroy failed. id: 0x%x status: 0x%x\n",
                        event_type, status);
    return status;
}

int nv_vgpu_dev_close(struct inode *inode, struct file *filp)
{
    vgpu_dev_t *vgpu_dev = NULL;
    vgpu_file_private_t *vgpu_fp = NULL;
    vgpu_dirty_pfn_t *dpfns, *tmp;

    if (filp == NULL)
        return -EINVAL;

    vgpu_fp = filp->private_data;
    if (vgpu_fp == NULL)
        return -EINVAL;

    vgpu_dev = vgpu_fp->vgpu_dev;
    if (vgpu_dev == NULL)
       return -EINVAL;

    down(&vgpu_dev->dev_lock);
    list_del(&vgpu_fp->next);
    filp->private_data = NULL;
    if (!list_empty(&vgpu_dev->dirty_pfn_reported_list)) {
        list_for_each_entry_safe(dpfns, tmp, &vgpu_dev->dirty_pfn_reported_list, next) {
            list_del(&dpfns->next);
            NV_KFREE(dpfns, sizeof(vgpu_dirty_pfn_t));
        }
    }

    up(&vgpu_dev->dev_lock);

    if (vgpu_fp->event != NULL)
        NV_KFREE((vgpu_fp->event), sizeof(vgpu_event_t));

    NV_KFREE(vgpu_fp, sizeof(vgpu_file_private_t));
    return 0;
}

long nv_vgpu_dev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    vgpu_dev_t *vgpu_dev = NULL;
    vgpu_file_private_t *vgpu_fp;
    NV_STATUS status = NV_ERR_INVALID_ARGUMENT;
    NV_VGPU_DEV_IOCTL_PARAMS ioctl_params;
    long ret = 0;

    if (filp && filp->private_data)
    {
        vgpu_fp = (vgpu_file_private_t *) filp->private_data;
        vgpu_dev = (vgpu_dev_t *) vgpu_fp->vgpu_dev;
        if (vgpu_dev == NULL)
            return -EIO;
    }
    else
        return -EINVAL;

    status = nv_vgpu_copy_from_user(&ioctl_params, (void __user *)arg,
                                    sizeof(ioctl_params));
    if (status != NV_OK)
        return -EIO;

    down(&vgpu_dev->dev_lock);
    switch(cmd)
    {
        NV_VGPU_VFIO_ROUTE_CMD(NV_VFIO_VGPU_PIN_PAGES,
                               NV_VFIO_VGPU_PIN_PAGES_PARAMS,
                               nv_vfio_vgpu_pin_pages);
        NV_VGPU_VFIO_ROUTE_CMD(NV_VFIO_VGPU_UNPIN_PAGES,
                               NV_VFIO_VGPU_UNPIN_PAGES_PARAMS,
                               nv_vfio_vgpu_unpin_pages);
        NV_VGPU_VFIO_ROUTE_CMD(NV_VFIO_VGPU_REG_ACCESS_GET_DATA,
                               NV_VFIO_VGPU_REG_ACCESS_GET_DATA_PARAMS,
                               nv_vfio_vgpu_reg_get_data);
        NV_VGPU_VFIO_ROUTE_CMD(NV_VFIO_VGPU_REG_ACCESS_SET_DATA,
                               NV_VFIO_VGPU_REG_ACCESS_SET_DATA_PARAMS,
                               nv_vfio_vgpu_reg_set_data);
        NV_VGPU_VFIO_ROUTE_CMD(NV_VFIO_VGPU_ADD_MMIO_MAPPING,
                               NV_VFIO_VGPU_MMIO_MAPPING_PARAMS,
                               nv_vfio_vgpu_add_mmio_mapping);
        NV_VGPU_VFIO_ROUTE_CMD(NV_VFIO_VGPU_REMOVE_MMIO_MAPPING,
                               NV_VFIO_VGPU_MMIO_MAPPING_PARAMS,
                               nv_vfio_vgpu_remove_mmio_mapping);
        NV_VGPU_VFIO_ROUTE_CMD(NV_VFIO_VGPU_NOTIFY_POWER_OP,
                               NV_VFIO_VGPU_NOTIFY_POWER_OP_PARAMS,
                               nv_vfio_vgpu_notify_power_op);
        NV_VGPU_VFIO_ROUTE_CMD(NV_VFIO_VGPU_GET_ATTACH_DEVICE_DATA,
                               NV_VFIO_VGPU_GET_ATTACH_DEVICE_DATA_PARAMS,
                               nv_vfio_vgpu_get_attach_device);
        NV_VGPU_VFIO_ROUTE_CMD(NV_VFIO_VGPU_ATTACH_DEVICE_ACK,
                               NV_VFIO_VGPU_ATTACH_DEVICE_ACK_PARAMS,
                               nv_vfio_vgpu_attach_device_ack);

        NV_VGPU_VFIO_ROUTE_CMD_NO_PARAMS(NV_VFIO_VGPU_INJECT_INTERRUPT,
                                         nv_vfio_vgpu_inject_interrupt);

        NV_VGPU_VFIO_HANDLE_EVENT(NV_VFIO_VGPU_EVENT_CREATE,
                                  NV_VFIO_VGPU_EVENT_PARAMS,
                                  nv_vfio_vgpu_event_create);
        NV_VGPU_VFIO_HANDLE_EVENT(NV_VFIO_VGPU_EVENT_DESTROY,
                                  NV_VFIO_VGPU_EVENT_PARAMS,
                                  nv_vfio_vgpu_event_destroy);

        NV_VGPU_VFIO_ROUTE_CMD(NV_VFIO_VGPU_ALLOC_CONSOLE_BUFFER,
                               NV_VFIO_VGPU_CONSOLE_BUFFER_PARAMS,
                               nv_vfio_vgpu_alloc_console_buffer);
        NV_VGPU_VFIO_ROUTE_CMD_NO_PARAMS(NV_VFIO_VGPU_FREE_CONSOLE_BUFFER,
                               nv_vfio_vgpu_free_console_buffer);
        NV_VGPU_VFIO_ROUTE_CMD(NV_VFIO_VGPU_SET_CONSOLE_SURFACE_PROP,
                               NV_VFIO_VGPU_CONSOLE_SURFACE_PARAMS,
                               nv_vfio_vgpu_set_console_suface_properties);
        NV_VGPU_VFIO_ROUTE_CMD(NV_VFIO_VGPU_GET_MIGRATION_STATE,
                               NV_VFIO_VGPU_MIGRATION_STATE_PARAMS,
                               nv_vfio_vgpu_get_migration_state);
        NV_VGPU_VFIO_ROUTE_CMD(NV_VFIO_VGPU_NOTIFY_MIGRATION_STATE_STATUS,
                               NV_VFIO_VGPU_NOTIFY_MIGRATION_STATE_STATUS_PARAMS,
                               nv_vfio_vgpu_notify_migration_state_status);
        NV_VGPU_VFIO_ROUTE_CMD(NV_VFIO_VGPU_GET_MIGRATION_BUFFER_SIZE,
                               NV_VFIO_VGPU_MIGRATION_BUFFER_SIZE_PARAMS,
                               nv_vfio_vgpu_get_migration_buffer_size);
        NV_VGPU_VFIO_ROUTE_CMD(NV_VFIO_VGPU_SET_MIGRATION_BUFFER_SIZE,
                               NV_VFIO_VGPU_MIGRATION_BUFFER_SIZE_PARAMS,
                               nv_vfio_vgpu_set_migration_buffer_size);

        NV_VGPU_VFIO_ROUTE_CMD(NV_VFIO_VGPU_VF_REG_ACCESS_HW,
                               NV_VFIO_VGPU_VF_REG_ACCESS_HW_PARAMS,
                               nv_vfio_vgpu_vf_reg_access_hw);


        default:
            NV_VGPU_DEV_LOG(VGPU_ERR, vgpu_dev->mdev, "IOCTL not found "
                            "cmd: 0x%x \n", cmd);
            status = NV_ERR_INVALID_COMMAND;
    }
    ioctl_params.status = status;

    up(&vgpu_dev->dev_lock);

    if (nv_vgpu_copy_to_user((void __user *)arg, &ioctl_params,
                             sizeof(ioctl_params)) != NV_OK)
        ret = -EIO;

    return ret;
}

unsigned int nv_vgpu_dev_poll(struct file *filp, poll_table *wait)
{
    vgpu_file_private_t *vgpu_fp;
    vgpu_event_t *vgpu_event;
    int ret = 0;
    unsigned long eflags;

    if (filp && filp->private_data)
    {
        vgpu_fp = (vgpu_file_private_t *)filp->private_data;
        vgpu_event = vgpu_fp->event;
    }
    else
        return -EINVAL;

    if ((filp->f_flags & O_NONBLOCK) == 0)
        poll_wait(filp, &vgpu_event->wait, wait);

    NV_SPIN_LOCK_IRQSAVE(&vgpu_event->lock, eflags);
    if (vgpu_event->pending == NV_TRUE)
    {
        ret = (POLLPRI | POLLIN);
        vgpu_event->pending = NV_FALSE;
    }
    NV_SPIN_UNLOCK_IRQRESTORE(&vgpu_event->lock, eflags);

    return ret;
}

int nv_vgpu_dev_mmap(struct file *file, struct vm_area_struct *vma)
{
    vgpu_dev_t *vgpu_dev = NULL;
    int ret = -EINVAL;
    NvU32 index;

    if (file && file->private_data)
    {
        vgpu_file_private_t *vgpu_fp;

        vgpu_fp = (vgpu_file_private_t *)file->private_data;
        vgpu_dev = (vgpu_dev_t *) vgpu_fp->vgpu_dev;
    }
    else
        return -EINVAL;

    down(&vgpu_dev->dev_lock);

    index = DRF_VAL64(_VGPU_VFIO, _PGOFF, _PCI_INDEX, (vma->vm_pgoff << PAGE_SHIFT));

    if (index == NV_VGPU_DEVICE_CONSOLE_REGION)
    {
        if (!vgpu_dev->console.surface) {
            NV_VGPU_DEV_LOG(VGPU_ERR, vgpu_dev->mdev,
                            "Console surface not allocated \n");
            goto mmap_exit;
        }

        ret = remap_vmalloc_range(vma, vgpu_dev->console.surface, 0);
        if (ret) {
            NV_VGPU_DEV_LOG(VGPU_ERR, vgpu_dev->mdev,
                            "remap_vmalloc_range failed for console surface ret=%d\n",
                            ret);
        }
    }
    else if (index == NV_VGPU_DEVICE_MIGRATION_REGION)
    {
        if (!vgpu_dev->mig_buffer_base) {
             NV_VGPU_DEV_LOG(VGPU_ERR, vgpu_dev->mdev,
                            "Migration buffer not allocated \n");
            goto mmap_exit;
        }

        ret = remap_vmalloc_range(vma, vgpu_dev->mig_buffer_base, 0);
        if (ret) {
            NV_VGPU_DEV_LOG(VGPU_ERR, vgpu_dev->mdev,
                            "remap_vmalloc_range failed for migration buffer %d\n",
                            ret);
        }
    }
    else if (index == NV_VGPU_DEVICE_STAGING_REGION)
    {
        if (!vgpu_dev->staging_buf_base) {
             NV_VGPU_DEV_LOG(VGPU_ERR, vgpu_dev->mdev,
                            "Staging buffer not allocated \n");
            goto mmap_exit;
        }

        ret = remap_vmalloc_range(vma, vgpu_dev->staging_buf_base, 0);
        if (ret) {
            NV_VGPU_DEV_LOG(VGPU_ERR, vgpu_dev->mdev,
                            "remap_vmalloc_range failed for staging buffer %d\n",
                            ret);
        }
    }
    else
    {
        NV_VGPU_DEV_LOG(VGPU_ERR, vgpu_dev->mdev, "Invalid region for mmap \n");
    }

mmap_exit:
    up(&vgpu_dev->dev_lock);

    return ret;
}

NV_STATUS nv_vgpu_dev_post_event(vgpu_dev_t *vgpu_dev, NvU32 event_type)
{
    unsigned long eflags;
    NV_STATUS status = NV_OK;
    vgpu_file_private_t *vgpu_fp = NULL;
    vgpu_event_t *vgpu_event = NULL;

    down(&vgpu_dev->dev_lock);
    if(list_empty(&vgpu_dev->file_private_list))
    {
        up(&vgpu_dev->dev_lock);
        return NV_ERR_NOT_SUPPORTED;
    }

    list_for_each_entry(vgpu_fp, &vgpu_dev->file_private_list, next)
    {
        if (vgpu_fp && vgpu_fp->event && (vgpu_fp->event->type == event_type))
            break;
    }

    if ((vgpu_fp == NULL) || (vgpu_fp->event == NULL) ||
        (&vgpu_fp->next == &vgpu_dev->file_private_list))
        status = NV_ERR_OBJECT_NOT_FOUND;

    up(&vgpu_dev->dev_lock);

    if (status != NV_OK)
        return status;

    vgpu_event = vgpu_fp->event;

    NV_SPIN_LOCK_IRQSAVE(&vgpu_event->lock, eflags);
    vgpu_event->pending = NV_TRUE;
    NV_SPIN_UNLOCK_IRQRESTORE(&vgpu_event->lock, eflags);

    wake_up_interruptible(&vgpu_event->wait);

    return NV_OK;
}

NV_STATUS nv_vgpu_copy_from_user(void *pkernel_params, void *puser_params,
                                 unsigned long size)
{
    unsigned long ret;

    if (!pkernel_params && !puser_params)
        return NV_ERR_INVALID_ARGUMENT;

    if (size > NV_VGPU_VFIO_MAX_PARAMS_SIZE)
        return NV_ERR_INVALID_ARGUMENT;

    ret = copy_from_user(pkernel_params, (void __user *)puser_params, size);
    if (ret != 0)
        return NV_ERR_INVALID_DATA;

    return NV_OK;
}

NV_STATUS nv_vgpu_copy_to_user(void *puser_params, void *pkernel_params,
                               unsigned long size)
{
    unsigned long ret;

    if (!pkernel_params && !puser_params)
        return NV_ERR_INVALID_ARGUMENT;

    if (size > NV_VGPU_VFIO_MAX_PARAMS_SIZE)
        return NV_ERR_INVALID_ARGUMENT;

    ret = copy_to_user((void __user *) puser_params, pkernel_params, size);
    if (ret != 0)
        return NV_ERR_INVALID_DATA;

    return NV_OK;
}

NV_STATUS nv_vfio_vgpu_pin_pages(void *cmd_params,
                                 vgpu_dev_t *vgpu_dev)
{
    NV_VFIO_VGPU_PIN_PAGES_PARAMS *pParams = cmd_params;
    NV_STATUS status;
    NvU64 *pgpfn_buffer = NULL, *phpfn_buffer = NULL, size;
#if !defined(NV_KVMALLOC_PRESENT)
    NvBool is_gpfn_vmalloc, is_hpfn_vmalloc;
#endif

    size = sizeof(NvU64) * pParams->pageCount;

    NV_MEM_ALLOC(pgpfn_buffer, size, is_gpfn_vmalloc);
    if (pgpfn_buffer == NULL)
    {
        status = NV_ERR_NO_MEMORY;
        goto exit;
    }

    NV_MEM_ALLOC(phpfn_buffer, size, is_hpfn_vmalloc);
    if (phpfn_buffer == NULL)
    {
        status = NV_ERR_NO_MEMORY;
        goto exit;
    }

    status = nv_vgpu_copy_from_user(pgpfn_buffer, pParams->pGuestPfnMem, size);
    if (status != NV_OK)
        goto exit;

    status = nv_vgpu_translate_gfn_to_pfn(pgpfn_buffer, phpfn_buffer,
                                          pParams->pageCount, vgpu_dev,
                                          pParams->addrType);
    if (status != NV_OK)
        goto exit;

    status = nv_vgpu_copy_to_user(pParams->pHostPfnMem, phpfn_buffer, size);

exit:
    if (pgpfn_buffer != NULL)
        NV_MEM_FREE(pgpfn_buffer, size, is_gpfn_vmalloc);

    if (phpfn_buffer != NULL)
        NV_MEM_FREE(phpfn_buffer, size, is_hpfn_vmalloc);

    return status;
}

NV_STATUS nv_vfio_vgpu_unpin_pages(void *cmd_params, vgpu_dev_t *vgpu_dev)
{
    NV_VFIO_VGPU_UNPIN_PAGES_PARAMS *pParams = cmd_params;
    NV_STATUS status;
    NvU64 *pgpfn_buffer = NULL, size;
#if !defined(NV_KVMALLOC_PRESENT)
    NvBool is_gpfn_vmalloc;
#endif

    size = sizeof(NvU64) * pParams->pageCount;

    NV_MEM_ALLOC(pgpfn_buffer, size, is_gpfn_vmalloc);
    if (pgpfn_buffer == NULL)
    {
        status = NV_ERR_NO_MEMORY;
        goto exit;
    }

    status = nv_vgpu_copy_from_user(pgpfn_buffer, pParams->pGuestPfnMem, size);
    if (status != NV_OK)
        goto exit;

    status = nv_vgpu_unpin_pages(pgpfn_buffer, pParams->pageCount,
                                 vgpu_dev, pParams->addrType);

exit:
    if (pgpfn_buffer != NULL)
        NV_MEM_FREE(pgpfn_buffer, size, is_gpfn_vmalloc);

    return status;
}

NV_STATUS nv_vfio_vgpu_reg_get_data(void *cmd_params, vgpu_dev_t *vgpu_dev)
{
    NV_VFIO_VGPU_REG_ACCESS_GET_DATA_PARAMS *pParams = cmd_params;

    pParams->offset = vgpu_dev->reg_info.offset;
    pParams->width = vgpu_dev->reg_info.count;
    pParams->emulSpace = vgpu_dev->reg_info.emul_space;
    pParams->isWrite = vgpu_dev->reg_info.is_write;

    if (vgpu_dev->reg_info.is_write == NV_TRUE)
        memcpy((void *)pParams->data, (void *)vgpu_dev->reg_info.data,
               pParams->width);

    return NV_OK;
}

NV_STATUS nv_vfio_vgpu_reg_set_data(void *cmd_params, vgpu_dev_t *vgpu_dev)
{
    NV_VFIO_VGPU_REG_ACCESS_SET_DATA_PARAMS *pParams = cmd_params;

    if (vgpu_dev->reg_info.is_write == NV_FALSE)
        memcpy(vgpu_dev->reg_info.data, pParams->data,
               vgpu_dev->reg_info.count);

    vgpu_dev->reg_info.status = pParams->returnStatus;
    wake_up_interruptible(&vgpu_dev->reg_info.wait);

    return NV_OK;
}

NV_STATUS nv_vfio_vgpu_add_mmio_mapping(void *cmd_params, vgpu_dev_t *vgpu_dev)
{
    NV_VFIO_VGPU_MMIO_MAPPING_PARAMS *pParams = cmd_params;
    return nv_vgpu_update_mapping(vgpu_dev, pParams->virtualMMIOStart,
                                  pParams->physicalMMIOStart, pParams->mmioSize,
                                  NV_TRUE, NV_FALSE);

}

NV_STATUS nv_vfio_vgpu_remove_mmio_mapping(void *cmd_params, vgpu_dev_t *vgpu_dev)
{
    NV_VFIO_VGPU_MMIO_MAPPING_PARAMS *pParams = cmd_params;

    return nv_vgpu_update_mapping(vgpu_dev, pParams->virtualMMIOStart,
                                  pParams->physicalMMIOStart, pParams->mmioSize,
                                  NV_FALSE, NV_FALSE);
}

NV_STATUS nv_vfio_vgpu_inject_interrupt(vgpu_dev_t *vgpu_dev)
{
    return nv_vgpu_inject_interrupt(vgpu_dev);
}

NV_STATUS nv_vfio_vgpu_notify_power_op(void *cmd_params, vgpu_dev_t *vgpu_dev)
{
    NV_VFIO_VGPU_NOTIFY_POWER_OP_PARAMS *pParams = cmd_params;

    if (vgpu_dev->return_status == -1)
    {
        vgpu_dev->return_status = pParams->returnStatus;
        wake_up_interruptible(&vgpu_dev->wait_queue);
        return NV_OK;
    }
    else
    {
        NV_VGPU_DEV_LOG(VGPU_ERR, vgpu_dev->mdev, "Power op failed \n");
        return NV_ERR_INVALID_STATE;
    }
}

NV_STATUS nv_vfio_vgpu_get_attach_device(void *cmd_params, vgpu_dev_t *vgpu_dev)
{
    NV_VFIO_VGPU_GET_ATTACH_DEVICE_DATA_PARAMS *pParams = cmd_params;
    vgpu_dev_t *vgpu_dev_temp = NULL;
    char mdev_params[VGPU_CONFIG_PARAMS_MAX_LENGTH] = {0};
    NV_STATUS ret = NV_ERR_INVALID_STATE;

    down(&vgpu_devices.vgpu_dev_list_lock);
    list_for_each_entry(vgpu_dev_temp, &vgpu_devices.vgpu_dev_list, next)
    {
        if (vgpu_dev_temp->device_state == NV_VGPU_DEV_OPENED)
        {
            snprintf(mdev_params, VGPU_CONFIG_PARAMS_MAX_LENGTH, "vgpu_type_id=%d",
                     vgpu_dev_temp->vgpu_type_id);

            if (strlen(vgpu_dev_temp->config_params))
            {
                snprintf(mdev_params, VGPU_CONFIG_PARAMS_MAX_LENGTH, "%s,%s",
                          mdev_params, vgpu_dev_temp->config_params);
            }

            pParams->vgpuId     = vgpu_dev_temp->vgpu_id;
            pParams->qemuPid    = vgpu_dev_temp->qemu_pid;
            pParams->gpuPciBdf  = vgpu_dev_temp->gpu_pci_bdf;
            pParams->gpuPciId   = vgpu_dev_temp->gpu_pci_id;
            memcpy(pParams->mdevUuid, NV_GET_MDEV_UUID(vgpu_dev_temp->mdev),
                   VGPU_UUID_SIZE);
            memcpy(&pParams->configParams, mdev_params,
                   sizeof(mdev_params));
            ret = NV_OK;
            break;
        }
    }

    up(&vgpu_devices.vgpu_dev_list_lock);

    if (ret != NV_OK)
        NV_VGPU_DEV_LOG(VGPU_ERR, vgpu_dev->mdev, "Attach device failed\n");

    return ret;
}

NV_STATUS nv_vfio_vgpu_attach_device_ack(void *cmd_params, vgpu_dev_t *vgpu_dev)
{
    NV_VFIO_VGPU_ATTACH_DEVICE_ACK_PARAMS *pParams = cmd_params;
    vgpu_dev_t *vgpu_dev_temp = NULL;
    NV_STATUS ret = NV_ERR_INVALID_STATE;

    down(&vgpu_devices.vgpu_dev_list_lock);
    list_for_each_entry(vgpu_dev_temp, &vgpu_devices.vgpu_dev_list, next)
    {
        if (vgpu_dev_temp->device_state == NV_VGPU_DEV_OPENED)
        {
            vgpu_dev_temp->instance_id = pParams->instanceId;

            if (vgpu_dev_temp->return_status == -1)
            {
                /* Wake up the waitqueue of the device waiting to get attached.*/
                vgpu_dev_temp->return_status = pParams->returnStatus;
                wake_up_interruptible(&vgpu_dev_temp->wait_queue);
                ret = NV_OK;
            }
            break;
        }
    }

    up(&vgpu_devices.vgpu_dev_list_lock);

    if (ret != NV_OK)
    {
        NV_VGPU_DEV_LOG(VGPU_ERR, vgpu_dev_temp->mdev,
                        "ATTACH_DEVICE_ACK failed \n");
    }

    return ret;
}

NV_STATUS nv_vfio_vgpu_alloc_console_buffer(void *cmd_params, vgpu_dev_t *vgpu_dev)
{
#if defined(NV_VFIO_DEVICE_GFX_PLANE_INFO_PRESENT)
    NV_VFIO_VGPU_CONSOLE_BUFFER_PARAMS *pParams = cmd_params;

    if (vgpu_dev->console.surface != NULL)
        return NV_OK;

    if (pParams->size > NV_VFIO_VGPU_CONSOLE_SURFACE_SIZE_MAX)
        return NV_ERR_INVALID_PARAMETER;

    vgpu_dev->console.surface = vmalloc_user(pParams->size);
    if (vgpu_dev->console.surface == NULL)
    {
        return NV_ERR_NO_MEMORY;
    }

    vgpu_dev->console.surface_size = pParams->size;
    return NV_OK;
#else
    return NV_ERR_NOT_SUPPORTED;
#endif
}

NV_STATUS nv_vfio_vgpu_free_console_buffer(vgpu_dev_t *vgpu_dev)
{
    if (vgpu_dev->console.surface != NULL)
    {
        nv_vfree(vgpu_dev->console.surface, vgpu_dev->console.surface_size);
        vgpu_dev->console.surface = NULL;
        vgpu_dev->console.surface_size = 0;
    }
    return NV_OK;
}

NV_STATUS nv_vfio_vgpu_set_console_suface_properties(void *cmd_params, vgpu_dev_t *vgpu_dev)
{
    NV_VFIO_VGPU_CONSOLE_SURFACE_PARAMS *pParams = cmd_params;

    if (vgpu_dev->console.surface == NULL)
        return NV_ERR_INVALID_COMMAND;

    memcpy((void *)&vgpu_dev->console.surface_params,
           (void *)pParams,
           sizeof(vgpu_dev->console.surface_params));

    if (vgpu_dev->return_status == -1)
    {
        vgpu_dev->return_status = NV_OK;
        wake_up_interruptible(&vgpu_dev->wait_queue);
        return NV_OK;
    }

    NV_VGPU_DEV_LOG(VGPU_ERR, vgpu_dev->mdev, "Set console surface properties failed \n");
    return NV_ERR_INVALID_STATE;
}

NV_STATUS nv_vfio_vgpu_get_migration_state(void *cmd_params, vgpu_dev_t *vgpu_dev)
{
    NV_VFIO_VGPU_MIGRATION_STATE_PARAMS *pParams = cmd_params;

    if (vgpu_dev->return_status == -1)
    {
        pParams->deviceState = vgpu_dev->migration_state;
        return NV_OK;
    }

    return NV_ERR_INVALID_STATE;
}

NV_STATUS nv_vfio_vgpu_notify_migration_state_status(void *cmd_params, vgpu_dev_t *vgpu_dev)
{
    NV_VFIO_VGPU_NOTIFY_MIGRATION_STATE_STATUS_PARAMS *pParams = cmd_params;

    if (vgpu_dev->return_status == -1)
    {
        vgpu_dev->return_status = pParams->returnStatus;
        wake_up_interruptible(&vgpu_dev->wait_queue);

        return NV_OK;
    }

    return NV_ERR_INVALID_STATE;
}

NV_STATUS nv_vfio_vgpu_get_migration_buffer_size(void *cmd_params, vgpu_dev_t *vgpu_dev)
{
    NV_VFIO_VGPU_MIGRATION_BUFFER_SIZE_PARAMS *pParams = cmd_params;

    if (vgpu_dev->return_status == -1)
    {
        pParams->written = vgpu_dev->bytes.written;
        return NV_OK;
    }

    return NV_ERR_INVALID_STATE;
}

NV_STATUS nv_vfio_vgpu_set_migration_buffer_size(void *cmd_params, vgpu_dev_t *vgpu_dev)
{
    NV_VFIO_VGPU_MIGRATION_BUFFER_SIZE_PARAMS *pParams = cmd_params;

    vgpu_dev->bytes.pending =  pParams->pending;
    vgpu_dev->bytes.written =  pParams->written;

    if (vgpu_dev->return_status == -1)
    {
        vgpu_dev->return_status = NV_OK;
        wake_up_interruptible(&vgpu_dev->wait_queue);
        return NV_OK;
    }

    return NV_ERR_INVALID_STATE;
}


NV_STATUS nv_vfio_vgpu_vf_reg_access_hw(void *cmd_params, vgpu_dev_t *vgpu_dev)
{
    NV_VFIO_VGPU_VF_REG_ACCESS_HW_PARAMS *pParams = cmd_params;
    struct pci_dev *pdev = to_pci_dev(NV_GET_MDEV_PARENT(vgpu_dev->mdev));

    if (!pdev || !pParams->data)
        return NV_ERR_INVALID_ARGUMENT;

    return nv_vfio_vgpu_vf_reg_access_from_plugin(pdev, pParams->emulSpace, pParams->offset,
                                                  pParams->width, pParams->data, pParams->isWrite);

}


#endif /* NV_VGPU_KVM_BUILD */
