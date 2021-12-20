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

#ifndef _VGPU_DEVICE_H__
#define _VGPU_DEVICE_H__

#include "nv-vgpu-ioctl.h"
#include "nvidia-vgpu-vfio.h"

NV_STATUS     nv_create_vgpu_chardev(vgpu_dev_t *);
void          nv_remove_vgpu_chardev(vgpu_dev_t *);
NV_STATUS     nv_vgpu_dev_post_event(vgpu_dev_t *, NvU32);
NV_STATUS     nv_alloc_chardev_region(void);
void          nv_unregister_chardev_region(void);

int           nv_vgpu_dev_open(struct inode *inode, struct file *filp);
int           nv_vgpu_dev_close(struct inode *inode, struct file *filp);
long          nv_vgpu_dev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);
unsigned int  nv_vgpu_dev_poll(struct file *file, poll_table *wait);
int           nv_vgpu_dev_mmap(struct file *file, struct vm_area_struct *vma);
NV_STATUS     nv_vfio_vgpu_pin_pages(void *, struct vgpu_dev_s *);
NV_STATUS     nv_vfio_vgpu_unpin_pages(void *, struct vgpu_dev_s *);
NV_STATUS     nv_vfio_vgpu_reg_get_data(void *, struct vgpu_dev_s *);
NV_STATUS     nv_vfio_vgpu_reg_set_data(void *, struct vgpu_dev_s *);
NV_STATUS     nv_vfio_vgpu_add_mmio_mapping(void *, struct vgpu_dev_s *);
NV_STATUS     nv_vfio_vgpu_remove_mmio_mapping(void *, struct vgpu_dev_s *);
NV_STATUS     nv_vfio_vgpu_inject_interrupt(struct vgpu_dev_s *);
NV_STATUS     nv_vfio_vgpu_notify_power_op(void *, struct vgpu_dev_s *);
NV_STATUS     nv_vfio_vgpu_event_create(vgpu_file_private_t *, NvU32);
NV_STATUS     nv_vfio_vgpu_event_destroy(vgpu_file_private_t *, NvU32);
NV_STATUS     nv_vgpu_copy_from_user(void *pkernel_params, void __user *puser_params,
                                     unsigned long size);
NV_STATUS     nv_vgpu_copy_to_user(void __user *puser_params, void *pkernel_params,
                                   unsigned long size);
NV_STATUS     nv_vfio_vgpu_get_attach_device(void *, struct vgpu_dev_s *);
NV_STATUS     nv_vfio_vgpu_attach_device_ack(void *,struct vgpu_dev_s *);
NV_STATUS     nv_vfio_vgpu_alloc_console_buffer(void *, vgpu_dev_t *);
NV_STATUS     nv_vfio_vgpu_free_console_buffer(vgpu_dev_t *);
NV_STATUS     nv_vfio_vgpu_set_console_suface_properties(void *, vgpu_dev_t *);
NV_STATUS     nv_vfio_vgpu_get_migration_state(void *, vgpu_dev_t *);
NV_STATUS     nv_vfio_vgpu_notify_migration_state_status(void *, struct vgpu_dev_s *);
NV_STATUS     nv_vfio_vgpu_get_migration_buffer_size(void *, struct vgpu_dev_s *);
NV_STATUS     nv_vfio_vgpu_set_migration_buffer_size(void *, struct vgpu_dev_s *);

NV_STATUS nv_vfio_vgpu_vf_reg_access_hw(void *cmd_params, vgpu_dev_t *vgpu_dev);


#define NV_MAX_VGPU_ID 0xFFFF

/* Maximum limit for copy_from_user. Same as max limit of RM */
#define NV_VGPU_VFIO_MAX_PARAMS_SIZE (1*1024*1024)

#if defined(NV_KVMALLOC_PRESENT)

#if defined(__GFP_RETRY_MAYFAIL)
#define NV_GFP_KVMALLOC (NV_GFP_KERNEL | __GFP_RETRY_MAYFAIL)
#else
#define NV_GFP_KVMALLOC NV_GFP_KERNEL
#endif

#define NV_MEM_ALLOC(address, size, is_vmalloc) \
{                                               \
    address = kvmalloc(size, NV_GFP_KVMALLOC);  \
}

#define NV_MEM_FREE(address, size, is_vmalloc)  \
{                                               \
    kvfree(address);                            \
}

#else

#define NV_MEM_ALLOC(address, size, is_vmalloc) \
do                                              \
{                                               \
    address = NULL;                             \
    is_vmalloc = NV_FALSE;                      \
    NV_KMALLOC_NO_OOM(address, size);           \
    if (address == NULL)                        \
    {                                           \
        address = nv_vmalloc(size);             \
        is_vmalloc = NV_TRUE;                   \
    }                                           \
} while(0)

#define NV_MEM_FREE(address, size, is_vmalloc)  \
do                                              \
{                                               \
    if (is_vmalloc == NV_TRUE)                  \
        nv_vfree(address, size);                \
    else                                        \
        NV_KFREE(address, size)                 \
} while(0)

#endif // #if defined(NV_KVMALLOC_PRESENT)

#define CHECK_PARAMS_SIZE(cmd, uparams, kparams)                                   \
    if (uparams != kparams)                                                        \
    {                                                                              \
        NV_VGPU_LOG(VGPU_INFO, "Params size mismatch. cmd: %s "                    \
                    "expected: 0x%lx actual: 0x%x \n", #cmd, kparams, uparams);    \
        status = NV_ERR_INVALID_ARGUMENT;                                          \
        break;                                                                     \
    }

#define NV_VGPU_VFIO_ROUTE_CMD(cmd, params_type, function_name)                    \
    case cmd:                                                                      \
    {                                                                              \
        params_type params;                                                        \
        CHECK_PARAMS_SIZE(cmd, ioctl_params.size, sizeof(params))                  \
        if ((status = nv_vgpu_copy_from_user(&params, ioctl_params.pCmdParams,     \
                                             sizeof(params))) == NV_OK)            \
        {                                                                          \
            if ((status = function_name(&params, vgpu_dev)) == NV_OK)              \
                status = nv_vgpu_copy_to_user(ioctl_params.pCmdParams, &params,    \
                                              sizeof(params));                     \
        }                                                                          \
        if (status != NV_OK)                                                       \
        {                                                                          \
            NV_VGPU_DEV_LOG(VGPU_INFO, vgpu_dev->mdev, "IOCTL %s failed. 0x%x \n", \
                            #cmd, status);                                         \
        }                                                                          \
        break;                                                                     \
    }

#define NV_VGPU_VFIO_HANDLE_EVENT(cmd, params_type, function_name)                 \
    case cmd:                                                                      \
    {                                                                              \
        params_type params;                                                        \
        CHECK_PARAMS_SIZE(cmd, ioctl_params.size, sizeof(params))                  \
        if ((status = nv_vgpu_copy_from_user(&params, ioctl_params.pCmdParams,     \
                                             sizeof(params))) == NV_OK)            \
        {                                                                          \
            if ((status = function_name(vgpu_fp, params.eventType)) == NV_OK)      \
                status = nv_vgpu_copy_to_user(ioctl_params.pCmdParams, &params,    \
                                              sizeof(params));                     \
        }                                                                          \
        if (status != NV_OK)                                                       \
        {                                                                          \
            NV_VGPU_DEV_LOG(VGPU_INFO, vgpu_dev->mdev, "IOCTL %s failed. 0x%x \n", \
                            #cmd, status);                                         \
        }                                                                          \
        break;                                                                     \
    }

#define NV_VGPU_VFIO_ROUTE_CMD_NO_PARAMS(cmd, function_name)                       \
    case cmd:                                                                      \
    {                                                                              \
        status = function_name(vgpu_dev);                                          \
        if (status != NV_OK)                                                       \
        {                                                                          \
            NV_VGPU_DEV_LOG(VGPU_INFO, vgpu_dev->mdev, "IOCTL %s failed. 0x%x \n", \
                            #cmd, status);                                         \
        }                                                                          \
        break;                                                                     \
    }

extern int major_num;

#endif /* _VGPU_DEVICE_H__ */
