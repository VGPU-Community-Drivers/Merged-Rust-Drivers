/*
 * Copyright (c) 2017-2020, NVIDIA CORPORATION. All rights reserved.
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
#include "nv-vgpu-vfio-interface.h"
#include "vgpu-devices.h"

#ifdef NV_VFIO_DEVICE_GFX_PLANE_INFO_PRESENT
#include <drm/drm_fourcc.h>
#endif

struct vgpu_devs vgpu_devices;
struct phys_devs phys_devices;

#define SLEEP_TIME_MILLISECONDS 20
#define VGPU_EXIT_TIMEOUT_MILLISECONDS 5000
#define WAITQUEUE_TIMEOUT_SECONDS 25000


static void vgpu_msix_disable(vgpu_dev_t *vgpu_dev);
static int do_vf_flr(struct mdev_device *mdev);


#if defined(NV_VGPU_KVM_BUILD)
static vgpu_vfio_ops_t vgpu_vfio_ops = {
    .probe                   = nv_vgpu_probe,
    .remove                  = nv_vgpu_remove,
    .inject_interrupt        = nv_vgpu_inject_interrupt,
};

static ssize_t
vgpu_params_show(struct device *dev, struct device_attribute *attr, char *buf)
{
    ssize_t     ret;
    vgpu_dev_t *vgpu_dev = NULL;

    down(&vgpu_devices.vgpu_dev_list_lock);
    vgpu_dev = mdev_get_drvdata(NV_GET_MDEV_FROM_DEV(dev));
    if (vgpu_dev == NULL)
    {
        up(&vgpu_devices.vgpu_dev_list_lock);
        return -ENXIO;
    }

    down(&vgpu_dev->ops_lock);
    ret = sprintf(buf, "%s\n", vgpu_dev->config_params);
    up(&vgpu_dev->ops_lock);

    up(&vgpu_devices.vgpu_dev_list_lock);

    return ret;
}

static ssize_t
vgpu_params_store(struct device *dev, struct device_attribute *attr,
                  const char *buf, size_t count)
{
    ssize_t     ret  = 0;
    vgpu_dev_t *vgpu_dev = NULL;

    if (count > VGPU_CONFIG_PARAMS_MAX_LENGTH)
        return -E2BIG;

    down(&vgpu_devices.vgpu_dev_list_lock);
    vgpu_dev = mdev_get_drvdata(NV_GET_MDEV_FROM_DEV(dev));
    if (vgpu_dev == NULL)
    {
        up(&vgpu_devices.vgpu_dev_list_lock);
        return -ENXIO;
    }

    down(&vgpu_dev->ops_lock);
    up(&vgpu_devices.vgpu_dev_list_lock);

    if (atomic_read(&vgpu_dev->usage_count) == 0)
        ret = snprintf(vgpu_dev->config_params, count, "%s", buf);
    else
        ret = -EPERM;

    up(&vgpu_dev->ops_lock);
    return ret;
}
static DEVICE_ATTR_RW(vgpu_params);

static ssize_t
vm_name_show(struct device *dev, struct device_attribute *attr, char *buf)
{
    ssize_t     ret;
    vgpu_dev_t *vgpu_dev = NULL;

    down(&vgpu_devices.vgpu_dev_list_lock);
    vgpu_dev = mdev_get_drvdata(NV_GET_MDEV_FROM_DEV(dev));
    if (vgpu_dev == NULL)
    {
        up(&vgpu_devices.vgpu_dev_list_lock);
        return -ENXIO;
    }
    down(&vgpu_dev->ops_lock);
    up(&vgpu_devices.vgpu_dev_list_lock);

    if (atomic_read(&vgpu_dev->usage_count) > 0)
        ret = sprintf(buf, "%s\n", vgpu_dev->vm_name);
    else
        ret = sprintf(buf, "\n");

    up(&vgpu_dev->ops_lock);

    return ret;
}
static DEVICE_ATTR_RO(vm_name);

#if defined(DEBUG)
static ssize_t
migration_data_show(struct device *dev, struct device_attribute *attr, char *buf)
{
    ssize_t     ret;
    vgpu_dev_t *vgpu_dev = NULL;

    down(&vgpu_devices.vgpu_dev_list_lock);
    vgpu_dev = mdev_get_drvdata(NV_GET_MDEV_FROM_DEV(dev));
    if (vgpu_dev == NULL)
    {
        up(&vgpu_devices.vgpu_dev_list_lock);
        return -ENXIO;
    }
    down(&vgpu_dev->ops_lock);
    up(&vgpu_devices.vgpu_dev_list_lock);

#if defined(NV_VFIO_DEVICE_MIGRATION_INFO_PRESENT)
    if (vgpu_dev->migration_state == NV_VFIO_DEVICE_STATE_NONE)
    {
        ret = sprintf(buf, "Bytes Transferred: %lld (%lld MB), Dirty Pages: %d\n",
                vgpu_dev->bytes_transferred, vgpu_dev->bytes_transferred >> 20,
                vgpu_dev->dirty_pfn_count);
    }
    else
#endif
    {
        ret = sprintf(buf, "Not Migrated\n");
    }

    up(&vgpu_dev->ops_lock);

    return ret;
}
static DEVICE_ATTR_RO(migration_data);
#endif

static struct attribute *vgpu_dev_attrs[] = {
    &dev_attr_vgpu_params.attr,
    &dev_attr_vm_name.attr,
#if defined(DEBUG)
    &dev_attr_migration_data.attr,
#endif
    NULL,
};

static const struct attribute_group vgpu_dev_group = {
    .name  = "nvidia",
    .attrs = vgpu_dev_attrs,
};

const struct attribute_group *vgpu_dev_groups[] = {
    &vgpu_dev_group,
    NULL,
};

/* vgpu fops to be registed to mdev module */
#if defined(NV_MDEV_PARENT_OPS_STRUCT_PRESENT)
struct mdev_parent_ops vgpu_fops = {
#else
struct parent_ops vgpu_fops = {
#endif
    .owner            = THIS_MODULE,
    .mdev_attr_groups = vgpu_dev_groups,
    .create           = nv_vgpu_vfio_create,
    .remove           = nv_vgpu_vfio_destroy,
    .read             = nv_vgpu_vfio_read,
    .write            = nv_vgpu_vfio_write,
    .open             = nv_vgpu_vfio_open,
    .release          = nv_vgpu_vfio_close,
    .ioctl            = nv_vgpu_vfio_ioctl,
    .mmap             = nv_vgpu_vfio_mmap,
};

static rm_vgpu_vfio_ops_t rm_vgpu_vfio_ops;

static gpfn_node_t *find_gpfn_from_list(vgpu_dev_t *vgpu_dev, unsigned long pfn)
{
    struct rb_node *node = vgpu_dev->gpfn_list.rb_node;
    gpfn_node_t *gpfn_node;

    while (node)
    {
        gpfn_node = rb_entry(node, gpfn_node_t, node);

        if (pfn < gpfn_node->gpfn)
            node = node->rb_left;
        else if (pfn > gpfn_node->gpfn)
            node = node->rb_right;
        else
            return gpfn_node;
    }
    return NULL;
}

static void remove_gpfn_from_list(vgpu_dev_t *vgpu_dev, gpfn_node_t *gpfn_node)
{
    if (atomic_dec_and_test(&gpfn_node->ref_count))
    {
        rb_erase(&gpfn_node->node, &vgpu_dev->gpfn_list);
        NV_KFREE(gpfn_node, sizeof(gpfn_node_t));
    }
}

static void remove_gpfn_from_list_all(vgpu_dev_t *vgpu_dev)
{
    struct rb_node *node;
    gpfn_node_t *gpfn_node;
    int ref_cnt = 0, i;

    while ((node = rb_first(&vgpu_dev->gpfn_list)))
    {
        gpfn_node = rb_entry(node, gpfn_node_t, node);
        ref_cnt = atomic_read(&gpfn_node->ref_count);
        for (i = 0; i < ref_cnt; i++)
            nv_vgpu_unpin_pages((NvU64 *)&gpfn_node->gpfn, 1,
                                (void *)vgpu_dev, GET_HOST_PFN);
    }
}

static void add_gpfn_buffer_to_list(vgpu_dev_t *vgpu_dev,
                                    unsigned long *gpfn_buffer, NvU32 count)
{
    struct rb_node *parent, **link;
    gpfn_node_t *gpfn_node, *tgpfn_node;
    int i = 0;

    for (i = 0; i < count; i++)
    {
        parent = NULL;
        link = &vgpu_dev->gpfn_list.rb_node;

        while(*link)
        {
            parent = *link;
            tgpfn_node = rb_entry(parent, gpfn_node_t, node);

            if (gpfn_buffer[i] < tgpfn_node->gpfn)
                link = &(*link)->rb_left;
            else if (gpfn_buffer[i] > tgpfn_node->gpfn)
                link = &(*link)->rb_right;
            else
            {
                atomic_inc(&tgpfn_node->ref_count);
                break;
            }
        }

        if ((*link) == NULL)
        {
            NV_KMALLOC(gpfn_node, sizeof(gpfn_node_t));
            memset(gpfn_node, 0, sizeof(gpfn_node_t));

            gpfn_node->gpfn = gpfn_buffer[i];
            atomic_set(&gpfn_node->ref_count, 1);
            rb_link_node(&gpfn_node->node, parent, link);
            rb_insert_color(&gpfn_node->node, &vgpu_dev->gpfn_list);
        }
   }
}

static NV_STATUS get_phys_dev(struct pci_dev *dev, phys_dev_t **phys_dev)
{
    phys_dev_t *phys_dev_temp = NULL;

    if(list_empty(&phys_devices.phys_dev_list))
    {
        *phys_dev = phys_dev_temp;
        return NV_OK;
    }

    list_for_each_entry(phys_dev_temp, &phys_devices.phys_dev_list, next)
    {

        /* 
         * Don't allow VF and it's parent PF to be simultaneously
         * registered to MDEV. Explicitly fail such probe requests
         * so that the vgpu-vfio interface layer in nvidia.ko does 
         * not proceed with the GPU_BIND_EVENT raise.
         */
        if (phys_dev_temp->is_virtfn)
        {
            if (phys_dev_temp->dev->physfn == dev)
                return NV_ERR_INVALID_REQUEST;
        }
        else
        {
            if ((dev->is_virtfn) && (dev->physfn == phys_dev_temp->dev))
                return NV_ERR_INVALID_REQUEST;
        }

        if (phys_dev_temp->dev == dev)
        {
            *phys_dev = phys_dev_temp;
            return NV_OK;
        }
    }

    *phys_dev = NULL;
    return NV_OK;
}

static int nv_vgpu_vfio_notifier(struct notifier_block *nb, unsigned long action,
                                 void *data)
{
    if (action == VFIO_IOMMU_NOTIFY_DMA_UNMAP)
    {
        vgpu_dev_t *vgpu_dev = container_of(nb, vgpu_dev_t, nb);
        gpfn_node_t *gpfn_node = NULL;
        unsigned long gpfn;
        struct vfio_iommu_type1_dma_unmap *unmap = data;
        NvU64 i;
        int ret;

        down(&vgpu_dev->ops_lock);

        NV_VGPU_DEV_LOG(VGPU_INFO, vgpu_dev->mdev,
                        "Unmap notifier called for iova: 0x%llx size: 0x%llx\n",
                        unmap->iova, unmap->size);

        gpfn = unmap->iova >> PAGE_SHIFT;
        for (i = 0; i < unmap->size; i += PAGE_SIZE)
        {
            if (!RB_EMPTY_ROOT(&vgpu_dev->gpfn_list))
            {
                gpfn_node = find_gpfn_from_list(vgpu_dev, gpfn);
                if (gpfn_node != NULL)
                    nv_vgpu_unpin_pages((NvU64 *)&gpfn, 1, vgpu_dev, GET_HOST_PFN);
            }

            if (vgpu_dev->mapping_cache && vgpu_dev->mapping_cache[gpfn])
            {
                ret = vfio_unpin_pages(NV_GET_MDEV_DEV(vgpu_dev->mdev),
                                       (long unsigned int *)&gpfn, 1);
                if (ret != 1)
                {
                    NV_VGPU_DEV_LOG(VGPU_ERR, vgpu_dev->mdev,
                                    "Failed to unpin dirty pinned page in notifier. gpfn: 0x%lx\n",
                                    gpfn);
                }
                else
                    NV_VGPU_DEV_LOG(VGPU_INFO, vgpu_dev->mdev,
                                    "Guest pfn 0x%lx unpinned from unmap notifier\n", gpfn);
#if defined(DEBUG)
                vgpu_dev->dirty_pfn_count -= 1;
#endif

                if (vgpu_dev->mapping_cache[gpfn] == (mapping_node_t *)GFN_PINNED)
                    vgpu_dev->mapping_cache[gpfn] = NULL;
                else
                    vgpu_dev->mapping_cache[gpfn]->base_gpfn_pinned = NV_FALSE;
            }

            gpfn++;
        }

        up(&vgpu_dev->ops_lock);
    }
    return 0;
}

static NV_STATUS nv_get_vgpu_type_id(const char *kobj_name, struct device *dev,
                                     NvU32 *vgpu_type_id)
{
    char *strp = NULL;
    const char *key = dev_driver_string(dev);

    strp = strstr(kobj_name, key);
    if (strp == NULL)
        return NV_ERR_INVALID_ARGUMENT;

    strp = strp + strlen(key) + 1;
    *vgpu_type_id = strtoul(strp, NULL, 0);

    return NV_OK;
}

static ssize_t name_show(struct kobject *kobj, struct device *dev, char *buf)
{
    struct pci_dev *pdev = to_pci_dev(dev);
    struct pci_dev *parent_device;
    NvU32 vgpu_type_id;
    NV_STATUS status;

    if (pdev->is_virtfn)
        parent_device = pdev->physfn;
    else

        parent_device = pdev;

    if (nv_get_vgpu_type_id(kobj->name, dev, &vgpu_type_id)
         == NV_OK)
        status = rm_vgpu_vfio_ops.get_name(parent_device, vgpu_type_id, buf);
    else
        return -EINVAL;

    if (status != NV_OK)
        return -EIO;

    return strlen(buf);
}
MDEV_TYPE_ATTR_RO(name);

static ssize_t description_show(struct kobject *kobj, struct device *dev, char *buf)
{
    struct pci_dev *pdev = to_pci_dev(dev);
    struct pci_dev *parent_device;
    NvU32 vgpu_type_id;
    NV_STATUS status;

    if (pdev->is_virtfn)
        parent_device = pdev->physfn;
    else

        parent_device = pdev;

    if (nv_get_vgpu_type_id(kobj->name, dev, &vgpu_type_id)
         == NV_OK)
        status = rm_vgpu_vfio_ops.get_description(parent_device, vgpu_type_id, buf);
    else
        return -EINVAL;

    if (status != NV_OK)
        return -EIO;

    return strlen(buf);
}
MDEV_TYPE_ATTR_RO(description);

static ssize_t available_instances_show(struct kobject *kobj, struct device *dev, char *buf)
{
    struct pci_dev *pdev = to_pci_dev(dev);
    NvU32 vgpu_type_id;
    NV_STATUS status;

    if ((nv_get_vgpu_type_id(kobj->name, dev, &vgpu_type_id)) == NV_OK)
        status = rm_vgpu_vfio_ops.get_instances(pdev, vgpu_type_id, buf);
    else
        return -EINVAL;

    if (status != NV_OK)
        return -EIO;

    return strlen(buf);
}
MDEV_TYPE_ATTR_RO(available_instances);

static ssize_t device_api_show(struct kobject *kobj, struct device *dev,
                               char *buf)
{
    return sprintf(buf, "%s\n",
                   VFIO_DEVICE_API_PCI_STRING);
}
MDEV_TYPE_ATTR_RO(device_api);

static struct attribute *vgpu_type_attrs[] = {
    &mdev_type_attr_name.attr,
    &mdev_type_attr_description.attr,
    &mdev_type_attr_available_instances.attr,
    &mdev_type_attr_device_api.attr,
    NULL,
};

static int nv_vgpu_vfio_destroy(struct mdev_device *mdev)
{
    int ret = 0;
    vgpu_dev_t *vgpu_dev = NULL;
    NV_STATUS status = NV_OK;
    NvBool vgpu_exited = NV_FALSE;
    NvU32 elapsed_time = 0;

    if (!mdev)
        return -EINVAL;

    down(&vgpu_devices.vgpu_dev_list_lock);

    vgpu_dev = mdev_get_drvdata(mdev);
    if (!vgpu_dev)
    {
        status = NV_ERR_OBJECT_NOT_FOUND;
        ret = -ENODEV;
        up(&vgpu_devices.vgpu_dev_list_lock);
        goto destroy_exit;
    }

    if (atomic_read(&vgpu_dev->usage_count) != 0)
    {
        up(&vgpu_devices.vgpu_dev_list_lock);
        status = NV_ERR_INVALID_OPERATION;
        ret = -EPERM;
        goto destroy_exit;
    }
    up(&vgpu_devices.vgpu_dev_list_lock);

    while (elapsed_time < VGPU_EXIT_TIMEOUT_MILLISECONDS)
    {
        down(&vgpu_dev->dev_lock);
        if (!list_empty(&vgpu_dev->file_private_list))
        {
            up(&vgpu_dev->dev_lock);
            msleep(SLEEP_TIME_MILLISECONDS);
        }
        else
        {
            up(&vgpu_dev->dev_lock);
            vgpu_exited = NV_TRUE;
            break;
        }
        elapsed_time += SLEEP_TIME_MILLISECONDS;
    }

    if (vgpu_exited == NV_FALSE)
    {
        status = NV_ERR_IN_USE;
        ret = -EBUSY;
        goto destroy_exit;
    }

    down(&vgpu_devices.vgpu_dev_list_lock);
    down(&vgpu_dev->ops_lock);
    nv_remove_vgpu_chardev(vgpu_dev);
    list_del(&vgpu_dev->next);
    mdev_set_drvdata(mdev, NULL);
    up(&vgpu_devices.vgpu_dev_list_lock);

    status = rm_vgpu_vfio_ops.vgpu_delete(NV_GET_MDEV_UUID(mdev), vgpu_dev->vgpu_id);

    if (status != NV_OK)
        ret = -EIO;

    NV_VGPU_DEV_LOG(VGPU_INFO, mdev, "vGPU device destroyed.\n");

    up(&vgpu_dev->ops_lock);
    NV_KFREE(vgpu_dev->vconfig, PCI_EXTENDED_CONFIG_SPACE_SIZE);
    NV_KFREE(vgpu_dev, sizeof(vgpu_dev_t));

destroy_exit:
    if (status != NV_OK)
       NV_VGPU_DEV_LOG(VGPU_ERR, mdev, "vGPU destroy failed: 0x%x\n", status);

    return ret;
}

static int nv_vgpu_vfio_create(struct kobject *kobj, struct mdev_device *mdev)
{
    NV_STATUS status = NV_OK;
    vgpu_dev_t *vgpu_dev = NULL;
    struct pci_dev *pdev;
    struct pci_dev *parent_device;
    NvU32 vgpu_type_id;
    int ret = 0;
    NvU16 vgpu_id;
    NvU32 gpu_pci_bdf;
    NvU32 gpu_pci_id;

    if (!mdev)
    {
        NV_VGPU_LOG(VGPU_ERR, "%s Invalid parameters\n", __FUNCTION__);
        return -EINVAL;
    }

    pdev = to_pci_dev(NV_GET_MDEV_PARENT(mdev));
    if (!pdev)
        return -EINVAL;

    if (nv_get_vgpu_type_id(kobj->name, NV_GET_MDEV_PARENT(mdev), &vgpu_type_id)
        != NV_OK)
    {
        ret = -EINVAL;
        goto create_exit;
    }

    gpu_pci_bdf =
            ((NvU32)(NV_PCI_DOMAIN_NUMBER(pdev) << DRF_SHIFT(NV_PCI_BDF_DOMAIN)) |
             (NvU32)(NV_PCI_BUS_NUMBER(pdev) << DRF_SHIFT(NV_PCI_BDF_BUS))       |
             (NvU32)(NV_PCI_DEVFN(pdev) << DRF_SHIFT(NV_PCI_BDF_DEVFN)));


    if (pdev->is_virtfn)
        parent_device = pdev->physfn;
    else

        parent_device = pdev;

    status = rm_vgpu_vfio_ops.vgpu_create(parent_device, NV_GET_MDEV_UUID(mdev),
                                          vgpu_type_id, &vgpu_id, &gpu_pci_id,
                                          gpu_pci_bdf);
    if (status != NV_OK)
    {
        ret = -EIO;
        goto create_exit;
    }

    NV_KMALLOC(vgpu_dev, sizeof(vgpu_dev_t));
    if (vgpu_dev == NULL)
    {
        ret = -ENOMEM;
        goto remove_vgpu;
    }

    memset(vgpu_dev, 0, sizeof(vgpu_dev_t));

    NV_KMALLOC(vgpu_dev->vconfig, PCI_EXTENDED_CONFIG_SPACE_SIZE);
    if (vgpu_dev->vconfig == NULL)
    {
        ret = -ENOMEM;
        goto remove_vgpu;
    }
    memset(vgpu_dev->vconfig, 0, PCI_EXTENDED_CONFIG_SPACE_SIZE);

    NV_INIT_MUTEX(&vgpu_dev->ops_lock);
    NV_INIT_MUTEX(&vgpu_dev->dev_lock);
    NV_SPIN_LOCK_INIT(&vgpu_dev->intr_info_lock);
    vgpu_dev->mdev = mdev;
    vgpu_dev->vgpu_type_id = vgpu_type_id;
    vgpu_dev->vgpu_id = vgpu_id;
    vgpu_dev->gpu_pci_id  = gpu_pci_id;
    vgpu_dev->gpu_pci_bdf = gpu_pci_bdf;
    vgpu_dev->instance_id = INVALID_VGPU_INSTANCE_ID;
    vgpu_dev->device_state = NV_VGPU_DEV_UNUSED;
    vgpu_dev->mig_buffer_base = NULL;
    vgpu_dev->staging_buf_base = NULL;
    vgpu_dev->migration_enabled = NV_FALSE;
    vgpu_dev->phys_mappings.bar1_vma = NULL;

    INIT_LIST_HEAD(&vgpu_dev->next);
    INIT_LIST_HEAD(&vgpu_dev->file_private_list);
    init_waitqueue_head(&vgpu_dev->wait_queue);
    init_waitqueue_head(&vgpu_dev->reg_info.wait);

    status = nv_create_vgpu_chardev(vgpu_dev);
    if (status != NV_OK)
    {
        ret = -EIO;
        goto remove_vgpu;
    }


    if (pdev->is_virtfn)
    {
#if defined(NV_MDEV_SET_IOMMU_DEVICE_PRESENT)
        ret = mdev_set_iommu_device(NV_GET_MDEV_DEV(mdev), NV_GET_MDEV_PARENT(mdev));
        if (ret != 0)
        {
            NV_VGPU_DEV_LOG(VGPU_ERR, mdev, "Failed to set IOMMU device. ret: %d \n", ret);
            goto remove_vgpu;
        }
#endif
    }


    down(&vgpu_devices.vgpu_dev_list_lock);
    list_add(&vgpu_dev->next, &vgpu_devices.vgpu_dev_list);
    mdev_set_drvdata(mdev, vgpu_dev);
    up(&vgpu_devices.vgpu_dev_list_lock);

    rm_vgpu_vfio_ops.update_request(NV_GET_MDEV_UUID(mdev), NULL,
                                    NULL, vgpu_dev->device_state, NULL);

    NV_VGPU_DEV_LOG(VGPU_INFO, mdev, "vGPU device created successfully. \n");

    return 0;

remove_vgpu:
    rm_vgpu_vfio_ops.vgpu_delete(NV_GET_MDEV_UUID(mdev), vgpu_id);

    if (vgpu_dev->vconfig != NULL)
        NV_KFREE(vgpu_dev->vconfig, PCI_EXTENDED_CONFIG_SPACE_SIZE);

    if (vgpu_dev != NULL)
        NV_KFREE(vgpu_dev, sizeof(vgpu_dev_t));

create_exit:
    NV_VGPU_DEV_LOG(VGPU_ERR, mdev, "vGPU creation failed %d\n", ret);

    return ret;
}

static int nv_vgpu_vfio_region_info(vgpu_dev_t *vgpu_dev,
                                    struct vfio_region_info *region_info,
                                    struct vfio_info_cap *caps)
{
    NV_STATUS status = NV_OK;
    int ret = 0;
    NvU64 size = 0;
    struct pci_dev *pdev;
    struct pci_dev *parent_device;

    if (!region_info || !vgpu_dev->mdev)
        return -EINVAL;

    pdev = to_pci_dev(NV_GET_MDEV_PARENT(vgpu_dev->mdev));
    if (!pdev)
    {
        ret = -ENODEV;
        goto region_info_exit;
    }

    if (pdev->is_virtfn)
        parent_device = pdev->physfn;
    else

        parent_device = pdev;

    if ((region_info->index >= VFIO_PCI_BAR0_REGION_INDEX) &&
        (region_info->index <= VFIO_PCI_ROM_REGION_INDEX))
    {
        vgpu_dev->region_info[region_info->index].phys_start = pci_resource_start(pdev,
                                                               region_info->index);
    }

    switch (region_info->index)
    {
        case VFIO_PCI_BAR0_REGION_INDEX ... VFIO_PCI_BAR4_REGION_INDEX:

            if (pdev->is_virtfn)
            {
                if (region_info->index == VFIO_PCI_BAR1_REGION_INDEX) {
                    status = rm_vgpu_vfio_ops.vgpu_bar_info(parent_device,
                                                            NV_GET_MDEV_UUID(vgpu_dev->mdev),
                                                            &size, region_info->index,
                                                            (void *) vgpu_dev,
                                                            &vgpu_dev->host_vgpu_dev);
                    if (status != NV_OK || size == 0)
                    {
                        ret = -EIO;
                        goto region_info_exit;
                    }
                } else {
                    size = pci_resource_len(pdev, region_info->index);
                }
            }
            else

            {
                if (region_info->index == VFIO_PCI_BAR4_REGION_INDEX)
                {
                    size = 0;
                    goto region_info_exit;
                }
                status = rm_vgpu_vfio_ops.vgpu_bar_info(parent_device,
                                                        NV_GET_MDEV_UUID(vgpu_dev->mdev),
                                                        &size, region_info->index,
                                                        (void *) vgpu_dev,
                                                        &vgpu_dev->host_vgpu_dev);
                if (status != NV_OK)
                {
                    ret = -EIO;
                    goto region_info_exit;
                }

                if (size == 0)
                {
                    if (region_info->index == VFIO_PCI_BAR2_REGION_INDEX)
                    {
                        NvU32 *addr;
                        addr = (NvU32 *)(vgpu_dev->vconfig + PCI_BASE_ADDRESS_1);
                        *addr |= PCI_BASE_ADDRESS_MEM_TYPE_64;

                        addr = (NvU32 *)(vgpu_dev->vconfig + PCI_BASE_ADDRESS_3);
                        *addr |= PCI_BASE_ADDRESS_MEM_TYPE_64;

                        vgpu_dev->region_info[region_info->index].size = size;
                    }
                    goto region_info_exit;
                }
            }
            break;
        case VFIO_PCI_CONFIG_REGION_INDEX:
            size = PCI_EXTENDED_CONFIG_SPACE_SIZE;
            break;
        case NV_VGPU_VFIO_CONSOLE_REGION:
            size = NV_VFIO_VGPU_CONSOLE_SURFACE_SIZE_MAX;
            break;
#if defined(NV_VFIO_DEVICE_MIGRATION_INFO_PRESENT)
        case NV_VGPU_VFIO_MIGRATION_REGION:
            {
                if (vgpu_dev->migration_enabled)
                {
                    size = NV_VFIO_VGPU_MIGRATION_REGION_SIZE_MAX;
                    break;
                }
                else
                {
                    size = 0;
                    goto region_info_exit;
                }
            }
#endif
        default:
            size = 0;
            goto region_info_exit;
    }

    region_info->size = size;
    region_info->flags = VFIO_REGION_INFO_FLAG_READ |
                         VFIO_REGION_INFO_FLAG_WRITE;

    region_info->offset = DRF_NUM64(_VGPU_VFIO, _PGOFF, _PCI_INDEX, region_info->index) |
                          DRF_NUM64(_VGPU_VFIO, _PGOFF, _UNIQUE_ID, vgpu_dev->vgpu_id);

    if (region_info->index == NV_VGPU_VFIO_CONSOLE_REGION)
    {
        region_info->flags |= VFIO_REGION_INFO_FLAG_MMAP;
        goto region_info_exit;
    }
#if defined(NV_VFIO_DEVICE_MIGRATION_INFO_PRESENT)
    else if ((region_info->index == NV_VGPU_VFIO_MIGRATION_REGION) &&
             (vgpu_dev->migration_enabled))
    {
        struct vfio_region_info_cap_sparse {
            struct vfio_region_info_cap_sparse_mmap sparse;
            struct vfio_region_sparse_mmap_area area;
        };

        struct vfio_region_info_cap_sparse mig_region;

        struct vfio_region_info_cap_type cap_type = {
            .header.id = VFIO_REGION_INFO_CAP_TYPE,
            .header.version = 1,
            .type = VFIO_REGION_TYPE_MIGRATION,
            .subtype = VFIO_REGION_SUBTYPE_MIGRATION
        };

        /* Add REGION CAP type */
        ret = nv_vfio_info_add_capability(caps, &cap_type.header,
                &cap_type, sizeof(cap_type));

        if (ret)
            goto region_info_exit;

        /* Add sparse mmap cap type */
        mig_region.sparse.nr_areas = 1;
        mig_region.sparse.header.id = VFIO_REGION_INFO_CAP_SPARSE_MMAP;
        mig_region.sparse.header.version = 1;

        mig_region.area.offset = NV_VFIO_VGPU_MIGRATION_REGION_DATA_OFFSET;
        mig_region.area.size = NV_VFIO_VGPU_MIGRATION_REGION_SIZE_MMAP;

        region_info->flags |= VFIO_REGION_INFO_FLAG_CAPS;

        if (region_info->argsz > sizeof(*region_info))
            region_info->flags |= VFIO_REGION_INFO_FLAG_MMAP;

        ret = nv_vfio_info_add_capability(caps, &mig_region.sparse.header,
                                          &mig_region.sparse, sizeof(mig_region));
    }
#endif

    vgpu_dev->region_info[region_info->index].size = size;


    if ((region_info->index == VFIO_PCI_BAR1_REGION_INDEX) ||
        (pdev->is_virtfn && ((region_info->index >= VFIO_PCI_BAR2_REGION_INDEX) && (region_info->index <= VFIO_PCI_BAR4_REGION_INDEX))))



    {
        region_info->flags |= VFIO_REGION_INFO_FLAG_MMAP;
    }
    else if ((region_info->index == VFIO_PCI_BAR0_REGION_INDEX)
              && (vgpu_dev->num_areas != 0))
    {
        NvU32 size = 0;

        size = sizeof(struct vfio_region_info_cap_sparse_mmap) +
                     (vgpu_dev->num_areas * sizeof(struct vfio_region_sparse_mmap_area));

        if (vgpu_dev->sparse == NULL)
        {
            struct vfio_region_info_cap_sparse_mmap *sparse;
            NvU32 i;

            NV_KMALLOC(sparse, size);
            if (sparse == NULL)
            {
                ret = -ENOMEM;
                goto region_info_exit;
            }
            sparse->nr_areas = vgpu_dev->num_areas;

            for (i = 0; i < vgpu_dev->num_areas; i++)
            {
                sparse->areas[i].offset = vgpu_dev->offsets[i];
                sparse->areas[i].size = vgpu_dev->sizes[i];
            }
            sparse->header.id = VFIO_REGION_INFO_CAP_SPARSE_MMAP;
            sparse->header.version = 1;

            vgpu_dev->sparse = sparse;
        }

        region_info->flags |= VFIO_REGION_INFO_FLAG_CAPS;

        if (region_info->argsz > sizeof(*region_info))
            region_info->flags |= VFIO_REGION_INFO_FLAG_MMAP;

        ret = nv_vfio_info_add_capability(caps, &vgpu_dev->sparse->header,
                                          vgpu_dev->sparse, size);
    }

region_info_exit:
    if (ret != 0)
        NV_VGPU_DEV_LOG(VGPU_ERR, vgpu_dev->mdev,
                        "Failed to query region info for region %d. ret: %d\n",
                        region_info->index, ret);

    return ret;
}

void nv_update_config_space(vgpu_dev_t *vgpu_dev, NvU64 offset,
                            char *buf, size_t count)
{
    NvU32 *data= (NvU32 *)buf;

    if (vgpu_dev->region_info[VFIO_PCI_BAR2_REGION_INDEX].size == 0)
    {
        if (offset == PCI_BASE_ADDRESS_1 || offset == PCI_BASE_ADDRESS_3)
            *data |= PCI_BASE_ADDRESS_MEM_TYPE_64;
    }
    else
    {
        if (offset == PCI_BASE_ADDRESS_1)
            *data &= ~PCI_BASE_ADDRESS_MEM_TYPE_64;
    }

    memcpy((void *)(vgpu_dev->vconfig + offset), (void *)data, count);
}

int update_pci_config_bars_cache(vgpu_dev_t *vgpu_dev)
{
    NV_STATUS status = NV_OK;
    NvU32 index, pos = PCI_BASE_ADDRESS_0;
    int ret;

    /*
     * During resuming, hypervisor/QEMU doesn't write PCI BAR addresses in
     * config space, but PCI config space is saved and restored by plugin.
     * In that case, when BAR address cache of PCI config space is not updated,
     * get BAR addresses from plugin.
     */
    if (*(NvU32 *)(vgpu_dev->vconfig + pos) != 0)
        return 0;

    for (index = 0; index <= VFIO_PCI_BAR5_REGION_INDEX; index++)
    {
        NvU32 buf = 0;

        vgpu_dev->reg_info.offset = pos;
        vgpu_dev->reg_info.data = (char *)&buf;
        vgpu_dev->reg_info.count = 4;
        vgpu_dev->reg_info.is_write = FALSE;
        vgpu_dev->reg_info.emul_space = VGPU_EMUL_CONFIG_SPACE;
        vgpu_dev->reg_info.status = -1;

        status = nv_vgpu_dev_post_event(vgpu_dev, NV_VFIO_VGPU_EVENT_VM_REG_ACCESS);
        if (status != NV_OK)
            return -EFAULT;

        ret = wait_event_interruptible_timeout(vgpu_dev->reg_info.wait,
                (vgpu_dev->reg_info.status >= 0),
                msecs_to_jiffies(8000));

        if (ret == 0 && vgpu_dev->reg_info.status == -1)  /* Timeout occured */
        {
            vgpu_dev->reg_info.status = NV_ERR_TIMEOUT;
            return -ETIMEDOUT;
        }
        else if (vgpu_dev->reg_info.status == NV_OK)
        {
            nv_update_config_space(vgpu_dev, pos, (char *)&buf, 4);
        }
        else
            return -EIO;
        pos += 4;
    }
    return 0;
}

static void vgpu_read_base(vgpu_dev_t *vgpu_dev)
{
    NvU32 index, pos;
    NvU32 start_lo, start_hi, mem_type;

    if (update_pci_config_bars_cache(vgpu_dev))
        return;

    pos = PCI_BASE_ADDRESS_0;

    for (index = 0; index <= VFIO_PCI_BAR4_REGION_INDEX; index++)
    {

        if (!vgpu_dev->region_info[index].size)
            continue;

        start_lo = (*(NvU32 *)(vgpu_dev->vconfig + pos)) &
                    PCI_BASE_ADDRESS_MEM_MASK;
        mem_type = (*(NvU32 *)(vgpu_dev->vconfig + pos)) &
                    PCI_BASE_ADDRESS_MEM_TYPE_MASK;

        switch (mem_type)
        {
            case PCI_BASE_ADDRESS_MEM_TYPE_64:
                start_hi = (*(NvU32 *)(vgpu_dev->vconfig + pos + 4));
                pos += 4;
                break;
            case PCI_BASE_ADDRESS_MEM_TYPE_32:
            case PCI_BASE_ADDRESS_MEM_TYPE_1M:
                /* 1M mem BAR treated as 32-bit BAR */
            default:
                /* mem unknown type treated as 32-bit BAR */
                start_hi = 0;
                break;
        }
        pos += 4;
        vgpu_dev->region_info[index].start = ((NvU64)start_hi << 32) | start_lo;
    }
}

#if defined(NV_VFIO_DEVICE_MIGRATION_INFO_PRESENT)
NvU32 nv_translate_device_state(NvU32 device_state, NvU32 nv_state)
{
    if (device_state & VFIO_DEVICE_STATE_RUNNING) {
        if (device_state & VFIO_DEVICE_STATE_SAVING)
            return NV_VFIO_DEVICE_STATE_MIGRATION_PRECOPY_ACTIVE;
        else
            return NV_VFIO_DEVICE_STATE_RUNNING;
    } else {
        if (device_state & VFIO_DEVICE_STATE_SAVING)
            return NV_VFIO_DEVICE_STATE_MIGRATION_STOPNCOPY_ACTIVE;
        else if (nv_state == NV_VFIO_DEVICE_STATE_MIGRATION_STOPNCOPY_ACTIVE)
            return NV_VFIO_DEVICE_STATE_NONE;
#if defined(NV_VFIO_DEVICE_MIGRATION_HAS_START_PFN)
        else
#else
        else if (device_state & VFIO_DEVICE_STATE_RESUMING)
#endif
            return NV_VFIO_DEVICE_STATE_MIGRATION_RESUME;
    }
    return NV_VFIO_DEVICE_STATE_NONE;
}

static int nv_vgpu_vfio_migration_set_state(vgpu_dev_t *vgpu_dev, NvU32 device_state)
{
    int ret = 0;
    NV_STATUS status = NV_OK;

    if (!vgpu_dev->mdev)
        return -ENODEV;

    vgpu_dev->migration_state = nv_translate_device_state(device_state, vgpu_dev->migration_state);

    if ((vgpu_dev->migration_state == NV_VFIO_DEVICE_STATE_MIGRATION_PRECOPY_ACTIVE) ||
        (vgpu_dev->migration_state == NV_VFIO_DEVICE_STATE_MIGRATION_STOPNCOPY_ACTIVE))
    {
        if (vgpu_dev->staging_buf_base == NULL)
        {
            vgpu_dev->staging_buf_base = vmalloc_user(NV_VFIO_VGPU_MIGRATION_REGION_SIZE_MMAP);
            if (vgpu_dev->staging_buf_base == NULL)
            {
                NV_VGPU_DEV_LOG(VGPU_ERR, vgpu_dev->mdev,
                                "Failed to allocated staging buffer\n");
                return -ENOMEM;
            }
        }
    }

    if (vgpu_dev->migration_state == NV_VFIO_DEVICE_STATE_NONE)
    {
        vgpu_dev->vfio_device_state = device_state;
        return 0;
    }
    else if (vgpu_dev->migration_state == NV_VFIO_DEVICE_STATE_RUNNING) {
        vgpu_dirty_pfn_t *dpfns, *tmp;

        memset(&vgpu_dev->bytes, 0, sizeof(vgpu_dev->bytes));
        vgpu_dev->bytes.read_pending = NV_FALSE;

        /* Free dirty pfn reported list */
        if (!list_empty(&vgpu_dev->dirty_pfn_reported_list)) {
            list_for_each_entry_safe(dpfns, tmp, &vgpu_dev->dirty_pfn_reported_list, next) {
                list_del(&dpfns->next);
                NV_KFREE(dpfns, sizeof(vgpu_dirty_pfn_t));
            }
        }

#if defined(DEBUG)
        vgpu_dev->bytes_transferred = 0;
        vgpu_dev->dirty_pfn_count = 0;
#endif
    }

    vgpu_dev->return_status = -1;

    status = nv_vgpu_dev_post_event(vgpu_dev, NV_VFIO_VGPU_EVENT_MIGRATION_STATE);
    if (status != NV_OK)
    {
        ret = -EIO;
        goto set_state_exit;
    }

    ret = wait_event_interruptible_timeout(vgpu_dev->wait_queue,
                                           (vgpu_dev->return_status >= 0),
                                           msecs_to_jiffies(WAITQUEUE_TIMEOUT_SECONDS));

    if (ret == 0 && vgpu_dev->return_status == -1)
    {
        vgpu_dev->return_status = NV_ERR_TIMEOUT;
        ret = -ETIMEDOUT;
    }
    else if (vgpu_dev->return_status == NV_OK) {
        NV_VGPU_DEV_LOG(VGPU_INFO, vgpu_dev->mdev,
                        "Current migration state: %u\n", vgpu_dev->migration_state);
        vgpu_dev->vfio_device_state = device_state;
        ret = 0;
    }

set_state_exit:
    if (vgpu_dev->migration_state == NV_VFIO_DEVICE_STATE_RUNNING)
    {
        if (vgpu_dev->staging_buf_base)
        {
            nv_vfree(vgpu_dev->staging_buf_base, NV_VFIO_VGPU_MIGRATION_REGION_SIZE_MMAP);
            vgpu_dev->staging_buf_base = NULL;
        }
    }

    return ret;
}
#endif

static int nv_vgpu_vfio_read_device_buffer(vgpu_dev_t *vgpu_dev, NvU64 *bytes_written)
{
    int ret = 0;
    NV_STATUS status = NV_OK;

    if (!vgpu_dev->mdev)
        return -ENODEV;

    vgpu_dev->return_status = -1;
    status = nv_vgpu_dev_post_event(vgpu_dev, NV_VFIO_VGPU_EVENT_READ_DEVICE_BUFFER);
    if (status != NV_OK)
        return -EIO;

    ret = wait_event_interruptible_timeout(vgpu_dev->wait_queue,
                                           (vgpu_dev->return_status >= 0),
                                           msecs_to_jiffies(WAITQUEUE_TIMEOUT_SECONDS));

    if (ret == 0 && vgpu_dev->return_status == -1)
    {
        vgpu_dev->return_status = NV_ERR_TIMEOUT;
        return -ETIMEDOUT;
    }
    else if (vgpu_dev->return_status == NV_OK) {
        *bytes_written = vgpu_dev->bytes.written;
        if (vgpu_dev->bytes.written != 0)
            vgpu_dev->bytes.read_pending = NV_TRUE;
        return 0;
    }

    return -EIO;
}

static int nv_vgpu_vfio_write_device_buffer(vgpu_dev_t *vgpu_dev, NvU64 data_size)
{
    int ret = 0;
    NV_STATUS status = NV_OK;

    if (!vgpu_dev->mdev)
        return -ENODEV;

    vgpu_dev->return_status = -1;
    vgpu_dev->bytes.written = data_size;

    status = nv_vgpu_dev_post_event(vgpu_dev, NV_VFIO_VGPU_EVENT_WRITE_DEVICE_BUFFER);
    if (status != NV_OK)
        return -EIO;

    ret = wait_event_interruptible_timeout(vgpu_dev->wait_queue,
                                           (vgpu_dev->return_status >= 0),
                                           msecs_to_jiffies(WAITQUEUE_TIMEOUT_SECONDS));

    if (ret == 0 && vgpu_dev->return_status == -1)
    {
        vgpu_dev->return_status = NV_ERR_TIMEOUT;
        return -ETIMEDOUT;
    }
    else if (vgpu_dev->return_status == NV_OK) {
        return 0;
    }

    return -EIO;
}

#if defined(NV_VFIO_DEVICE_MIGRATION_INFO_PRESENT) && defined(NV_VFIO_DEVICE_MIGRATION_HAS_START_PFN)
#define BITS_PER_CHAR           8

#define BIT_CHAR_MASK(nr)       (1 << ((nr) % BITS_PER_CHAR))
#define BIT_CHAR(nr)            ((nr) / BITS_PER_CHAR)

/*
 * set_bit - Set a bit in memory
 * @nr: the bit to set
 * @addr: the address to start counting from
 */
static inline void set_dirty_pfn_bit(NvU64 nr, NvU8 *addr)
{
    NvU8 mask = BIT_CHAR_MASK(nr);
    NvU8 *p = addr + BIT_CHAR(nr);

    *p  |= mask;
}

static int nv_vgpu_vfio_migration_dirty_pfns(vgpu_dev_t *vgpu_dev)
{
    NvU64 i = vgpu_dev->dirty_pfns.counter, dirty_count = 0, k = 0;
    NvU64 pfns_to_copy;
    vgpu_dirty_pfn_t *dpfns;

    if (vgpu_dev->migration_state != NV_VFIO_DEVICE_STATE_MIGRATION_STOPNCOPY_ACTIVE)
        return 0;

    if (!list_empty(&vgpu_dev->dirty_pfn_reported_list)) {
        list_for_each_entry(dpfns, &vgpu_dev->dirty_pfn_reported_list, next) {
            if ((dpfns->start_pfn == vgpu_dev->dirty_pfns.start_pfn) &&
                (dpfns->total_pfns == vgpu_dev->dirty_pfns.total_pfns) &&
                (dpfns->total_pfns == dpfns->counter)) {
                // if pfns in requested range are already reported dirty, then
                // skip reporting
                goto dirty_pfns_exit;
            }
        }
    }

    pfns_to_copy = (vgpu_dev->dirty_pfns.total_pfns - vgpu_dev->dirty_pfns.counter);

    if (pfns_to_copy/BITS_PER_CHAR > NV_VFIO_VGPU_MIGRATION_REGION_SIZE_MMAP) {
        vgpu_dev->dirty_pfns.counter += NV_VFIO_VGPU_MIGRATION_REGION_SIZE_MMAP * BITS_PER_CHAR;
    } else {
        vgpu_dev->dirty_pfns.counter += pfns_to_copy;
    }

    while (i < vgpu_dev->dirty_pfns.counter)
    {
        // look into vgpu_dev->mapping_cache
        if (vgpu_dev->mapping_cache &&
            (vgpu_dev->vfio_max_gpfn >= ( vgpu_dev->dirty_pfns.start_pfn + i)) &&
            (vgpu_dev->mapping_cache[vgpu_dev->dirty_pfns.start_pfn + i] != NULL))
        {
                set_dirty_pfn_bit(k, vgpu_dev->mig_buffer_base);
                dirty_count++;

        }
        else if (!RB_EMPTY_ROOT(&vgpu_dev->gpfn_list))
        {
            // look into vgpu_dev->gpfn_list
            gpfn_node_t *gpfn_node = NULL;

            gpfn_node = find_gpfn_from_list(vgpu_dev, vgpu_dev->dirty_pfns.start_pfn + i);
            if (gpfn_node)
            {
                set_dirty_pfn_bit(k, vgpu_dev->mig_buffer_base);
                dirty_count++;
            }
        }

        i++;
        k++;
    }

    if (vgpu_dev->dirty_pfns.total_pfns == vgpu_dev->dirty_pfns.counter) {
        vgpu_dirty_pfn_t *tmp_dpfns;

        NV_KMALLOC(tmp_dpfns, sizeof(vgpu_dirty_pfn_t));
        if (tmp_dpfns == NULL)
            return -ENOMEM;

        memcpy(tmp_dpfns, &vgpu_dev->dirty_pfns, sizeof(vgpu_dev->dirty_pfns));

        list_add(&tmp_dpfns->next, &vgpu_dev->dirty_pfn_reported_list);
    }

dirty_pfns_exit:
    if (dirty_count == 0)
        vgpu_dev->dirty_pfns.copied_pfns = 0;
    else
        vgpu_dev->dirty_pfns.copied_pfns = k;

    NV_VGPU_DEV_LOG(VGPU_INFO, vgpu_dev->mdev,
                    "%s: start_pfn: 0x%llx pfn_count: 0x%llx dirty_count: 0x%llx, copied_pfns: 0x%llx \n",
                    __FUNCTION__, vgpu_dev->dirty_pfns.start_pfn,
                    vgpu_dev->dirty_pfns.total_pfns, dirty_count,
                    vgpu_dev->dirty_pfns.copied_pfns);
    return 0;
}
#endif


static void nv_vgpu_vfio_hw_config_access(struct pci_dev *pdev, char *buf,
                                   size_t count, NvU64 offset, NvBool is_write)
{
    switch (count) {
        case 4 :
            if (is_write)
                pci_write_config_dword(pdev, offset, *(NvU32 *)buf);
            else
                pci_read_config_dword(pdev, offset, (NvU32 *)buf);
            break;

        case 2 :
            if (is_write)
                pci_write_config_word(pdev, offset, *(NvU16 *)buf);
            else
                pci_read_config_word(pdev, offset, (NvU16 *)buf);
            break;

        case 1 :
            if (is_write)
                pci_write_config_byte(pdev, offset, *(NvU8 *)buf);
            else
                pci_read_config_byte(pdev, offset, (NvU8 *)buf);
            break;
    }

}

NV_STATUS
nv_vfio_vgpu_vf_reg_access_from_plugin(struct pci_dev *pdev, VGPU_EMUL_SPACE_T emulSpace,
                                        NvU64 offset, NvU32 width, NvU8* data, NvBool isWrite)
{
    if (!pdev->is_virtfn)
        return NV_ERR_INVALID_ARGUMENT;

    switch (emulSpace)
    {
        case VGPU_EMUL_CONFIG_SPACE:
            nv_vgpu_vfio_hw_config_access(pdev, data, width, offset, isWrite);
            return NV_OK;

        default:
            return NV_ERR_INVALID_ARGUMENT;
    }
}


static ssize_t nv_vgpu_vfio_access(struct mdev_device *mdev, char *buf,
                                   size_t count, loff_t pos, NvBool is_write)
{
    NV_STATUS status = NV_OK;
    int ret = 0;
    struct pci_dev *pdev;
    vgpu_dev_t *vgpu_dev = NULL;
    NvU32 index = 0;
    VGPU_EMUL_SPACE_T emul_space;
    NvU64 offset = 0;

    NvBool access_via_plugin = NV_FALSE;


    pdev = to_pci_dev(NV_GET_MDEV_PARENT(mdev));
    if (!pdev || !buf)
    {
        ret = -EINVAL;
        goto reg_access_exit;
    }

    index = DRF_VAL64(_VGPU_VFIO, _PGOFF, _PCI_INDEX, pos);
    offset = DRF_VAL64(_VGPU_VFIO, _PGOFF, _PCI_OFFSET, pos);

    vgpu_dev = mdev_get_drvdata(mdev);
    if (!vgpu_dev || !vgpu_dev->vconfig)
    {
        ret = -ENODEV;
        goto reg_access_exit;
    }

    down(&vgpu_dev->ops_lock);

    switch (index)
    {
        case VFIO_PCI_CONFIG_REGION_INDEX:
            emul_space = VGPU_EMUL_CONFIG_SPACE;

            if (pdev->is_virtfn)
            {
                if ((offset >= pdev->msix_cap) && (offset < pdev->msix_cap + PCI_CAP_MSIX_SIZEOF))
                {
                    nv_vgpu_vfio_hw_config_access(pdev, buf, count, offset, is_write);
                    ret = count;
                }
                else
                {
                    access_via_plugin = NV_TRUE;
                }
            }

            break;

        case VFIO_PCI_BAR0_REGION_INDEX ... VFIO_PCI_BAR4_REGION_INDEX:
            emul_space = VGPU_EMUL_MMIO;

            if (pdev->is_virtfn)
            {
                access_via_plugin = NV_TRUE;
            }

            if (!vgpu_dev->region_info[index].start)
                vgpu_read_base(vgpu_dev);

            offset = vgpu_dev->region_info[index].start + offset;
            break;
#if defined(NV_VFIO_DEVICE_MIGRATION_INFO_PRESENT)
        case NV_VGPU_VFIO_MIGRATION_REGION:
            if (is_write)
            {
                if (offset == offsetof(struct vfio_device_migration_info, device_state))
                {
                    NvU32 *data = (NvU32 *)buf;

                    ret = nv_vgpu_vfio_migration_set_state(vgpu_dev, *data);
                }
                else if (offset == offsetof(struct vfio_device_migration_info, data_offset))
                {
#if defined(NV_VFIO_DEVICE_MIGRATION_HAS_START_PFN)
                    NvU64 *data = (NvU64 *)buf;

                    if (*data != NV_VFIO_VGPU_MIGRATION_REGION_DATA_OFFSET)
                    {
                        NV_VGPU_DEV_LOG(VGPU_ERR, vgpu_dev->mdev,
                                        "Migration region data_offset: Incorrect data offset 0x%llx \n",
                                        *data);
                        ret = -EINVAL;
                    }
#else
                    /* data_offset field if read-only, return invalid if tried to write */
                    ret = -EINVAL;
#endif
                }
                else if (offset == offsetof(struct vfio_device_migration_info, data_size))
                {
                    ret = nv_vgpu_vfio_write_device_buffer(vgpu_dev, *(NvU64 *)buf);
                }
#if defined(NV_VFIO_DEVICE_MIGRATION_HAS_START_PFN)
                else if (offset == offsetof(struct vfio_device_migration_info, start_pfn))
                {
                    memset(&vgpu_dev->dirty_pfns, 0, sizeof(vgpu_dirty_pfn_t));
                    vgpu_dev->dirty_pfns.start_pfn = *(NvU64 *)buf;
                }
                else if (offset == offsetof(struct vfio_device_migration_info, page_size))
                {
                    vgpu_dev->dirty_pfns.page_size = *(NvU64 *)buf;
                }
                else if (offset == offsetof(struct vfio_device_migration_info, total_pfns))
                {
                    vgpu_dev->dirty_pfns.total_pfns = *(NvU64 *)buf;
                }
#endif
                else
                    ret = -EINVAL;
            }
            else
            {
                if (offset == offsetof(struct vfio_device_migration_info, pending_bytes))
                {
                    NvU64 pending = 0;
                    if (vgpu_dev->bytes.read_pending == NV_FALSE)
                    {
                        ret = nv_vgpu_vfio_read_device_buffer(vgpu_dev, &pending);
                    }
                    else
                        pending = vgpu_dev->bytes.written;

                    if (!ret)
                    {
                        if ((pending == NV_VFIO_VGPU_MIGRATION_REGION_SIZE_MMAP) &&
                            (vgpu_dev->migration_state == NV_VFIO_DEVICE_STATE_MIGRATION_PRECOPY_ACTIVE))
                        {
                            pending = vgpu_dev->bytes.pending;
                        }

                        *(NvU64 *)buf = pending;
                    }
                }
#if defined(NV_VFIO_DEVICE_MIGRATION_HAS_START_PFN)
                else if (offset == offsetof(struct vfio_device_migration_info, data_offset))
                {
                    *(NvU64 *)buf = NV_VFIO_VGPU_MIGRATION_REGION_DATA_OFFSET;

                    if (vgpu_dev->bytes.read_pending == NV_TRUE)
                        memcpy(vgpu_dev->mig_buffer_base,
                               vgpu_dev->staging_buf_base, vgpu_dev->bytes.written);
#if defined(DEBUG)
                    vgpu_dev->bytes_transferred += vgpu_dev->bytes.written;
#endif
                    vgpu_dev->bytes.read_pending = NV_FALSE;
                }
                else if (offset == offsetof(struct vfio_device_migration_info, copied_pfns))
                {
                    ret = nv_vgpu_vfio_migration_dirty_pfns(vgpu_dev);
                    if (!ret)
                        *(NvU64 *)buf = vgpu_dev->dirty_pfns.copied_pfns;
                }
#else
                else if (offset == offsetof(struct vfio_device_migration_info, data_offset))
                {
                    *(NvU64 *)buf = NV_VFIO_VGPU_MIGRATION_REGION_DATA_OFFSET;
                }
                else if (offset == offsetof(struct vfio_device_migration_info, data_size))
                {
                    *(NvU64 *)buf = vgpu_dev->bytes.written;
                    if ((vgpu_dev->bytes.read_pending == NV_TRUE) && vgpu_dev->staging_buf_base)
                    {
                        memcpy(vgpu_dev->mig_buffer_base,
                               vgpu_dev->staging_buf_base, vgpu_dev->bytes.written);
                    }
#if defined(DEBUG)
                    vgpu_dev->bytes_transferred += vgpu_dev->bytes.written;
#endif
                    vgpu_dev->bytes.read_pending = NV_FALSE;
                }
                else if (offset == offsetof(struct vfio_device_migration_info, device_state))
                {
                    *(NvU64 *)buf = vgpu_dev->vfio_device_state;
                }
#endif
            }

            if (ret < 0)
            {
                status = NV_ERR_INVALID_STATE;
            }
            else
            {
                ret = count;
            }

            NV_VGPU_DEV_LOG(VGPU_INFO, vgpu_dev->mdev,
                            "%s MIGRATION %s offset: 0x%llx size: 0x%lx ret: %d, data: 0x%llx\n",
                            __FUNCTION__, is_write? "Write" : "Read", offset, count, ret, *(NvU64 *)buf);
            goto unlock;
#endif
        default:
            ret = -EINVAL;
            status = NV_ERR_INVALID_ARGUMENT;
            goto unlock;
    }

    /*
     * Do not send PCI config space write events to plugin during VM restore.
     * Plugin already restores the PCI cofig space later in write_device_buffer().
     */
    if ((vgpu_dev->migration_state == NV_VFIO_DEVICE_STATE_MIGRATION_RESUME) &&
        (emul_space == VGPU_EMUL_CONFIG_SPACE) && (is_write == NV_TRUE))
    {
        nv_update_config_space(vgpu_dev, offset, buf, count);
        ret = count;
        goto unlock;
    }


    if (!pdev->is_virtfn || access_via_plugin)

    {
        vgpu_dev->reg_info.offset = offset;
        vgpu_dev->reg_info.data = buf;
        vgpu_dev->reg_info.count = count;
        vgpu_dev->reg_info.is_write = is_write;
        vgpu_dev->reg_info.emul_space = emul_space;
        vgpu_dev->reg_info.status = -1;

        status = nv_vgpu_dev_post_event(vgpu_dev, NV_VFIO_VGPU_EVENT_VM_REG_ACCESS);
        if (status != NV_OK)
            goto unlock;

        ret = wait_event_interruptible_timeout(vgpu_dev->reg_info.wait,
                                               (vgpu_dev->reg_info.status >= 0),
                                               msecs_to_jiffies(8000));

        if (ret == 0 && vgpu_dev->reg_info.status == -1)  /* Timeout occured */
        {
            vgpu_dev->reg_info.status = NV_ERR_TIMEOUT;
            ret = -ETIMEDOUT;
        }
        else if (vgpu_dev->reg_info.status == NV_OK)
        {
            ret = count;
            if (is_write && (emul_space == VGPU_EMUL_CONFIG_SPACE))
                nv_update_config_space(vgpu_dev, offset, buf, count);
        }
        else
            ret = -EIO;

        status = vgpu_dev->reg_info.status;
    }

unlock:
    up(&vgpu_dev->ops_lock);

reg_access_exit:
    if (ret < 0)
    {
        NV_VGPU_DEV_LOG(VGPU_ERR, mdev,
                        "Register %s failed. index: %d  offset: 0x%llx status: 0x%x %s",
                         is_write ? "write": "read", index, offset, status,
                         (ret == -ETIMEDOUT) ? "Timeout occured\n" : "\n");
    }

    return ret;
}

static ssize_t nv_vgpu_vfio_read(struct mdev_device *mdev, char __user *buf,
                                 size_t count, loff_t *ppos)
{
    NvU64 val;
    NvU32 size, done = 0;

    while (count)
    {
#if defined(NV_VFIO_DEVICE_MIGRATION_INFO_PRESENT)
        NvU32 index = DRF_VAL64(_VGPU_VFIO, _PGOFF, _PCI_INDEX, *ppos);

        // allow 64-bit access only for MIGRATION region
        if ((index == NV_VGPU_VFIO_MIGRATION_REGION) &&
            (count >= 8) && !(*ppos % 8))
            size = 8;
        else
#endif
        {
            if (count >= 4 && !(*ppos % 4))
                size = 4;
            else if (count >= 2 && !(*ppos % 2))
                size = 2;
            else
                size = 1;
        }

       if (nv_vgpu_vfio_access(mdev, (char *) &val, size, *ppos, NV_FALSE) <= 0)
            goto read_err;

        if (copy_to_user(buf, &val, size) != 0)
            goto read_err;

        *ppos += size;
        buf += size;
        count -= size;
        done += size;
    }

    return done;
read_err:
    return -EFAULT;
}

static ssize_t nv_vgpu_vfio_write(struct mdev_device *mdev, const char __user *buf,
                                  size_t count, loff_t *ppos)
{
    NvU64 val;
    NvU32 size, done = 0;

    while (count)
    {
#if defined(NV_VFIO_DEVICE_MIGRATION_INFO_PRESENT)
        NvU32 index = DRF_VAL64(_VGPU_VFIO, _PGOFF, _PCI_INDEX, *ppos);

        // allow 64-bit access only for MIGRATION region
        if ((index == NV_VGPU_VFIO_MIGRATION_REGION) &&
            (count >= 8) && !(*ppos % 8))
            size = 8;
        else
#endif
        {
            if (count >= 4 && !(*ppos % 4))
                size = 4;
            else if (count >= 2 && !(*ppos % 2))
                size = 2;
            else
                size = 1;
        }

        if (copy_from_user(&val, buf, size) != 0)
            goto write_err;
        if (nv_vgpu_vfio_access(mdev, (char *)&val, count, *ppos, NV_TRUE) <= 0)
            goto write_err;

        *ppos += size;
        buf += size;
        count -= size;
        done += size;
    }

    return done;
write_err:
    return -EFAULT;
}

static int nv_vgpu_vfio_open(struct mdev_device *mdev)
{
    NV_STATUS status = NV_OK;
    int ret = 0;
    struct pci_dev *pdev;
    struct pci_dev *parent_device;
    char mdev_params[VGPU_CONFIG_PARAMS_MAX_LENGTH] = {0};
    vgpu_dev_t *vgpu_dev = NULL, *tmp_vgpu_dev = NULL;
    NvU32 elapsed_time = 0;
    NvBool vgpu_exited = NV_FALSE, attach_device = NV_FALSE;

    if (!mdev)
        return -EINVAL;

    pdev = to_pci_dev(NV_GET_MDEV_PARENT(mdev));
    if (!pdev)
        return -EINVAL;

    if (pdev->is_virtfn)
        parent_device = pdev->physfn;
    else

        parent_device = pdev;

    down(&vgpu_devices.vgpu_dev_list_lock);
    vgpu_dev = mdev_get_drvdata(mdev);
    if (!vgpu_dev)
    {
        up(&vgpu_devices.vgpu_dev_list_lock);
        return -EINVAL;
    }
    up(&vgpu_devices.vgpu_dev_list_lock);

    down(&vgpu_dev->ops_lock);
    while (elapsed_time < VGPU_EXIT_TIMEOUT_MILLISECONDS)
    {
        down(&vgpu_dev->dev_lock);
        if (!list_empty(&vgpu_dev->file_private_list))
        {
            up(&vgpu_dev->dev_lock);
            msleep(SLEEP_TIME_MILLISECONDS);
        }
        else
        {
            up(&vgpu_dev->dev_lock);
            vgpu_exited = NV_TRUE;
            break;
        }
        elapsed_time += SLEEP_TIME_MILLISECONDS;
    }

    if (vgpu_exited == NV_FALSE)
    {
        up(&vgpu_dev->ops_lock);
        NV_VGPU_DEV_LOG(VGPU_ERR, mdev, "Existing vgpu process not cleaned up yet. Aborting...\n");
        return -EBUSY;
    }

    if (!try_module_get(THIS_MODULE))
    {
        up(&vgpu_dev->ops_lock);
        return -ENODEV;
    }

    if (atomic_read(&vgpu_dev->usage_count) >= 1)
    {
        atomic_inc(&vgpu_dev->usage_count);
        up(&vgpu_dev->ops_lock);
        return 0;
    }

    snprintf(mdev_params, VGPU_CONFIG_PARAMS_MAX_LENGTH, "vgpu_type_id=%d",
             vgpu_dev->vgpu_type_id);

    if (strlen(vgpu_dev->config_params))
        snprintf(mdev_params, VGPU_CONFIG_PARAMS_MAX_LENGTH, "%s,%s",
                 mdev_params, vgpu_dev->config_params);

    down(&vgpu_devices.start_lock);
    down(&vgpu_devices.vgpu_dev_list_lock);
    list_for_each_entry(tmp_vgpu_dev, &vgpu_devices.vgpu_dev_list, next)
    {
        if (tmp_vgpu_dev->instance_id == 0 &&
            tmp_vgpu_dev->qemu_pid == current->pid)
        {
            attach_device = NV_TRUE;
            memcpy(vgpu_dev->vm_name, tmp_vgpu_dev->vm_name, VM_NAME_SIZE);
            break;
        }
    }
    up(&vgpu_devices.vgpu_dev_list_lock);

    vgpu_dev->return_status = -1;
    vgpu_dev->qemu_pid = current->pid;
    vgpu_dev->device_state = NV_VGPU_DEV_OPENED;
#if defined(DEBUG)
    vgpu_dev->bytes_transferred = 0;
    vgpu_dev->dirty_pfn_count = 0;
#endif
    rm_vgpu_vfio_ops.update_request(NV_GET_MDEV_UUID(mdev), NULL,
                                   NULL, vgpu_dev->device_state, mdev_params);

    if (attach_device == NV_TRUE)
    {
        /* Raise event on first vgpu device. wait on the current vgpu_dev's waitqueue */
        ret = nv_vgpu_dev_post_event(tmp_vgpu_dev, NV_VFIO_VGPU_EVENT_ATTACH_DEVICE);
        if (ret != NV_OK)
        {
            NV_VGPU_DEV_LOG(VGPU_ERR, mdev, "Post attach device event failed\n");
            goto open_exit;
        }
    }
    else
    {
        status = rm_vgpu_vfio_ops.vgpu_start(NV_GET_MDEV_UUID(mdev),
                                             (void *) &vgpu_dev->wait_queue,
                                             &vgpu_dev->return_status,
                                             vgpu_dev->vm_name,
                                             vgpu_dev->qemu_pid);
        if (status != NV_OK)
        {
            ret = -EIO;
            goto open_exit;
        }
        vgpu_dev->instance_id = 0;
    }

    ret = wait_event_interruptible_timeout(vgpu_dev->wait_queue,
                                           (vgpu_dev->return_status >= 0),
                                           msecs_to_jiffies(10000));

    if (ret == 0 && vgpu_dev->return_status == -1)
    {
        vgpu_dev->return_status = NV_ERR_TIMEOUT;
        ret = -ETIMEDOUT;
    }
    else if (vgpu_dev->return_status == NV_OK)
    {
        struct device *dev;
        unsigned long events = VFIO_IOMMU_NOTIFY_DMA_UNMAP;
        vgpu_dev->nb.notifier_call = nv_vgpu_vfio_notifier;

        dev = NV_GET_MDEV_DEV(mdev);

        if ((ret = NV_VFIO_REGISTER_NOTIFIER(dev, events, &vgpu_dev->nb))
            || events != 0)
        {
            NV_VGPU_DEV_LOG(VGPU_ERR, mdev,
                            "Failed to register notifier. ret: %d\n", ret);
            goto close_vgpu;
        }

        status = rm_vgpu_vfio_ops.get_sparse_mmap(parent_device,
                                                  NV_GET_MDEV_UUID(mdev),
                                                  &vgpu_dev->offsets,
                                                  &vgpu_dev->sizes,
                                                  &vgpu_dev->num_areas);
        if (status != NV_OK)
        {
            NV_VGPU_DEV_LOG(VGPU_ERR, mdev,
                            "Failed to get requested sparse MMAP region, status = 0x%x",
                            status);
            ret = -EIO;
            goto close_vgpu;
        }
        ret = 0;
    }
    else
        ret = -EIO;

    status = vgpu_dev->return_status;

close_vgpu:
    if (ret != 0)
    {
        int sig_ret;
        down(&vgpu_dev->dev_lock);
        if (!list_empty(&vgpu_dev->file_private_list) &&
            vgpu_dev->vgpu_task && !(vgpu_dev->vgpu_task->flags & PF_EXITING))
        {
            sig_ret = send_sig_info(SIGKILL, SEND_SIG_PRIV,
                                    vgpu_dev->vgpu_task);
            NV_VGPU_DEV_LOG(VGPU_INFO, mdev, "Sent SIGKILL to vgpu process."
                            " ret: %d\n", sig_ret);
        }
        up(&vgpu_dev->dev_lock);
    }
open_exit:
    if (ret != 0)
    {
        NV_VGPU_DEV_LOG(VGPU_ERR, mdev, "start failed. status: 0x%x %s",
                        status, (ret == -ETIMEDOUT) ? "Timeout Occured\n" : "\n");

        vgpu_dev->device_state = NV_VGPU_DEV_UNUSED;
        module_put(THIS_MODULE);
    }
    else
    {
        vgpu_dev->device_state = NV_VGPU_DEV_IN_USE;
        atomic_inc(&vgpu_dev->usage_count);
    }

    rm_vgpu_vfio_ops.update_request(NV_GET_MDEV_UUID(mdev), NULL,
                                    NULL, vgpu_dev->device_state, NULL);

    up(&vgpu_devices.start_lock);
    up(&vgpu_dev->ops_lock);
    return ret;
}

struct rb_node **find_bar1_node_parent(struct rb_node **parent, NvU64 guest_addr,
                                       NvU64 size, vgpu_dev_t *vgpu_dev)
{
    struct rb_node **link = &vgpu_dev->bar1_list.rb_node;
    bar1_node_t *bar1_node = NULL;

    while (*link)
    {
        *parent = *link;
        bar1_node = rb_entry(*parent, bar1_node_t, node);

        if ((guest_addr + size - 1) < bar1_node->guest_addr)
            link = &(*link)->rb_left;
        else if (guest_addr >= (bar1_node->guest_addr + bar1_node->size))
            link = &(*link)->rb_right;
        else
            break;
    }

    return link;
}

static bar1_node_t *nv_add_bar1_mapping(vgpu_dev_t *vgpu_dev, NvU64 host_addr,
                                        NvU64 guest_addr, NvU64 size,
                                        NvBool is_dummy)
{
    struct rb_node **link, *parent = NULL;
    bar1_node_t *bar1_node = NULL;
    NV_STATUS status = NV_OK;

    link = find_bar1_node_parent(&parent, guest_addr, size, vgpu_dev);

    if ((*link) == NULL)
    {
        NV_KMALLOC(bar1_node, sizeof(bar1_node_t));
        if (bar1_node == NULL)
            return NULL;

        memset(bar1_node, 0, sizeof(bar1_node_t));
        bar1_node->guest_addr = guest_addr;
        bar1_node->host_addr = host_addr;
        bar1_node->size = size;
        bar1_node->is_dummy = is_dummy;
    }
    else
    {
        bar1_node = rb_entry(*link, bar1_node_t, node);

        if (bar1_node && bar1_node->is_dummy == NV_TRUE)
        {
            // Invalidate dummy mapping and update with new one
            if (bar1_node->is_validated)
            {
                status = nv_vgpu_invalidate_guest_mmio(bar1_node->host_addr,
                                                       bar1_node->guest_addr,
                                                       bar1_node->is_dummy,
                                                       bar1_node->size, vgpu_dev);
                if (status != NV_OK)
                    return NULL;
            }
            rb_erase(&bar1_node->node, &vgpu_dev->bar1_list);

            memset(bar1_node, 0, sizeof(bar1_node_t));
            bar1_node->guest_addr = guest_addr;
            bar1_node->host_addr = host_addr;
            bar1_node->size = size;
            bar1_node->is_dummy = NV_FALSE;

            parent = NULL;
            link = find_bar1_node_parent(&parent, guest_addr, size, vgpu_dev);
            if ((*link) != NULL)
                return NULL;
        }
        else
            return NULL;
    }

    rb_link_node(&bar1_node->node, parent, link);
    rb_insert_color(&bar1_node->node, &vgpu_dev->bar1_list);

    return bar1_node;
}

static bar1_node_t *nv_find_bar1_mapping(vgpu_dev_t *vgpu_dev, NvU64 guest_addr)
{
    struct rb_node *node = vgpu_dev->bar1_list.rb_node;
    bar1_node_t *bar1_node;

    while (node)
    {
        bar1_node = rb_entry(node, bar1_node_t, node);

        if (guest_addr < bar1_node->guest_addr)
            node = node->rb_left;
        else if (guest_addr >= (bar1_node->guest_addr + bar1_node->size))
            node = node->rb_right;
        else
            return bar1_node;
    }

    return NULL;
}

NV_STATUS nv_vgpu_update_mapping(void *pvgpu_ref, NvU64 guest_addr,
                                 NvU64 host_addr, NvU64 size,
                                 NvBool is_add, NvBool is_dummy)
{
    vgpu_dev_t *vgpu_dev = pvgpu_ref;
    bar1_node_t *bar1_node = NULL;
    NV_STATUS status = NV_OK;
    NvU32 i = 0, index = NV_VGPU_VFIO_REGIONS_MAX;
    struct pci_dev *pdev;
    struct pci_dev *parent_device;

    if (is_dummy == NV_FALSE)
    {
        pdev = to_pci_dev(NV_GET_MDEV_PARENT(vgpu_dev->mdev));
        if (!pdev)
            return -EINVAL;

        if (pdev->is_virtfn)
            parent_device = pdev->physfn;
        else

            parent_device = pdev;

        for (i = VFIO_PCI_BAR0_REGION_INDEX; i < VFIO_PCI_ROM_REGION_INDEX; i++)
        {
            if ((host_addr >= vgpu_dev->region_info[i].phys_start) &&
                (host_addr < (vgpu_dev->region_info[i].phys_start +
                              pci_resource_len(parent_device, i))))
            {
                index = i;
                break;
            }
        }


        if (pdev->is_virtfn && index != VFIO_PCI_BAR0_REGION_INDEX)
        {
            status = NV_OK;
            goto bar1_map_exit;
        }


        if (index == VFIO_PCI_BAR0_REGION_INDEX)
        {
            for (i = 0; i < vgpu_dev->num_areas; i++)
            {
                if (((host_addr - vgpu_dev->region_info[index].phys_start) == vgpu_dev->offsets[i]) &&
                    (size == vgpu_dev->sizes[i]))
                {
                    status = NV_OK;
                    goto bar1_map_exit;
                }
            }

            status = NV_ERR_INVALID_ADDRESS;
            goto bar1_map_exit;
        }
        else if (index != VFIO_PCI_BAR1_REGION_INDEX)
        {
            status = NV_ERR_INVALID_ARGUMENT;
            goto bar1_map_exit;
        }
    }

    if (is_add == NV_TRUE)
    {
        bar1_node = nv_add_bar1_mapping(vgpu_dev, host_addr, guest_addr,
                                        size, NV_FALSE);
        if (bar1_node == NULL)
            status = NV_ERR_INVALID_ARGUMENT;
    }
    else
    {
        bar1_node = nv_find_bar1_mapping(vgpu_dev, guest_addr);
        if (bar1_node == NULL)
        {
            status = NV_ERR_OBJECT_NOT_FOUND;
            goto bar1_map_exit;
        }

        if (guest_addr != bar1_node->guest_addr ||
            host_addr != bar1_node->host_addr ||
            size != bar1_node->size)
        {
            status = NV_ERR_INVALID_ADDRESS;
            goto bar1_map_exit;
        }

        if (bar1_node->is_validated)
            status = nv_vgpu_invalidate_guest_mmio(bar1_node->host_addr,
                                                   bar1_node->guest_addr,
                                                   bar1_node->is_dummy,
                                                   bar1_node->size, vgpu_dev);

         rb_erase(&bar1_node->node, &vgpu_dev->bar1_list);
         NV_KFREE(bar1_node, sizeof(bar1_node_t));
    }

bar1_map_exit:
    if (status != NV_OK)
        NV_VGPU_DEV_LOG(VGPU_ERR, vgpu_dev->mdev,
                        "Failed to %s mapping. status:  0x%x index: 0x%x guest_addr: 0x%llx "
                        "host_addr: 0x%llx \n", is_add ? "add" : "remove", status, index,
                         guest_addr, host_addr);
    return status;
}

static void delete_all_bar1_mappings(vgpu_dev_t *vgpu_dev)
{
    struct rb_node *node;
    bar1_node_t *bar1_node;

    if (!RB_EMPTY_ROOT(&vgpu_dev->bar1_list))
    {
        while ((node = rb_first(&vgpu_dev->bar1_list)))
        {
            bar1_node = rb_entry(node, bar1_node_t, node);
            nv_vgpu_update_mapping(vgpu_dev, bar1_node->guest_addr,
                                   bar1_node->host_addr, bar1_node->size,
                                   NV_FALSE, bar1_node->is_dummy);
        }
    }

    if (vgpu_dev->dummy_page_allocated == NV_TRUE)
    {
        free_page(vgpu_dev->dummy_virt_addr);
        vgpu_dev->dummy_phys_addr = 0;
        vgpu_dev->dummy_virt_addr = 0;
        vgpu_dev->dummy_page_allocated = NV_FALSE;
    }
}

static void cleanup_vgpu_dev(vgpu_dev_t *vgpu_dev)
{
    unsigned long eflags;

    vgpu_dev->qemu_pid = 0;
    vgpu_dev->offsets = NULL;
    vgpu_dev->sizes = NULL;
    vgpu_dev->vgpu_task = NULL;
    vgpu_dev->phys_mappings.bar1_vma = NULL;
    vgpu_dev->num_areas = 0;
    vgpu_dev->instance_id = INVALID_VGPU_INSTANCE_ID;
    vgpu_dev->migration_enabled = NV_FALSE;

    NV_SPIN_LOCK_IRQSAVE(&vgpu_dev->intr_info_lock, eflags);
    memset(&vgpu_dev->intr_info, 0, sizeof(intr_info_t));
    NV_SPIN_UNLOCK_IRQRESTORE(&vgpu_dev->intr_info_lock, eflags);

    vgpu_dev->host_vgpu_dev = NULL;

    if (vgpu_dev->staging_buf_base)
    {
        nv_vfree(vgpu_dev->staging_buf_base, NV_VFIO_VGPU_MIGRATION_REGION_SIZE_MMAP);
        vgpu_dev->staging_buf_base = NULL;
    }

    memset(&vgpu_dev->phys_mappings, 0, sizeof(struct mdev_phys_mapping));
    memset(&vgpu_dev->gpfn_list, 0, sizeof(struct rb_root));
    memset(&vgpu_dev->bar1_list, 0, sizeof(struct rb_root));
    memset(&vgpu_dev->vm_name, 0, VM_NAME_SIZE);
    memset(&vgpu_dev->region_info, 0, (sizeof(region_info_t) * NV_VGPU_VFIO_REGIONS_MAX));
    memset(&vgpu_dev->vfio_info, 0, sizeof(struct vfio_device_info));
    memset(&vgpu_dev->nb, 0, sizeof(struct notifier_block));
    memset(vgpu_dev->vconfig, 0, PCI_EXTENDED_CONFIG_SPACE_SIZE);

}

static void nv_vgpu_clear_mapping_cache(vgpu_dev_t *vgpu_dev)
{
    NvU64 i, ret;
    NvU64 *gpfn_buffer = NULL;
    NvU32 pfn_count = 0;

    if (vgpu_dev->mapping_cache == NULL)
        return;

    gpfn_buffer = (NvU64 *) nv_vmalloc(VFIO_PIN_PAGES_MAX_ENTRIES * sizeof(NvU64));
    if (gpfn_buffer == NULL)
    {
        NV_VGPU_DEV_LOG(VGPU_ERR, vgpu_dev->mdev,
                    "Failed to allocate memory for Guest PFN buffer.\n");
        return;
    }
    memset(gpfn_buffer, 0, VFIO_PIN_PAGES_MAX_ENTRIES * sizeof(NvU64));

    for (i = 0; i <= vgpu_dev->vfio_max_gpfn; i++)
    {
        if (vgpu_dev->mapping_cache[i])
        {
            if ((vgpu_dev->mapping_cache[i] == (mapping_node_t *)GFN_PINNED) ||
                (vgpu_dev->mapping_cache[i]->base_gpfn_pinned == NV_TRUE))
                gpfn_buffer[pfn_count++] = i;

            if (vgpu_dev->mapping_cache[i] != (mapping_node_t *)GFN_PINNED)
            {
                nv_destroy_dma_mappings(vgpu_dev,
                                (mapping_node_t *) vgpu_dev->mapping_cache[i]);
            }
            vgpu_dev->mapping_cache[i] = NULL;
        }

        if (((i == (vgpu_dev->vfio_max_gpfn)) ||
            (pfn_count == VFIO_PIN_PAGES_MAX_ENTRIES)) &&
            pfn_count != 0)
        {
            // unpin these pages
            ret = vfio_unpin_pages(NV_GET_MDEV_DEV(vgpu_dev->mdev),
                                   (long unsigned int *)gpfn_buffer, pfn_count);

            if (ret != pfn_count)
            {
                NV_VGPU_DEV_LOG(VGPU_ERR, vgpu_dev->mdev,
                            "Failed to unpin %u pages.\n", pfn_count);
            }
#if defined(DEBUG)
            vgpu_dev->dirty_pfn_count -= pfn_count;
#endif
            pfn_count = 0;
            memset(gpfn_buffer, 0, VFIO_PIN_PAGES_MAX_ENTRIES * sizeof(NvU64));
        }

    }

    nv_vfree(vgpu_dev->mapping_cache,
             (sizeof(mapping_node_t *) * (vgpu_dev->vfio_max_gpfn + 1)));

    nv_vfree(gpfn_buffer,
             (sizeof(NvU64) * VFIO_PIN_PAGES_MAX_ENTRIES));

    vgpu_dev->mapping_cache = NULL;
    vgpu_dev->vfio_max_gpfn = 0;
}

static void nv_vgpu_vfio_close(struct mdev_device *mdev)
{
    NV_STATUS status = NV_OK;
    vgpu_dev_t *vgpu_dev = NULL;
    struct device *dev;
    int ret = 0;
    unsigned long eflags;

    if (!mdev)
    {
        module_put(THIS_MODULE);
        return;
    }

    vgpu_dev = mdev_get_drvdata(mdev);
    if (!vgpu_dev)
    {
        module_put(THIS_MODULE);
        return;
    }

    down(&vgpu_dev->ops_lock);

    if (atomic_read(&vgpu_dev->usage_count) > 1)
    {
        module_put(THIS_MODULE);
        atomic_dec(&vgpu_dev->usage_count);
        up(&vgpu_dev->ops_lock);
        return;
    }

    NV_SPIN_LOCK_IRQSAVE(&vgpu_dev->intr_info_lock, eflags);
    vgpu_dev->intr_info.ignore_interrupts = NV_TRUE;
    NV_SPIN_UNLOCK_IRQRESTORE(&vgpu_dev->intr_info_lock, eflags);

    vgpu_dev->return_status = -1;
    status = nv_vgpu_dev_post_event(vgpu_dev, NV_VFIO_VGPU_EVENT_VM_SHUTDOWN);
    if (status == NV_OK)
    {
        ret = wait_event_interruptible_timeout(vgpu_dev->wait_queue,
                                               (vgpu_dev->return_status >= 0),
                                               msecs_to_jiffies(WAITQUEUE_TIMEOUT_SECONDS));

        if (ret == 0 && vgpu_dev->return_status == -1)
            vgpu_dev->return_status = NV_ERR_TIMEOUT;
    }
    else
        vgpu_dev->return_status = status;


    NV_SPIN_LOCK_IRQSAVE(&vgpu_dev->intr_info_lock, eflags);
    vgpu_msix_disable(vgpu_dev);
    NV_SPIN_UNLOCK_IRQRESTORE(&vgpu_dev->intr_info_lock, eflags);


    dev = NV_GET_MDEV_DEV(mdev);

    if (NV_VFIO_UNREGISTER_NOTIFIER(dev, &vgpu_dev->nb) != 0)
        NV_VGPU_DEV_LOG(VGPU_ERR, mdev, "Failed to unregister notifier.\n");

    if (vgpu_dev->sparse != NULL)
    {
        int size;
        size = sizeof(*vgpu_dev->sparse) +
               vgpu_dev->num_areas * sizeof(*vgpu_dev->sparse->areas);

        NV_KFREE(vgpu_dev->sparse, size);
        vgpu_dev->sparse = NULL;
    }

    status = vgpu_dev->return_status;

    if (status != NV_OK)
    {
        int sig_ret;
        down(&vgpu_dev->dev_lock);
        if (!list_empty(&vgpu_dev->file_private_list) &&
            vgpu_dev->vgpu_task && !(vgpu_dev->vgpu_task->flags & PF_EXITING))
        {
            sig_ret = send_sig_info(SIGKILL, SEND_SIG_PRIV,
                                    vgpu_dev->vgpu_task);
            NV_VGPU_DEV_LOG(VGPU_INFO, mdev, "Sent SIGKILL to vgpu process."
                            " ret: %d\n", sig_ret);
        }
        up(&vgpu_dev->dev_lock);
    }

    if (!RB_EMPTY_ROOT(&vgpu_dev->gpfn_list))
        remove_gpfn_from_list_all(vgpu_dev);

    delete_all_bar1_mappings(vgpu_dev);

    nv_vgpu_clear_mapping_cache(vgpu_dev);

    vgpu_dev->device_state = NV_VGPU_DEV_UNUSED;

    rm_vgpu_vfio_ops.update_request(NV_GET_MDEV_UUID(mdev), vgpu_dev->offsets,
                                    vgpu_dev->sizes, vgpu_dev->device_state, NULL);

    cleanup_vgpu_dev(vgpu_dev);
    atomic_dec(&vgpu_dev->usage_count);
    up(&vgpu_dev->ops_lock);


    ret = do_vf_flr(mdev);


    if (status != NV_OK)
    {
        NV_VGPU_DEV_LOG(VGPU_ERR, mdev, "stop failed. status: 0x%x %s",
                        status, (status == NV_ERR_TIMEOUT) ? "Timeout Occured\n" : "\n");
    }
    module_put(THIS_MODULE);
}

static int nv_vgpu_vfio_reset(vgpu_dev_t *vgpu_dev)
{
#if defined(NVCPU_AARCH64)
    struct vm_area_struct *vma = vgpu_dev->phys_mappings.bar1_vma;
#endif
    int ret = 0;
    NV_STATUS status = NV_OK;

    if (!vgpu_dev->mdev)
        return -ENODEV;

    vgpu_dev->return_status = -1;
    status = nv_vgpu_dev_post_event(vgpu_dev, NV_VFIO_VGPU_EVENT_VM_REBOOT);
    if (status != NV_OK)
    {
        ret = -EIO;
        goto reset_exit;
    }

    ret = wait_event_interruptible_timeout(vgpu_dev->wait_queue,
                                           (vgpu_dev->return_status >= 0),
                                           msecs_to_jiffies(WAITQUEUE_TIMEOUT_SECONDS));

    if (ret == 0 && vgpu_dev->return_status == -1)
    {
        vgpu_dev->return_status = NV_ERR_TIMEOUT;
        ret = -ETIMEDOUT;
    }
    else if (vgpu_dev->return_status == NV_OK)
        ret = 0;
    else
        ret = -EIO;

    status = vgpu_dev->return_status;
reset_exit:
    if (!RB_EMPTY_ROOT(&vgpu_dev->gpfn_list))
        remove_gpfn_from_list_all(vgpu_dev);

    delete_all_bar1_mappings(vgpu_dev);

    nv_vgpu_clear_mapping_cache(vgpu_dev);

#if defined(NVCPU_AARCH64)
    /*
     * aarch64: kvm hypervisor in next reboot, looks at MMIO region and checks
     * for VM_PFNMAP flag set for that MMIO's vma  or not if set then ioremaps
     * the MMIO region, In vGPU driver case - BAR1 gets ioremaped in the same way
     * for the next reboot cycle and because of that mmio fault handler path
     * won't kick in, so fix this by unsetting the VM_PFNMAP flag of BAR1 vma.
     * TODO: Soon SRIO-v's MMIO region will be remapped by fault handler like
     * Bar1 vGPU, so plan to fix that in coming future.
     */
    if (vma)
    {
        vma->vm_flags &= ~VM_PFNMAP;
    }
#endif


    ret = do_vf_flr(vgpu_dev->mdev);


    if (ret != 0)
    {
        NV_VGPU_DEV_LOG(VGPU_ERR, vgpu_dev->mdev, "reset failed. status: %d %s",
                        status, (ret == -ETIMEDOUT) ? "Timeout Occured\n" : "\n");
    }

    return ret;
}

static NV_STATUS create_dummy_mapping(vgpu_dev_t *vgpu_dev, NvU64 guest_addr,
                                      bar1_node_t **bar1_node)
{
    NV_STATUS status;

    if (vgpu_dev->dummy_page_allocated == NV_FALSE)
    {
        vgpu_dev->dummy_virt_addr = __get_free_page(GFP_KERNEL);
        if (!virt_addr_valid(vgpu_dev->dummy_virt_addr))
        {
            status = NV_ERR_OPERATING_SYSTEM;
            goto dummy_fail;
        }
        vgpu_dev->dummy_phys_addr = virt_to_phys((void *)vgpu_dev->dummy_virt_addr);
        vgpu_dev->dummy_page_allocated = NV_TRUE;
    }

    *bar1_node = nv_add_bar1_mapping(vgpu_dev, vgpu_dev->dummy_phys_addr,
                                    guest_addr, PAGE_SIZE, NV_TRUE);
    if (*bar1_node == NULL)
    {
        status = NV_ERR_INVALID_OPERATION;
        goto dummy_fail;
    }

    return NV_OK;

dummy_fail:
    if (vgpu_dev->dummy_virt_addr != 0)
        free_page(vgpu_dev->dummy_virt_addr);

    return status;
}

static NV_STATUS nv_vgpu_vfio_validate_map_request(struct mdev_device *mdev,
                                                   loff_t pos, NvU64 *virt_addr,
                                                   NvU64 *host_addr, NvU64 *size,
                                                   pgprot_t *prot, NvBool *dup_fault)
{
    NV_STATUS status = NV_OK;
    NvU64 guest_addr = 0, guest_offset = 0;
    NvU32 index =0;
    vgpu_dev_t *vgpu_dev;
    bar1_node_t *bar1_node = NULL;

    if (!mdev || !virt_addr || !host_addr || !size)
        return NV_ERR_INVALID_ARGUMENT;

    vgpu_dev = mdev_get_drvdata(mdev);
    if (!vgpu_dev)
        return NV_ERR_OBJECT_NOT_FOUND;

    down(&vgpu_dev->ops_lock);

    guest_offset = DRF_VAL64(_VGPU_VFIO, _PGOFF, _PCI_OFFSET, pos);
    index = DRF_VAL64(_VGPU_VFIO, _PGOFF, _PCI_INDEX, pos);

   /*
    * When a pass through device and a vGPU device is assigned to a VM, before
    * any BAR0 access for vGPU, VFIO_IOMMU_MAP_DMA calls GUP on BAR1 of vGPU
    * device which triggers this fault. In that case
    * vgpu_dev->region_info[index].start should be filled here if
    * vgpu_dev->region_info[index].start is 0.
    */
    if (!vgpu_dev->region_info[index].start)
        vgpu_read_base(vgpu_dev);

    guest_addr = (vgpu_dev->region_info[index].start + guest_offset);

    bar1_node = nv_find_bar1_mapping(vgpu_dev, guest_addr);
    if (bar1_node == NULL)
    {
        NV_VGPU_DEV_LOG(VGPU_INFO, vgpu_dev->mdev,
                        "BAR mapping not found for guest addr: 0x%llx. Creating dummy mapping.\n",
                        guest_addr);
        status = create_dummy_mapping(vgpu_dev, guest_addr, &bar1_node);
        if (status != NV_OK)
            goto map_exit;
    }

    if (bar1_node->is_validated == NV_TRUE)
    {
        *dup_fault = NV_TRUE;
        NV_VGPU_DEV_LOG(VGPU_ERR, mdev,
                        "BAR1 guest address already mapped. guest_addr: 0x%llx"
                        "size: 0x%llx\n", bar1_node->guest_addr, bar1_node->size);
        goto map_exit;
    }

    *virt_addr = *virt_addr - (guest_addr - bar1_node->guest_addr);
    *host_addr = bar1_node->host_addr;
    *size = bar1_node->size;
    *prot = pgprot_noncached(*prot);

    bar1_node->is_validated = NV_TRUE;

map_exit:
    if (status != NV_OK)
        NV_VGPU_DEV_LOG(VGPU_ERR, mdev,
                        "Validate map request failed. status: 0x%x\n", status);

    up(&vgpu_dev->ops_lock);
    return status;
}

static NV_STATUS mdev_device_invalidate_mapping(vgpu_dev_t *vgpu_dev,
                                                unsigned long addr,
                                                unsigned long size)
{
    NV_STATUS status = NV_ERR_INVALID_ADDRESS;
    struct mdev_phys_mapping *phys_mappings;
    struct addr_desc *addr_desc;

    if (!vgpu_dev || !vgpu_dev->phys_mappings.mapping)
        return status;

    phys_mappings = &vgpu_dev->phys_mappings;

    down(&phys_mappings->addr_lock);
    if(list_empty(&phys_mappings->addr_desc_list))
    {
        up(&phys_mappings->addr_lock);
        return NV_ERR_NOT_SUPPORTED;
    }

    list_for_each_entry(addr_desc, &phys_mappings->addr_desc_list, next)
    {
        if ((addr >= addr_desc->start) &&
            ((addr + size) <= (addr_desc->start + addr_desc->size)))
        {
            unmap_mapping_range(phys_mappings->mapping,
                                addr, size, 0);
            status = NV_OK;
            break;
        }
    }
    up(&phys_mappings->addr_lock);

    return status;
}

static NV_STATUS nv_vgpu_invalidate_guest_mmio(NvU64 phys_mmio_addr,
                                               NvU64 virt_mmio_addr,
                                               NvBool is_dummy,
                                               NvU64 mmio_size, void *vgpu_ref)
{
    NV_STATUS           status    = NV_OK;
    int                 index     = 0;
    NvU64               vfio_addr = 0, offset;
    vgpu_dev_t         *vgpu_dev  = vgpu_ref;
    int                 i;

    if (!vgpu_dev)
        return NV_ERR_INVALID_REQUEST;

    if (is_dummy)
    {
        index = VFIO_PCI_BAR1_REGION_INDEX;
    }
    else
    {
        for (i = 0; i < NV_VGPU_VFIO_REGIONS_MAX; i++)
        {
            if ((virt_mmio_addr >= vgpu_dev->region_info[i].start) &&
                (virt_mmio_addr < (vgpu_dev->region_info[i].start +
                                   vgpu_dev->region_info[i].size)))
            {
                index = i;
                break;
            }
        }

        if (i == VFIO_PCI_NUM_REGIONS)
        {
           status = NV_ERR_INVALID_ADDRESS;
           goto invalidate_exit;
        }
    }

    if ((index == VFIO_PCI_BAR1_REGION_INDEX) &&
        (vgpu_dev->phys_mappings.bar1_munmapped == NV_TRUE))
        return NV_OK;

    offset = virt_mmio_addr - vgpu_dev->region_info[index].start;

    vfio_addr = DRF_NUM64(_VGPU_VFIO, _PGOFF, _PCI_OFFSET, offset) |
                DRF_NUM64(_VGPU_VFIO, _PGOFF, _PCI_INDEX, index) |
                DRF_NUM64(_VGPU_VFIO, _PGOFF, _UNIQUE_ID, vgpu_dev->vgpu_id);

    status = mdev_device_invalidate_mapping(vgpu_dev, vfio_addr, mmio_size);

invalidate_exit:
    if (status != NV_OK)
    {
        NV_VGPU_DEV_LOG(VGPU_ERR, vgpu_dev->mdev,
                        "invalidate guest mmio for address 0x%08llx failed\n",
                         vfio_addr);
    }

    return status;
}

static int vgpu_save_fd(vgpu_dev_t *vgpu_dev, int fd, NvU32 index)
{
    struct fd irqfd;

    irqfd = fdget(fd);
    if (!irqfd.file)
        return -EBADF;

    if (index == VFIO_PCI_INTX_IRQ_INDEX)
        vgpu_dev->intr_info.intx_file = irqfd.file;
    else if (index == VFIO_PCI_MSI_IRQ_INDEX)
        vgpu_dev->intr_info.msi_file = irqfd.file;

    vgpu_dev->intr_info.index = index;
    fdput(irqfd);

    return 0;
}


static irqreturn_t vgpu_msix_handler(int irq, void *arg)
{
    vgpu_dev_t *vgpu_dev = (vgpu_dev_t *)arg;
    struct file *pfile = NULL;
    mm_segment_t old_fs;
    NvU64 val = 1;
    int ret = 0;
    loff_t offset = 0;
    int i;
    unsigned long eflags;

    for (i = 0; i < MAX_NUM_VECTORS; i++)
    {
        if (vgpu_dev->intr_info.allocated_irq[i] == irq)
        {
            pfile = vgpu_dev->intr_info.msix_fd[i].file;
            break;
        }
    }

    if (pfile && pfile->f_op && pfile->f_op->write)
    {
        old_fs = get_fs();
        set_fs(KERNEL_DS);

        NV_SAVE_FLAGS(eflags);
        ret = pfile->f_op->write(pfile, (char *)&val, sizeof(val), &offset);
        NV_RESTORE_FLAGS(eflags);

        set_fs(old_fs);
    }

    return IRQ_HANDLED;
}

static int vgpu_msix_set_vector_signal(vgpu_dev_t *vgpu_dev,
                                      int vector, int fd)
{
    struct pci_dev *pdev;
    int irq = INVALID_IRQ, ret;
    struct fd irqfd;

    pdev = to_pci_dev(NV_GET_MDEV_PARENT(vgpu_dev->mdev));

    if (vgpu_dev->intr_info.msix_fd[vector].file)
    {
        free_irq(vgpu_dev->intr_info.allocated_irq[vector], vgpu_dev);
        vgpu_dev->intr_info.msix_fd[vector].file = NULL;
        vgpu_dev->intr_info.allocated_irq[vector] = INVALID_IRQ;
    }

    if (fd < 0)
        return 0;

    irqfd = fdget(fd);
    if (!irqfd.file)
        return -EBADF;

    if (vector < 0 || vector >= vgpu_dev->intr_info.num_ctx)
        return -EINVAL;

#if defined(NV_PCI_IRQ_VECTOR_HELPERS_PRESENT)
    irq = pci_irq_vector(pdev, vector);
#endif

    ret = request_irq(irq, vgpu_msix_handler, 0,
                      "nvidia", vgpu_dev);
    if (ret)
        return ret;

    vgpu_dev->intr_info.allocated_irq[vector] = irq;

    vgpu_dev->intr_info.msix_fd[vector]= irqfd;

    return 0;
}

static void vgpu_msix_disable(vgpu_dev_t *vgpu_dev)
{
    struct pci_dev *pdev = to_pci_dev(NV_GET_MDEV_PARENT(vgpu_dev->mdev));
    NvU32 i;

    if (vgpu_dev->intr_info.index == VFIO_PCI_MSIX_IRQ_INDEX)
    {
        for (i = 0; i < MAX_NUM_VECTORS; i++)
        {
            if (vgpu_dev->intr_info.allocated_irq[i] != INVALID_IRQ)
            {
                free_irq(vgpu_dev->intr_info.allocated_irq[i], vgpu_dev);
                vgpu_dev->intr_info.msix_fd[i].file = NULL;
                vgpu_dev->intr_info.allocated_irq[i] = INVALID_IRQ;
            }
        }
#if defined(NV_PCI_IRQ_VECTOR_HELPERS_PRESENT)
        pci_free_irq_vectors(pdev);
#endif
    }

    vgpu_dev->intr_info.index = VFIO_PCI_NUM_IRQS;
    vgpu_dev->intr_info.num_ctx = 0;
}

static int vgpu_msix_enable(vgpu_dev_t *vgpu_dev, int nvec)
{
    struct pci_dev *pdev;
    int ret;
    NvU32 i;

    pdev = to_pci_dev(NV_GET_MDEV_PARENT(vgpu_dev->mdev));

#if defined(NV_PCI_IRQ_VECTOR_HELPERS_PRESENT)
    ret = pci_alloc_irq_vectors(pdev, 1, nvec, PCI_IRQ_ALL_TYPES);
    if (ret < nvec)
    {
        if (ret > 0)
            pci_free_irq_vectors(pdev);
        return ret;
    }
#endif

    vgpu_dev->intr_info.num_ctx = nvec;
    vgpu_dev->intr_info.index = VFIO_PCI_MSIX_IRQ_INDEX;

    // reset the IRQ numbers for all vectors
    for (i = 0; i < MAX_NUM_VECTORS; i++)
    {
        vgpu_dev->intr_info.allocated_irq[i] = INVALID_IRQ;
    }

    return 0;
}

static int vgpu_msix_set_block(vgpu_dev_t *vgpu_dev, unsigned start,
                              unsigned count, int32_t *fds)
{
    int i, j, ret = 0;

    if (start >= vgpu_dev->intr_info.num_ctx || start + count > vgpu_dev->intr_info.num_ctx)
        return -EINVAL;

    for (i = 0, j = start; i < count && !ret; i++, j++)
    {
        int fd = fds ? fds[i] : -1;
        ret = vgpu_msix_set_vector_signal(vgpu_dev, j, fd);
    }

    if (ret)
    {
        for (--j; j >= (int)start; j--)
            vgpu_msix_set_vector_signal(vgpu_dev, j, -1);
    }

    return ret;
}


static int nv_vgpu_vfio_set_irqs(vgpu_dev_t *vgpu_dev, uint32_t flags,
                                 unsigned index, unsigned start, unsigned count,
                                 void *data)
{
    int ret = 0;
    unsigned long eflags;

    if (!vgpu_dev->mdev)
        return -EINVAL;

    NV_SPIN_LOCK_IRQSAVE(&vgpu_dev->intr_info_lock, eflags);
    switch (index) {
        case VFIO_PCI_INTX_IRQ_INDEX:
            switch (flags & VFIO_IRQ_SET_ACTION_TYPE_MASK)
            {
                case VFIO_IRQ_SET_ACTION_MASK:
                case VFIO_IRQ_SET_ACTION_UNMASK:
                    break;
                case VFIO_IRQ_SET_ACTION_TRIGGER:
                {
                    if (flags & VFIO_IRQ_SET_DATA_NONE)
                    {
                        vgpu_dev->intr_info.intx_file = NULL;
                        break;
                    }

                    if (flags & VFIO_IRQ_SET_DATA_EVENTFD)
                    {
                        int fd = *(int *)data;
                        if (fd > 0)
                            ret = vgpu_save_fd(vgpu_dev, fd, index);
                    }
                    break;
                }
            }
            break;
        case VFIO_PCI_MSI_IRQ_INDEX:
            switch (flags & VFIO_IRQ_SET_ACTION_TYPE_MASK)
            {
                case VFIO_IRQ_SET_ACTION_MASK:
                case VFIO_IRQ_SET_ACTION_UNMASK:
                    /* XXX Need masking support exported */
                    break;
                case VFIO_IRQ_SET_ACTION_TRIGGER:
                {
                    if (flags & VFIO_IRQ_SET_DATA_NONE)
                    {
                        vgpu_dev->intr_info.msi_file = NULL;
                        vgpu_dev->intr_info.index = VFIO_PCI_INTX_IRQ_INDEX;
                        break;
                    }

                    if (flags & VFIO_IRQ_SET_DATA_EVENTFD)
                    {
                        int fd = *(int *)data;
                        if (fd > 0)
                        {
                            if (vgpu_dev->intr_info.msi_file == NULL)
                                ret = vgpu_save_fd(vgpu_dev, fd, index);
                        }
                    }
                    break;
                }
            }
            break;
        case VFIO_PCI_MSIX_IRQ_INDEX:

            switch (flags & VFIO_IRQ_SET_ACTION_TYPE_MASK)
            {
                case VFIO_IRQ_SET_ACTION_MASK:
                case VFIO_IRQ_SET_ACTION_UNMASK:
                    /* XXX Need masking support exported */
                    break;
                case VFIO_IRQ_SET_ACTION_TRIGGER:
                {
                    if (flags & VFIO_IRQ_SET_DATA_NONE)
                    {
                        vgpu_msix_disable(vgpu_dev);
                    }
                    if (flags & VFIO_IRQ_SET_DATA_EVENTFD)
                    {
                        if (vgpu_dev->intr_info.index != VFIO_PCI_MSIX_IRQ_INDEX)
                        {
                            ret = vgpu_msix_enable(vgpu_dev, start + count);
                            if (ret)
                                goto exit;
                        }

                        ret = vgpu_msix_set_block(vgpu_dev, start, count, data);
                    }
                }
                break;
            }
            break;

        case VFIO_PCI_ERR_IRQ_INDEX:
        case VFIO_PCI_REQ_IRQ_INDEX:
            break;
    }

exit:

    NV_SPIN_UNLOCK_IRQRESTORE(&vgpu_dev->intr_info_lock, eflags);

    if (ret != 0)
        NV_VGPU_DEV_LOG(VGPU_ERR, vgpu_dev->mdev, "Failed to set irq. ret: %d\n",
                        ret);

    return ret;
}

NV_STATUS nv_vgpu_inject_interrupt(void *vgpuRef)
{
    mm_segment_t old_fs;
    NvU64 val = 1;
    int ret = 0;
    loff_t offset = 0;
    NV_STATUS status = NV_OK;
    struct file *pfile = NULL;
    vgpu_dev_t *vgpu_dev = vgpuRef;
    unsigned long eflags;

    if (vgpuRef == NULL)
        return NV_ERR_INVALID_STATE;

    NV_SPIN_LOCK_IRQSAVE(&vgpu_dev->intr_info_lock, eflags);

    if ((vgpu_dev->intr_info.index == VFIO_PCI_MSI_IRQ_INDEX) && (vgpu_dev->intr_info.msi_file == NULL))
    {
        NV_SPIN_UNLOCK_IRQRESTORE(&vgpu_dev->intr_info_lock, eflags);
        return NV_ERR_INVALID_REQUEST;
    }
    else if ((vgpu_dev->intr_info.index == VFIO_PCI_INTX_IRQ_INDEX) && (vgpu_dev->intr_info.intx_file == NULL))
    {
        NV_SPIN_UNLOCK_IRQRESTORE(&vgpu_dev->intr_info_lock, eflags);
        return NV_ERR_INVALID_REQUEST;
    }
    else if (vgpu_dev->intr_info.index >= VFIO_PCI_MSIX_IRQ_INDEX)
    {
        NV_SPIN_UNLOCK_IRQRESTORE(&vgpu_dev->intr_info_lock, eflags);
        return NV_ERR_INVALID_REQUEST;
    }

    if (vgpu_dev->intr_info.index == VFIO_PCI_MSI_IRQ_INDEX)
        pfile = vgpu_dev->intr_info.msi_file;
    else
        pfile = vgpu_dev->intr_info.intx_file;

    // QEMU has exited. So, safe to ignore interrupts.
    if (vgpu_dev->intr_info.ignore_interrupts == NV_TRUE)
    {
        NV_SPIN_UNLOCK_IRQRESTORE(&vgpu_dev->intr_info_lock, eflags);
        return NV_OK;
    }
    NV_SPIN_UNLOCK_IRQRESTORE(&vgpu_dev->intr_info_lock, eflags);

    old_fs = get_fs();
    set_fs(KERNEL_DS);

    if (pfile->f_op && pfile->f_op->write)
       ret = pfile->f_op->write(pfile, (char *)&val, sizeof(val), &offset);
    else
        status = NV_ERR_INVALID_REQUEST;

    if (ret < 0)
        status = NV_ERR_INVALID_STATE;

    set_fs(old_fs);

    return status;
}

static NV_STATUS nv_create_dma_mappings(vgpu_dev_t *vgpu_dev,
                                        NvU64 *gpfn_buffer,
                                        NvU64 *hpfn_buffer,
                                        NvU32 pfn_count)
{
    NV_STATUS status = NV_OK;
    struct sg_table sgt = {0};
    struct scatterlist *sg;
    int ret = 0;
    unsigned int i;
    int mapped_count;
    struct pci_dev *pdev;
    NvU64 sg_addr, sg_off, sg_len, k, l = 0;
    mapping_node_t *tmapping_node = NULL;
#if !defined(NV_KVMALLOC_PRESENT)
    NvBool is_vmalloc;
#endif

    NV_MEM_ALLOC(tmapping_node,
                 sizeof(mapping_node_t) + (pfn_count * sizeof(struct page *)),
                 is_vmalloc);
    if (tmapping_node == NULL)
        return NV_ERR_NO_MEMORY;

    if (gpfn_buffer == NULL) {
        return NV_ERR_INVALID_ARGUMENT;
    }

    if (hpfn_buffer == NULL) {
        return NV_ERR_INVALID_ARGUMENT;
    }

    if (vgpu_dev->mapping_cache == NULL) {
        return NV_ERR_INVALID_ARGUMENT;
    }

    memset(tmapping_node, 0, sizeof(mapping_node_t) + (pfn_count * sizeof(struct page *)));
    tmapping_node->pfn_count = pfn_count;
#if !defined(NV_KVMALLOC_PRESENT)
    tmapping_node->is_vmalloc = is_vmalloc;
#endif

    for (i = 0; i < tmapping_node->pfn_count; i++)
    {
        if (vgpu_dev->mapping_cache && vgpu_dev->mapping_cache[gpfn_buffer[i]])
        {
            NV_VGPU_DEV_LOG(VGPU_ERR, vgpu_dev->mdev,
                            "Guest PFN already pinned. gpfn: 0x%llx\n",
                             gpfn_buffer[i]);
            status = NV_ERR_OPERATING_SYSTEM;
            goto dma_map_error;
        }
        tmapping_node->page_buffer[i] = pfn_to_page(hpfn_buffer[i]);
    }

    ret = NV_DMA_ALLOC_SG_TABLE(sgt, tmapping_node->page_buffer, tmapping_node->pfn_count);
    if (ret != 0)
    {
        NV_VGPU_DEV_LOG(VGPU_ERR, vgpu_dev->mdev,
                        "Failed to allocate sg table ret: %d \n", ret);
        status = NV_ERR_OPERATING_SYSTEM;
        goto dma_map_error;
    }

    pdev = to_pci_dev(NV_GET_MDEV_PARENT(vgpu_dev->mdev));
    mapped_count = pci_map_sg(pdev, sgt.sgl, sgt.orig_nents, PCI_DMA_BIDIRECTIONAL);
    if (mapped_count == 0)
    {
        NV_VGPU_DEV_LOG(VGPU_ERR, vgpu_dev->mdev,
                        "Failed to map host physical address \n");
        status = NV_ERR_OPERATING_SYSTEM;
        goto dma_map_error;
    }

    tmapping_node->iova = sgt.sgl[0].dma_address;

    for_each_sg(sgt.sgl, sg, mapped_count, i)
    {
        for (sg_addr = sg_dma_address(sg), sg_len = sg_dma_len(sg),
                 sg_off = 0, k = 0;
             (sg_off < sg_len) && (k < pfn_count);
             sg_off += PAGE_SIZE, l++, k++)
        {
            hpfn_buffer[l] = (sg_addr + sg_off) >> PAGE_SHIFT;
            vgpu_dev->mapping_cache[gpfn_buffer[l]] = (mapping_node_t *)GFN_PINNED;
        }
    }

    tmapping_node->base_gpfn_pinned = NV_TRUE;
    vgpu_dev->mapping_cache[gpfn_buffer[0]] = (mapping_node_t *) tmapping_node;

dma_map_error:

    if (status != NV_OK)
    {
        NV_MEM_FREE(tmapping_node,
                    sizeof(mapping_node_t) + (pfn_count * sizeof(struct page *)),
                    is_vmalloc);
    }

    if (sgt.sgl)
        NV_DMA_FREE_SG_TABLE(sgt);

    return status;
}

static void nv_destroy_dma_mappings(vgpu_dev_t *vgpu_dev, mapping_node_t *mapping_node)
{
    struct sg_table sgt;
    int ret = 0;
    unsigned int i;
    NvU64 j = 0;
    NvU32 pfn_count;
    struct pci_dev *pdev;
    struct scatterlist *sg;

    if (mapping_node == NULL)
    {
        NV_VGPU_DEV_LOG(VGPU_ERR, vgpu_dev->mdev,
                        "Failed to destroy dma mapping as mapping"
                        " node is invalid.\n");
        return;
    }

    pfn_count = mapping_node->pfn_count;

    ret = NV_DMA_ALLOC_SG_TABLE(sgt, mapping_node->page_buffer, pfn_count);
    if (ret != 0)
    {
        NV_VGPU_DEV_LOG(VGPU_ERR, vgpu_dev->mdev,
                        "Failed to allocate sg table. ret: %d \n", ret);
        goto destroy_exit;
    }

    sgt.sgl[0].dma_address = mapping_node->iova;

    for_each_sg(sgt.sgl, sg, sgt.orig_nents, i)
    {
        sg_dma_address(sg) = sgt.sgl[0].dma_address + j;
        sg_dma_len(sg) = sg->length;
        j += sg->length;
    }

    pdev = to_pci_dev(NV_GET_MDEV_PARENT(vgpu_dev->mdev));
    pci_unmap_sg(pdev, sgt.sgl, sgt.orig_nents, PCI_DMA_BIDIRECTIONAL);
    NV_DMA_FREE_SG_TABLE(sgt);

destroy_exit:
    NV_MEM_FREE(mapping_node,
                sizeof(mapping_node_t) + (pfn_count * sizeof(struct page *)),
                mapping_node->is_vmalloc);
}

NV_STATUS nv_vgpu_unpin_pages(NvU64 *buffer, NvU32 pfn_count,
                              void *vgpu_ref, VGPU_ADDR_TYPE_T addr_type)
{
    NV_STATUS status = NV_OK;
    vgpu_dev_t *vgpu_dev = vgpu_ref;
    int ret = 0, i;
    gpfn_node_t *gpfn_node;
    unsigned long *gpfn_buffer = (unsigned long *) buffer;
    NvU32 count, initial_count = pfn_count;

    if (!vgpu_dev)
        return NV_ERR_INVALID_STATE;

    while (pfn_count != 0)
    {
        if (pfn_count > VFIO_PIN_PAGES_MAX_ENTRIES)
            count = VFIO_PIN_PAGES_MAX_ENTRIES;
        else
            count = pfn_count;

        ret = vfio_unpin_pages(NV_GET_MDEV_DEV(vgpu_dev->mdev),
                               gpfn_buffer, count);

        if (ret != count)
        {
            if (ret > 0)
                pfn_count -= ret;

            status = NV_ERR_OPERATING_SYSTEM;
            goto unpin_err;
        }
#if defined(DEBUG)
        vgpu_dev->dirty_pfn_count -= count;
#endif
        pfn_count = pfn_count - count;
        gpfn_buffer = gpfn_buffer + count;
    }

unpin_err:
    if (addr_type == GET_IOVA)
    {
        for (i = 0; i < initial_count; i++)
        {
            if (buffer[i] <= vgpu_dev->vfio_max_gpfn &&
                vgpu_dev->mapping_cache &&
                vgpu_dev->mapping_cache[buffer[i]])
            {
                if (vgpu_dev->mapping_cache[buffer[i]] != (mapping_node_t *) GFN_PINNED)
                    nv_destroy_dma_mappings(vgpu_dev, vgpu_dev->mapping_cache[buffer[i]]);
                vgpu_dev->mapping_cache[buffer[i]] = NULL;
            }
            else
            {
                NV_VGPU_DEV_LOG(VGPU_INFO, vgpu_dev->mdev,
                                "Request to unpin gfn 0x%llx failed. Page was"
                                " not pinned \n",buffer[i]);
            }
        }
    }
    else
    {
        for (i = 0; i < initial_count - pfn_count; i++)
        {
            gpfn_node = NULL;
            gpfn_node = find_gpfn_from_list(vgpu_dev, (unsigned long) buffer[i]);
            if (gpfn_node)
                remove_gpfn_from_list(vgpu_dev, gpfn_node);
        }
    }

    if (status != NV_OK)
    {
        NV_VGPU_DEV_LOG(VGPU_ERR, vgpu_dev->mdev,
                        "Failed to unpin all 0x%x pages Total pages unpinned: 0x%x"
                        " status: 0x%x ret: %d\n", initial_count,
                        initial_count - pfn_count, status, ret);
    }
    return status;
}

static NvU64 get_max_gpfn_count(unsigned long *gpfn_buffer, NvU32 pfn_count)
{
    NvU32 i;
    NvU64 max_gpfn = 0;

    for (i = 0; i < pfn_count; i++)
    {
        if (gpfn_buffer[i] > max_gpfn)
            max_gpfn = gpfn_buffer[i];
    }
    return max_gpfn;
}

static NV_STATUS nv_adjust_mapping_cache(vgpu_dev_t *vgpu_dev,
                                         NvU32 pfn_count,
                                         NvU64 current_max_gpfn)
{
    NvU64 size;

    size = NV_ALIGN_UP((current_max_gpfn + 1), NV_INITIAL_CACHE_SIZE);

    if (vgpu_dev->vfio_max_gpfn == 0)
    {
        vgpu_dev->mapping_cache = (mapping_node_t **)
                                  nv_vmalloc(sizeof(mapping_node_t *) * size);
        if (vgpu_dev->mapping_cache == NULL)
        {
            NV_VGPU_DEV_LOG(VGPU_ERR, vgpu_dev->mdev,
                            "Failed to allocate memory for mapping cache \n");
            return NV_ERR_NO_MEMORY;
        }
        memset(vgpu_dev->mapping_cache, 0, sizeof(mapping_node_t *) * size);
    }
    else
    {
        mapping_node_t **temp;

        temp = (mapping_node_t **)
               nv_vmalloc(size * sizeof(mapping_node_t *));
        if (temp == NULL)
        {
            NV_VGPU_DEV_LOG(VGPU_ERR, vgpu_dev->mdev,
                            "Failed to reallocate memory for mapping cache \n");
            return NV_ERR_NO_MEMORY;
        }

        memset(temp, 0, (size) * sizeof(mapping_node_t *));

        memcpy((void *) temp, (void *) vgpu_dev->mapping_cache ,
               sizeof(mapping_node_t *) * (vgpu_dev->vfio_max_gpfn + 1));
        nv_vfree(vgpu_dev->mapping_cache,
                 sizeof(mapping_node_t *) * (vgpu_dev->vfio_max_gpfn + 1));

        vgpu_dev->mapping_cache = temp;
    }
    vgpu_dev->vfio_max_gpfn = size - 1;

    return NV_OK;
}

NV_STATUS nv_vgpu_translate_gfn_to_pfn(NvU64 *gpfn_buffer, NvU64 *hpfn_buffer,
                                       NvU32 pfn_count, void *vgpu_ref,
                                       VGPU_ADDR_TYPE_T addr_type)
{
    int ret = 0;
    vgpu_dev_t *vgpu_dev = vgpu_ref;
    unsigned long *thpfn_buffer = (unsigned long *) hpfn_buffer;
    unsigned long *tgpfn_buffer = (unsigned long *) gpfn_buffer;
    NvU32 cnt, pinned_count = 0;

    if (!vgpu_dev)
        return NV_ERR_INVALID_STATE;

    while (pinned_count < pfn_count)
    {
        if ((pfn_count - pinned_count) > VFIO_PIN_PAGES_MAX_ENTRIES)
            cnt = VFIO_PIN_PAGES_MAX_ENTRIES;
        else
            cnt = pfn_count - pinned_count;

        ret = vfio_pin_pages(NV_GET_MDEV_DEV(vgpu_dev->mdev),
                             tgpfn_buffer + pinned_count,
                             cnt, IOMMU_READ | IOMMU_WRITE,
                             thpfn_buffer + pinned_count);
        if (ret <= 0)
        {
            NV_VGPU_DEV_LOG(VGPU_ERR, vgpu_dev->mdev,
                            "Failed to pin 0x%x pages. ret: %d \n",
                            pfn_count, ret);
            goto pin_err;
        }
        else if (ret != cnt)
        {
            NV_VGPU_DEV_LOG(VGPU_ERR, vgpu_dev->mdev,
                            "Failed to pin all 0x%x pages. Total pages pinned: 0x%x",
                            pfn_count, cnt);
            WARN_ON(1);
            goto pin_err;
        }

        pinned_count += cnt;
#if defined(DEBUG)
        vgpu_dev->dirty_pfn_count += cnt;
#endif
    }

    if (addr_type == GET_HOST_PFN)
        add_gpfn_buffer_to_list(vgpu_dev, tgpfn_buffer, pfn_count);
    else
    {
        NV_STATUS status;
        NvU64 current_max_gpfn;

        current_max_gpfn = get_max_gpfn_count(tgpfn_buffer, pfn_count);

        if (current_max_gpfn > vgpu_dev->vfio_max_gpfn)
        {
            status = nv_adjust_mapping_cache(vgpu_dev, pfn_count,
                                             current_max_gpfn);
            if (status != NV_OK)
                goto pin_err;
        }

        status = nv_create_dma_mappings(vgpu_dev, gpfn_buffer,
                                        hpfn_buffer, pfn_count);
        if (status != NV_OK)
        {
            NV_VGPU_DEV_LOG(VGPU_ERR, vgpu_dev->mdev,
                            "Failed to create DMA mappings status: 0x%x \n",
                            status);
            goto pin_err;
        }
    }

    return NV_OK;

pin_err:
    while (pinned_count != 0)
    {
        if (pinned_count > VFIO_PIN_PAGES_MAX_ENTRIES)
            cnt = VFIO_PIN_PAGES_MAX_ENTRIES;
        else
            cnt = pinned_count;

        ret = vfio_unpin_pages(NV_GET_MDEV_DEV(vgpu_dev->mdev), tgpfn_buffer, cnt);
        if (ret != cnt)
            return NV_ERR_OPERATING_SYSTEM;

#if defined(DEBUG)
        vgpu_dev->dirty_pfn_count -= cnt;
#endif
        pinned_count -= cnt;
        gpfn_buffer = gpfn_buffer + cnt;
    }

    return NV_ERR_OPERATING_SYSTEM;
}

static int vgpu_get_irq_info(vgpu_dev_t *vgpu_dev, struct vfio_irq_info *irq_info)
{
    struct pci_dev *pdev;

    pdev = to_pci_dev(NV_GET_MDEV_PARENT(vgpu_dev->mdev));
    
    if (!pdev)
        return -EINVAL;
    
    switch (irq_info->index) {
        case VFIO_PCI_INTX_IRQ_INDEX:
        case VFIO_PCI_MSI_IRQ_INDEX:

        case VFIO_PCI_MSIX_IRQ_INDEX:

        case VFIO_PCI_REQ_IRQ_INDEX:
            break;
        case VFIO_PCI_ERR_IRQ_INDEX:
            return 0;
        default:
            return -EINVAL;
    }

    irq_info->flags = VFIO_IRQ_INFO_EVENTFD;


    if (pdev->is_virtfn)
    {
        NvU32 pos = pdev->msix_cap;
        NvU16 flags;
        pci_read_config_word(pdev,
                             pos + PCI_MSIX_FLAGS, &flags);

        irq_info->count = (flags & PCI_MSIX_FLAGS_QSIZE) + 1;

    }
    else

    {
        irq_info->count = 1;
    }

    if (irq_info->index == VFIO_PCI_INTX_IRQ_INDEX)
        irq_info->flags |= (VFIO_IRQ_INFO_MASKABLE |
                            VFIO_IRQ_INFO_AUTOMASKED);
    else
        irq_info->flags |= VFIO_IRQ_INFO_NORESIZE;

    return 0;
}

#if defined(NV_VFIO_DEVICE_GFX_PLANE_INFO_PRESENT)
NvU32 get_drm_format(uint32_t bpp)
{
    NvU32 fmt;

    switch (bpp) {
        case 8:
            fmt = DRM_FORMAT_C8;
            break;
        case 16:
            fmt = DRM_FORMAT_RGB565;
            break;
        case 24:
            fmt = DRM_FORMAT_RGB888;
            break;
        case 32:
        default:
            fmt = DRM_FORMAT_XRGB8888;
            break;
    }
    return fmt;
}

int nv_vgpu_vfio_get_gfx_plane_info(vgpu_dev_t *vgpu_dev, struct vfio_device_gfx_plane_info *gfx_plane_info)
{
    int ret = 0;
    NV_STATUS status = NV_OK;

    if (!vgpu_dev->mdev)
        return -ENODEV;

    vgpu_dev->return_status = -1;
    status = nv_vgpu_dev_post_event(vgpu_dev, NV_VFIO_VGPU_EVENT_CONSOLE_INFO);
    if (status != NV_OK)
        return -EIO;

    ret = wait_event_interruptible_timeout(vgpu_dev->wait_queue,
                                           (vgpu_dev->return_status >= 0),
                                           msecs_to_jiffies(8000));

    if (ret == 0 && vgpu_dev->return_status == -1)
    {
        vgpu_dev->return_status = NV_ERR_TIMEOUT;
        return -ETIMEDOUT;
    }
    else if (vgpu_dev->return_status == NV_OK) {
        gfx_plane_info->drm_format = get_drm_format(vgpu_dev->console.surface_params.depth);
        gfx_plane_info->width = vgpu_dev->console.surface_params.width;
        gfx_plane_info->height = vgpu_dev->console.surface_params.height;
        gfx_plane_info->stride = (vgpu_dev->console.surface_params.depth *
                                  vgpu_dev->console.surface_params.width) / 8;
        gfx_plane_info->size = vgpu_dev->console.surface_params.size;
        gfx_plane_info->region_index = NV_VGPU_VFIO_CONSOLE_REGION;
        return 0;
    }

    return -EIO;
}
#endif

static long nv_vgpu_vfio_ioctl(struct mdev_device *mdev, unsigned int cmd,
                               unsigned long arg)
{
    int ret = -EINVAL;
    unsigned long minsz;
    vgpu_dev_t *vgpu_dev;
    struct vfio_region_info region_info;
    struct vfio_info_cap caps = { .buf = NULL, .size = 0 };
    struct vfio_irq_info irq_info;
    u8 *data = NULL, *ptr = NULL;
    char *err_str = NULL;
    size_t data_size = 0;
    struct vfio_irq_set hdr;

#if defined(NV_VFIO_DEVICE_GFX_PLANE_INFO_PRESENT)
    struct vfio_device_gfx_plane_info gfx_plane_info;
#endif

    vgpu_dev = mdev_get_drvdata(mdev);
    if (!vgpu_dev)
        return -ENODEV;

    down(&vgpu_dev->ops_lock);

    switch(cmd)
    {
        case VFIO_DEVICE_GET_INFO:
            minsz = offsetofend(struct vfio_device_info, num_irqs);
            err_str = "VFIO_DEVICE_GET_INFO";

            if (copy_from_user(&vgpu_dev->vfio_info, (void __user *)arg, minsz))
            {
                ret = -EFAULT;
                break;
            }

            if (vgpu_dev->vfio_info.argsz < minsz)
            {
                ret = -EINVAL;
                break;
            }

            vgpu_dev->vfio_info.flags = VFIO_DEVICE_FLAGS_PCI |
                                        VFIO_DEVICE_FLAGS_RESET;
            vgpu_dev->vfio_info.num_regions = NV_VGPU_VFIO_REGIONS_MAX;
            vgpu_dev->vfio_info.num_irqs = VFIO_PCI_NUM_IRQS;

            ret = copy_to_user((void __user *)arg, &vgpu_dev->vfio_info, minsz) ? -EFAULT : 0;
            break;

        case VFIO_DEVICE_GET_REGION_INFO:
            minsz = offsetofend(struct vfio_region_info, offset);
            err_str = "VFIO_DEVICE_GET_REGION_INFO";

            if (copy_from_user(&region_info, (void __user *)arg, minsz))
            {
                ret = -EFAULT;
                break;
            }

            if (region_info.argsz < minsz)
            {
                ret = -EINVAL;
                break;
            }

            ret = nv_vgpu_vfio_region_info(vgpu_dev, &region_info, &caps);
            if (ret != 0)
                break;

            if (caps.size)
            {
                region_info.flags |= VFIO_REGION_INFO_FLAG_CAPS;
                if (region_info.argsz < sizeof(region_info) + caps.size)
                {
                    region_info.argsz = sizeof(region_info) + caps.size;
                    region_info.cap_offset = 0;
                }
                else
                {
                    vfio_info_cap_shift(&caps, sizeof(region_info));
                    if (copy_to_user((void __user *)arg +
                                     sizeof(region_info), caps.buf,
                                     caps.size))
                    {
                         kfree(caps.buf);
                         ret = -EFAULT;
                         break;
                    }
                    region_info.cap_offset = sizeof(region_info);
                }
                kfree(caps.buf);
            }

            ret = copy_to_user((void __user *)arg, &region_info, minsz)? -EFAULT : 0 ;
            break;

        case VFIO_DEVICE_GET_IRQ_INFO:

            minsz = offsetofend(struct vfio_irq_info, count);
            err_str = "VFIO_DEVICE_GET_IRQ_INFO";

            if (copy_from_user(&irq_info, (void __user *)arg, minsz))
            {
                ret = -EFAULT;
                break;
            }

            if ((irq_info.argsz < minsz) ||
                (irq_info.index >= vgpu_dev->vfio_info.num_irqs))
            {
                ret = -EINVAL;
                break;
            }

            ret = vgpu_get_irq_info(vgpu_dev, &irq_info);
            if (ret != 0)
                break;

            if (irq_info.count == -1)
            {
                ret = -EINVAL;
                break;
            }

            ret = copy_to_user((void __user *)arg, &irq_info, minsz)? -EFAULT : 0;
            break;

        case VFIO_DEVICE_SET_IRQS:
            minsz = offsetofend(struct vfio_irq_set, count);
            err_str = "VFIO_DEVICE_SET_IRQS";

            if (copy_from_user(&hdr, (void __user *)arg, minsz))
            {
                ret = -EFAULT;
                break;
            }

            ret = vfio_set_irqs_validate_and_prepare(&hdr,
                                                     vgpu_dev->vfio_info.num_irqs,
                                                     VFIO_PCI_NUM_IRQS,
                                                     &data_size);
            if (ret)
                break;

            if (data_size)
            {
                ptr = data = memdup_user((void __user *)(arg + minsz),
                                         data_size);
                if (IS_ERR(data))
                {
                    ret = PTR_ERR(data);
                    break;
                }
            }

            ret = nv_vgpu_vfio_set_irqs(vgpu_dev, hdr.flags,
                                        hdr.index, hdr.start,
                                        hdr.count, data);

            kfree(ptr);
            break;

        case VFIO_DEVICE_RESET:
            err_str = "VFIO_DEVICE_RESET";
            ret = nv_vgpu_vfio_reset(vgpu_dev);
            break;
#if defined(NV_VFIO_DEVICE_GFX_PLANE_INFO_PRESENT)
        case VFIO_DEVICE_QUERY_GFX_PLANE:
            minsz = offsetofend(struct vfio_device_gfx_plane_info, region_index);
            err_str = "VFIO_DEVICE_QUERY_GFX_PLANE";

            if (copy_from_user(&gfx_plane_info, (void __user*)arg, minsz))
            {
                ret = -EFAULT;
                break;
            }
            if (gfx_plane_info.argsz < minsz)
            {
                ret = -EINVAL;
                break;
            }

            if (!(gfx_plane_info.flags & VFIO_GFX_PLANE_TYPE_REGION))
            {
                /* No need to print error for VFIO_GFX_PLANE_TYPE_DMABUF case */
                up(&vgpu_dev->ops_lock);
                return -EINVAL;
            }

            if (gfx_plane_info.flags & VFIO_GFX_PLANE_TYPE_PROBE) {
                ret = 0;
            }
            else
            {
                ret = nv_vgpu_vfio_get_gfx_plane_info(vgpu_dev, &gfx_plane_info);
                if (ret)
                    break;

                ret = copy_to_user((void __user *)arg, &gfx_plane_info, minsz)? -EFAULT : 0;
            }

            break;
#endif
    }
    up(&vgpu_dev->ops_lock);

    if (ret != 0)
        NV_VGPU_DEV_LOG(VGPU_ERR, mdev,
                        "VFIO IOCTL %s failed. cmd: 0x%x ret: %d\n",
                        (err_str != NULL) ? err_str : " ", cmd, ret);

    return ret;
}

static int vgpu_add_phys_mapping(vgpu_dev_t *vgpu_dev,
                                 struct address_space *mapping,
                                 unsigned long addr, unsigned long size)
{
    struct mdev_phys_mapping *phys_mappings;
    struct addr_desc *addr_desc, *new_addr_desc;
    int ret = 0;

    phys_mappings = &vgpu_dev->phys_mappings;
    if (phys_mappings->mapping && (mapping != phys_mappings->mapping))
        return -EINVAL;

    if (!phys_mappings->mapping)
    {
        phys_mappings->mapping = mapping;
        INIT_LIST_HEAD(&phys_mappings->addr_desc_list);
        NV_INIT_MUTEX(&phys_mappings->addr_lock);
    }

    down(&phys_mappings->addr_lock);
    list_for_each_entry(addr_desc, &phys_mappings->addr_desc_list, next)
    {
        if ((addr + size <= addr_desc->start) ||
            (addr_desc->start + addr_desc->size) <= addr)
            continue;
        else
        {
            /* should be no overlap */
            ret = -EINVAL;
            goto map_exit;
        }
    }

    /* add the new entry to the list */
    new_addr_desc = kzalloc(sizeof(*new_addr_desc), GFP_KERNEL);

    if (!new_addr_desc)
    {
        ret = -ENOMEM;
        goto map_exit;
    }
    new_addr_desc->start = addr;
    new_addr_desc->size = size;
    list_add(&new_addr_desc->next, &phys_mappings->addr_desc_list);

map_exit:
    up(&phys_mappings->addr_lock);
    return ret;
}

void vgpu_del_phys_mapping(vgpu_dev_t *vgpu_dev, unsigned long offset)
{
    struct mdev_phys_mapping *phys_mappings;
    struct addr_desc *addr_desc;
    unsigned long addr;
    int index;

    phys_mappings = &vgpu_dev->phys_mappings;

    addr = offset << PAGE_SHIFT;
    index = DRF_VAL64(_VGPU_VFIO, _PGOFF, _PCI_INDEX, addr);

    if (index == VFIO_PCI_BAR1_REGION_INDEX)
        phys_mappings->bar1_munmapped = NV_TRUE;

    down(&phys_mappings->addr_lock);
    if(list_empty(&phys_mappings->addr_desc_list))
        goto del_map_exit;

    list_for_each_entry(addr_desc, &phys_mappings->addr_desc_list, next)
    {
        if (addr_desc->start == addr)
        {
            list_del(&addr_desc->next);
            kfree(addr_desc);
            break;
        }
    }

del_map_exit:
    up(&phys_mappings->addr_lock);
}

static vm_fault_t vgpu_mmio_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
    int ret;
    NV_STATUS status = NV_OK;
    struct mdev_device *mdev = vma->vm_private_data;
    NvU64 virtaddr = nv_page_fault_va(vmf), host_addr = 0, req_size = 0;
    NvBool dup_fault = NV_FALSE;
    pgprot_t pg_prot;
    NvU64 guest_offset;
    loff_t pos;

    if (!mdev)
        return -EINVAL;

    pg_prot = vma->vm_page_prot;
    guest_offset = virtaddr - vma->vm_start;
    pos = (vma->vm_pgoff << PAGE_SHIFT) + guest_offset;

    status = nv_vgpu_vfio_validate_map_request(mdev, pos, &virtaddr, &host_addr,
                                               &req_size, &pg_prot, &dup_fault);
    if (status != NV_OK)
        return -EIO;

    if (dup_fault == NV_TRUE)
        return VM_FAULT_NOPAGE;

    /*
     * Verify pgoff and req_size are valid and virtaddr is within
     * vma range
     */
    if (!host_addr || !req_size || (virtaddr < vma->vm_start) ||
        ((virtaddr + req_size) >= vma->vm_end))
        return -EINVAL;

#if defined(CONFIG_AMD_MEM_ENCRYPT) && defined(NV_PGPROT_DECRYPTED_PRESENT)
    /*
     * When AMD memory encryption is enabled, device memory mappings with the
     * C-bit set read as 0xFF, so ensure the bit is cleared for user mappings.
     */
    pg_prot = pgprot_decrypted(pg_prot);
#endif

    ret = remap_pfn_range(vma, virtaddr, (host_addr >> PAGE_SHIFT),
                          req_size, pg_prot);

    if (ret != 0)
        NV_VGPU_DEV_LOG(VGPU_ERR, mdev,
                        "Failed to do mmap for fault handler. ret: %d\n", ret);

    return ret | VM_FAULT_NOPAGE;
}

void vgpu_mmio_close(struct vm_area_struct *vma)
{
    struct mdev_device *mdev = vma->vm_private_data;
    vgpu_dev_t *vgpu_dev;
    uint32_t index = 0;

    vgpu_dev = mdev_get_drvdata(mdev);
    if (!vgpu_dev)
        return;

    index = DRF_VAL64(_VGPU_VFIO, _PGOFF, _PCI_INDEX, (vma->vm_pgoff << PAGE_SHIFT));

#if defined(NV_VFIO_DEVICE_MIGRATION_INFO_PRESENT)
    if (index == NV_VGPU_VFIO_MIGRATION_REGION) {
        if (vgpu_dev->mig_buffer_base) {
            nv_vfree(vgpu_dev->mig_buffer_base, NV_VFIO_VGPU_MIGRATION_REGION_SIZE_MMAP);
            vgpu_dev->mig_buffer_base = NULL;
        }

    }
#endif
    down(&vgpu_dev->ops_lock);
    vgpu_del_phys_mapping(vgpu_dev, vma->vm_pgoff);
    up(&vgpu_dev->ops_lock);
}

static vm_fault_t vgpu_mmio_fault_wrapper(struct vm_fault *vmf)
{
#if defined(NV_VM_OPS_FAULT_REMOVED_VMA_ARG)
    return vgpu_mmio_fault(vmf->vma, vmf);
#else
    return vgpu_mmio_fault(NULL, vmf);
#endif
}

static const struct vm_operations_struct vgpu_mmio_ops = {
#if defined(NV_VM_OPS_FAULT_REMOVED_VMA_ARG)
    .fault = vgpu_mmio_fault_wrapper,
#else
    .fault = vgpu_mmio_fault,
#endif
    .close = vgpu_mmio_close,
};

static const struct vm_operations_struct vgpu_sparse_ops = {
        .close = vgpu_mmio_close,
};

static pgprot_t nv_vgpu_adjust_pgprot(pgprot_t vm_page_prot)
{
    pgprot_t prot = pgprot_noncached(vm_page_prot);

#if defined(CONFIG_AMD_MEM_ENCRYPT) && defined(NV_PGPROT_DECRYPTED_PRESENT)
    /*
     * When AMD memory encryption is enabled, device memory mappings with the
     * C-bit set read as 0xFF, so ensure the bit is cleared for user mappings.
     */
     prot = pgprot_decrypted(prot);
#endif
    return prot;
}

int nv_vgpu_vfio_mmap(struct mdev_device *mdev, struct vm_area_struct *vma)
{
    uint32_t index = 0;
    int ret = -EINVAL;
    vgpu_dev_t *vgpu_dev;
    struct pci_dev *pdev;

    if (!mdev)
       return ret;

    pdev = to_pci_dev(NV_GET_MDEV_PARENT(mdev));
    vgpu_dev = mdev_get_drvdata(mdev);

    if (!vgpu_dev || !pdev)
    {
        goto mmap_exit;
    }

    index = DRF_VAL64(_VGPU_VFIO, _PGOFF, _PCI_INDEX, (vma->vm_pgoff << PAGE_SHIFT));

    if ((index >= VFIO_PCI_ROM_REGION_INDEX) &&
        (index != NV_VGPU_VFIO_CONSOLE_REGION)
#if defined(NV_VFIO_DEVICE_MIGRATION_INFO_PRESENT)
         && (index != NV_VGPU_VFIO_MIGRATION_REGION)
#endif
       )
    {
        goto mmap_exit;
    }

    vma->vm_private_data = mdev;


    if (pdev->is_virtfn && (index != VFIO_PCI_BAR0_REGION_INDEX) &&
        (index != NV_VGPU_VFIO_CONSOLE_REGION)
#if defined(NV_VFIO_DEVICE_MIGRATION_INFO_PRESENT)
        && (index != NV_VGPU_VFIO_MIGRATION_REGION)
#endif
       )
    {
        unsigned long req_size, pgoff = 0;
        vma->vm_page_prot = nv_vgpu_adjust_pgprot(vma->vm_page_prot);

        pgoff = pci_resource_start(pdev, index);
        pgoff = pgoff >> PAGE_SHIFT;

        if (index == VFIO_PCI_BAR1_REGION_INDEX) {
            req_size = vgpu_dev->region_info[index].size;
        } else {
            req_size = pci_resource_len(pdev,index);
        }

        ret = remap_pfn_range(vma, vma->vm_start, pgoff, req_size, vma->vm_page_prot);
        if (ret != 0)
            goto mmap_exit;
    }
    else

    if (index == VFIO_PCI_BAR1_REGION_INDEX)
    {
        vma->vm_ops = &vgpu_mmio_ops;
        ret = 0;
        vgpu_dev->phys_mappings.bar1_vma = vma;
    }
    else if (index == VFIO_PCI_BAR0_REGION_INDEX && (vgpu_dev->num_areas != 0))
    {
        unsigned long req_size, pgoff = 0, i;
        struct pci_dev *pdev;

        pdev = to_pci_dev(NV_GET_MDEV_PARENT(mdev));
        vma->vm_ops = &vgpu_sparse_ops;

        vma->vm_page_prot = nv_vgpu_adjust_pgprot(vma->vm_page_prot);

        pgoff = DRF_VAL64(_VGPU_VFIO, _PGOFF, _PCI_OFFSET, (vma->vm_pgoff << PAGE_SHIFT));
        for (i = 0; i < vgpu_dev->num_areas; i++)
        {
            if (pgoff != vgpu_dev->offsets[i])
                continue;

            pgoff = pci_resource_start(pdev, 0) + vgpu_dev->offsets[i];
            pgoff = pgoff >> PAGE_SHIFT;
            vma->vm_pgoff = pgoff;
            req_size = vgpu_dev->sizes[i];
            ret = remap_pfn_range(vma, vma->vm_start, pgoff, req_size, vma->vm_page_prot);
            if (ret != 0)
                goto mmap_exit;

            break;
        }
    }
    else if (index == NV_VGPU_VFIO_CONSOLE_REGION)
    {
        if (!vgpu_dev->console.surface) {
            NV_VGPU_DEV_LOG(VGPU_ERR, vgpu_dev->mdev,
                            "console surface not allocated  %d\n",
                            ret);
            goto mmap_exit;
        }

        vma->vm_ops = &vgpu_sparse_ops;

        ret = remap_vmalloc_range(vma, vgpu_dev->console.surface, 0);
        if (ret != 0) {
            NV_VGPU_DEV_LOG(VGPU_ERR, vgpu_dev->mdev,
                            "console remap_vmalloc_range failed, ret= %d\n",
                            ret);
            goto mmap_exit;
        }
    }
#if defined(NV_VFIO_DEVICE_MIGRATION_INFO_PRESENT)
    else if (index == NV_VGPU_VFIO_MIGRATION_REGION)
    {
        vgpu_dev->mig_buffer_base = vmalloc_user(NV_VFIO_VGPU_MIGRATION_REGION_SIZE_MMAP);
        if (vgpu_dev->mig_buffer_base == NULL)
        {
            NV_VGPU_DEV_LOG(VGPU_ERR, vgpu_dev->mdev,
                            "Failed to allocated migration buffer\n");
            ret = -ENOMEM;
            goto mmap_exit;
        }
        NV_VGPU_DEV_LOG(VGPU_INFO, vgpu_dev->mdev,
                        "migration buffer allocated\n");

        vma->vm_ops = &vgpu_sparse_ops;

        ret = remap_vmalloc_range(vma, vgpu_dev->mig_buffer_base, 0);
        if (ret != 0) {
            NV_VGPU_DEV_LOG(VGPU_ERR, vgpu_dev->mdev,
                            "migration remap_vmalloc_range failed, ret= %d\n",
                            ret);
            goto mmap_exit;
        }
        NV_VGPU_DEV_LOG(VGPU_ERR, vgpu_dev->mdev,
                        "Migration buffer mapped\n");
    }
#endif

    if (!ret)
    {
        down(&vgpu_dev->ops_lock);
        ret = vgpu_add_phys_mapping(vgpu_dev, vma->vm_file->f_mapping,
                                    vma->vm_pgoff << PAGE_SHIFT,
                                    vma->vm_end - vma->vm_start);
        up(&vgpu_dev->ops_lock);
    }
mmap_exit:
    if (ret != 0)
        NV_VGPU_DEV_LOG(VGPU_ERR, mdev,
                        "mmap call failed for region %d ret: %d \n", index, ret);
    return ret;
}


/* Wait till 1000 ms for HW that returns CRS completion status */
#define MIN_FLR_WAIT_TIME 100
#define MAX_FLR_WAIT_TIME 1000

/* Trigger Function Level Reset on the SR-IOV VF, as per PCIe spec */
static int do_vf_flr(struct mdev_device *mdev)
{
    struct pci_dev *pdev;
    NvU32 data, elapsed_time = 0;

    pdev = to_pci_dev(NV_GET_MDEV_PARENT(mdev));

    if (!pdev->is_virtfn)
        return 0;

    pcie_capability_read_dword(pdev, PCI_EXP_DEVCAP, &data);
    if (!(data & PCI_EXP_DEVCAP_FLR))
    {
        NV_VGPU_DEV_LOG(VGPU_ERR, mdev, "FLR capability not present on the VF.\n");
        return -EINVAL;
    }

    device_lock(&pdev->dev);
    pci_set_power_state(pdev, PCI_D0);
    pci_save_state(pdev);

    if (!pci_wait_for_pending_transaction(pdev))
        NV_VGPU_DEV_LOG(VGPU_ERR, mdev, "Timed out waiting for transaction pending to go to 0.\n");

    pcie_capability_set_word(pdev, PCI_EXP_DEVCTL, PCI_EXP_DEVCTL_BCR_FLR);

    /* 
     * If CRS-SV is supported and enabled, then the root-port returns '0001h'
     * for a PCI config read of the 16-byte vendor_id field. This indicates CRS
     * completion status.
     * If CRS-SV is not supported/enabled, then the root-port will generally
     * synthesise ~0 data for any PCI config read.
     */

    do {
        msleep (MIN_FLR_WAIT_TIME);
        elapsed_time += MIN_FLR_WAIT_TIME;
        pci_read_config_dword(pdev, PCI_VENDOR_ID, &data);
    } while (((data & 0xffff) == 0x0001) && (elapsed_time < MAX_FLR_WAIT_TIME));

    if ((data & 0xffff) == PCI_VENDOR_ID_NVIDIA)
        goto flr_done;

    if (elapsed_time == MIN_FLR_WAIT_TIME)
    {
        do {
            msleep (MIN_FLR_WAIT_TIME);
            elapsed_time += MIN_FLR_WAIT_TIME;
            pci_read_config_dword(pdev, PCI_COMMAND, &data);
        } while ((data == ~0) && (elapsed_time < MAX_FLR_WAIT_TIME));
        if (data != ~0)
            goto flr_done;
    }

    NV_VGPU_DEV_LOG(VGPU_ERR, mdev, "Failed to return from FLR despite waiting for %d ms.\n", elapsed_time);
        
flr_done:
    pci_restore_state(pdev);
    device_unlock(&pdev->dev);

    return 0;
}

#endif /* NV_VGPU_KVM_BUILD */

static void delete_type_groups(phys_dev_t *phys_dev)
{
    struct attribute_group *vgpu_type_group;
    int i;

    if (phys_dev->vgpu_type_groups == NULL)
        return ;

    for (i = 0; i < phys_dev->num_vgpu_types; i++)
    {
        vgpu_type_group = phys_dev->vgpu_type_groups[i];
        if (vgpu_type_group == NULL)
            break;

        if (vgpu_type_group->name)
            NV_KFREE(vgpu_type_group->name, sizeof(NvU32));

        NV_KFREE(vgpu_type_group, sizeof(struct attribute_group));
    }
    NV_KFREE(phys_dev->vgpu_type_groups,
             sizeof(struct attribute *) * (phys_dev->num_vgpu_types + 1));
}

static NV_STATUS nv_vgpu_probe(struct pci_dev *dev, NvU32 num_vgpu_types, NvU32 *vgpu_type_ids)
{
    NV_STATUS status = NV_OK;
#if defined(NV_VGPU_KVM_BUILD)
    NvU32 i;
    struct  attribute_group *vgpu_type_group = NULL;
    char *vgpu_type_name = NULL;
    phys_dev_t *phys_dev = NULL;

    down(&phys_devices.phys_dev_list_lock);
    if (((status = get_phys_dev(dev, &phys_dev)) != NV_OK) || (phys_dev != NULL))
    {
        up(&phys_devices.phys_dev_list_lock);
        return status;
    }
    up(&phys_devices.phys_dev_list_lock);


    if (dev->is_virtfn)
    {
        NvU64 pf_dma_mask = 0;
#if defined(NV_PCI_IRQ_VECTOR_HELPERS_PRESENT) && defined(NV_MDEV_SET_IOMMU_DEVICE_PRESENT)
        if (pci_enable_device(dev) != 0)
        {
            NV_VGPU_LOG(VGPU_ERR, "pci_enable_device failed for VF, aborting.\n");
            return NV_ERR_GENERIC;
        }
#else
        NV_VGPU_LOG(VGPU_ERR, "Kernel doesn't support SRIOV based vGPU, aborting.\n");
        return NV_ERR_OPERATING_SYSTEM;
#endif

        pci_set_master(dev);

        pf_dma_mask = dma_get_mask(&dev->physfn->dev);
        pci_set_dma_mask(dev, pf_dma_mask);
        pci_set_consistent_dma_mask (dev, pf_dma_mask);
    }


    NV_KMALLOC(phys_dev, sizeof(phys_dev_t));
    if (phys_dev == NULL)
        return NV_ERR_NO_MEMORY;

    memset(phys_dev, 0, sizeof(phys_dev_t));

    phys_dev->num_vgpu_types = num_vgpu_types;
    NV_KMALLOC(phys_dev->vgpu_type_groups, sizeof(struct attribute *) * (num_vgpu_types + 1));
    if (phys_dev->vgpu_type_groups == NULL)
    {
        status = NV_ERR_NO_MEMORY;
        goto probe_fail;
    }

    for (i = 0; i < phys_dev->num_vgpu_types; i++)
    {
        NV_KMALLOC(vgpu_type_group, sizeof(struct attribute_group));
        NV_KMALLOC(vgpu_type_name, sizeof(NvU32));

        if (vgpu_type_name == NULL || vgpu_type_group == NULL)
        {
            status = NV_ERR_NO_MEMORY;
            goto probe_fail;
        }
        memset(vgpu_type_group, 0, sizeof(struct attribute_group));

        snprintf(vgpu_type_name, sizeof(NvU32),"%d",vgpu_type_ids[i]);
        vgpu_type_group->name = vgpu_type_name;
        vgpu_type_group->attrs = vgpu_type_attrs;
        phys_dev->vgpu_type_groups[i] = vgpu_type_group;
    }
    phys_dev->vgpu_type_groups[i] = NULL;

    vgpu_fops.supported_type_groups = phys_dev->vgpu_type_groups;
    if (mdev_register_device(&dev->dev, &vgpu_fops) != 0)
        goto probe_fail;

    phys_dev->dev = dev;

    phys_dev->is_virtfn = dev->is_virtfn;

    INIT_LIST_HEAD(&phys_dev->next);
    NV_INIT_MUTEX(&phys_dev->ops_lock);

    down(&phys_devices.phys_dev_list_lock);
    list_add(&phys_dev->next, &phys_devices.phys_dev_list);
    up(&phys_devices.phys_dev_list_lock);

    return status;
probe_fail:
    delete_type_groups(phys_dev);

    if (dev->is_virtfn)
        pci_disable_device(dev);

#endif

    return status;
}

static void nv_vgpu_remove(struct pci_dev *dev)
{
#if defined(NV_VGPU_KVM_BUILD)
    phys_dev_t *phys_dev, *tmp;

    if(list_empty(&phys_devices.phys_dev_list))
        return;

    list_for_each_entry_safe(phys_dev, tmp, &phys_devices.phys_dev_list, next)
    {
        if (phys_dev->dev == dev)
        {
            mdev_unregister_device(&dev->dev);

            if (dev->is_virtfn)
                pci_disable_device(dev);

            break;
        }
    }

    down(&phys_devices.phys_dev_list_lock);
    list_for_each_entry_safe(phys_dev, tmp, &phys_devices.phys_dev_list, next)
    {
        down(&phys_dev->ops_lock);
        if (phys_dev->dev == dev)
        {
            delete_type_groups(phys_dev);
            list_del(&phys_dev->next);
            up(&phys_dev->ops_lock);
            NV_KFREE(phys_dev, sizeof(phys_dev_t));
            break;
        }
        up(&phys_dev->ops_lock);
    }
    up(&phys_devices.phys_dev_list_lock);
#endif
}

static int __init nv_vgpu_vfio_init(void)
{
#if defined(NV_VGPU_KVM_BUILD)
    rm_vgpu_vfio_ops.version_string = NV_VERSION_STRING;

    if (nvidia_vgpu_vfio_get_ops(&rm_vgpu_vfio_ops) != NV_OK)
    {
        NV_VGPU_LOG(VGPU_ERR, "Version mismatch: "
                    "nvidia.ko(%s) nvidia-vgpu-vfio.ko(%s)\n",
                     rm_vgpu_vfio_ops.version_string, NV_VERSION_STRING);

        return -EINVAL;
    }

    INIT_LIST_HEAD(&phys_devices.phys_dev_list);
    NV_INIT_MUTEX(&phys_devices.phys_dev_list_lock);
    if (nvidia_vgpu_vfio_set_ops(&vgpu_vfio_ops) != NV_OK)
        return -EINVAL;

    if (nv_alloc_chardev_region() != NV_OK)
        return -EIO;

    INIT_LIST_HEAD(&vgpu_devices.vgpu_dev_list);
    NV_INIT_MUTEX(&vgpu_devices.start_lock);
    NV_INIT_MUTEX(&vgpu_devices.vgpu_dev_list_lock);
#endif

    return 0;
}

static void __exit nv_vgpu_vfio_exit(void)
{
#if defined(NV_VGPU_KVM_BUILD)
    phys_dev_t *phys_dev, *tmpdev;

    list_for_each_entry_safe(phys_dev, tmpdev, &phys_devices.phys_dev_list, next)
        mdev_unregister_device(&phys_dev->dev->dev);

    down(&phys_devices.phys_dev_list_lock);
    list_for_each_entry_safe(phys_dev, tmpdev, &phys_devices.phys_dev_list, next)
    {
        down(&phys_dev->ops_lock);
        delete_type_groups(phys_dev);
        list_del(&phys_dev->next);
        up(&phys_dev->ops_lock);
        NV_KFREE(phys_dev, sizeof(phys_dev_t));
    }
    up(&phys_devices.phys_dev_list_lock);

    nv_unregister_chardev_region();

    nvidia_vgpu_vfio_set_ops(NULL);
#endif
}

module_init(nv_vgpu_vfio_init);
module_exit(nv_vgpu_vfio_exit);

MODULE_LICENSE("Dual MIT/GPL");
MODULE_INFO(supported, "external");
MODULE_VERSION(NV_VERSION_STRING);
