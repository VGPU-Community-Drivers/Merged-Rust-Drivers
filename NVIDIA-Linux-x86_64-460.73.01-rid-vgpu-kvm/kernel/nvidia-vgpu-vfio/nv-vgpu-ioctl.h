/* _NVRM_COPYRIGHT_BEGIN_
 *
 * Copyright 2017-2020 by NVIDIA Corporation.  All rights reserved.  All
 * information contained herein is proprietary and confidential to NVIDIA
 * Corporation.  Any use, reproduction, or disclosure without the written
 * permission of NVIDIA Corporation is prohibited.
 *
 * _NVRM_COPYRIGHT_END_
 */

#ifndef _NV_VGPU_IOCTL_H_
#define _NV_VGPU_IOCTL_H_

typedef struct
{
    NvP64 pCmdParams;
    NV_STATUS status;
    NvU32 size;
} NV_VGPU_DEV_IOCTL_PARAMS;

#define NV_VGPU_IOCTL_MAGIC 'q'

#define NV_VGPU_IOCTL(cmd) \
    _IOWR(NV_VGPU_IOCTL_MAGIC, cmd, NV_VGPU_DEV_IOCTL_PARAMS)

#define PCI_CONFIG_SPACE_SIZE 256

/* Type of emulated address space
 * Replicated from vmioplugin.h
 */
typedef enum VGPU_EMUL_SPACE_E
{
    VGPU_EMUL_CONFIG_SPACE, /* CONFIG space */
    VGPU_EMUL_IO_PORT,      /* IO Port */
    VGPU_EMUL_MMIO          /* MMIO */
} VGPU_EMUL_SPACE_T;

/* Type of translated address */
typedef enum VGPU_ADDR_TYPE_E
{
    GET_IOVA = 0, /* Get IOMMU address from guest PFN */
    GET_HOST_PFN = 1 /* Get Host PFN from IOMMU addres */
} VGPU_ADDR_TYPE_T;

enum {
    NV_VFIO_DEVICE_STATE_NONE,
    NV_VFIO_DEVICE_STATE_RUNNING,
    NV_VFIO_DEVICE_STATE_MIGRATION_PRECOPY_ACTIVE,
    NV_VFIO_DEVICE_STATE_MIGRATION_STOPNCOPY_ACTIVE,
    NV_VFIO_DEVICE_STATE_MIGRATION_RESUME,
};

/* VGPU EVENT TYPES */
#define NV_VFIO_VGPU_EVENT_VM_REG_ACCESS          1
#define NV_VFIO_VGPU_EVENT_VM_SHUTDOWN            2
#define NV_VFIO_VGPU_EVENT_VM_REBOOT              3
#define NV_VFIO_VGPU_EVENT_ATTACH_DEVICE          4
#define NV_VFIO_VGPU_EVENT_CONSOLE_INFO           5
#define NV_VFIO_VGPU_EVENT_MIGRATION_STATE        6
#define NV_VFIO_VGPU_EVENT_READ_DEVICE_BUFFER     7
#define NV_VFIO_VGPU_EVENT_WRITE_DEVICE_BUFFER    8
#define NV_VFIO_VGPU_EVENT_MAX_COUNT              9

#define VM_UUID_SIZE                         16
#define VGPU_CONFIG_PARAMS_MAX_LENGTH        1024

#define NV_VFIO_VGPU_MIGRATION_REGION_SIZE_MAX  (16 * 1024 * 1024)

/* Data section should start from page aligned offset */
#define NV_VFIO_VGPU_MIGRATION_REGION_DATA_OFFSET   (0x1000)

/* Minus data since first page is used for struct vfio_device_migration_info */
#define NV_VFIO_VGPU_MIGRATION_REGION_SIZE_MMAP     \
    (NV_VFIO_VGPU_MIGRATION_REGION_SIZE_MAX - NV_VFIO_VGPU_MIGRATION_REGION_DATA_OFFSET)

#define NV_VGPU_DEVICE_CONSOLE_REGION               1
#define NV_VGPU_DEVICE_MIGRATION_REGION             2
#define NV_VGPU_DEVICE_STAGING_REGION               3

#define NV_VGPU_DEVICE_PGOFF_REGION_OFFSET    39:0
#define NV_VGPU_DEVICE_PGOFF_REGION_INDEX     43:40

#define NV_VGPU_DEVICE_CONSOLE_REGION_BASE        \
    DRF_NUM64(_VGPU_DEVICE, _PGOFF, _REGION_INDEX, NV_VGPU_DEVICE_CONSOLE_REGION)

#define NV_VGPU_DEVICE_MIGRATION_REGION_BASE      \
    DRF_NUM64(_VGPU_DEVICE, _PGOFF, _REGION_INDEX, NV_VGPU_DEVICE_MIGRATION_REGION)

#define NV_VGPU_DEVICE_STAGING_REGION_BASE      \
    DRF_NUM64(_VGPU_DEVICE, _PGOFF, _REGION_INDEX, NV_VGPU_DEVICE_STAGING_REGION)

/*
 * NV_VFIO_VGPU_EVENT_CREATE
 *
 * This command registers a event with nvidia-vgpu-vfio
 * module. vgpu process waits on the event after registering
 * with nvidia-vgpu-vfio module. This ioctl should only be done
 * on event FD.
 *
 * Parameter:
 *  event_id [IN]
 *    event identifier of the event to be registered with unique FD
 *
 */
#define NV_VFIO_VGPU_EVENT_CREATE                            NV_VGPU_IOCTL(0x01)

/*
 * NV_VFIO_VGPU_EVENT_DESTROY
 *
 * This command removes a event registered earlier with nvidia-vgpu-vfio
 * module. This ioctl should only be done on event FD.
 *
 * Parameter:
 *  event_id [IN]
 *    event identifier of the event to be removed.
 *
 */
#define NV_VFIO_VGPU_EVENT_DESTROY                           NV_VGPU_IOCTL(0x02)

typedef struct
{
    NvU32 eventType;
} NV_VFIO_VGPU_EVENT_PARAMS;

/*
 * NV_VFIO_VGPU_PIN_PAGES
 *
 * This command translates a set of guest pfn to host pfn
 * It calls into nvidia-vgpu-vfio module to translate pages for
 * vGPU on KVM.
 *
 * Parameters:
 *
 * addrType [IN]
 *  enum to specify the type of translated address.
 * pageCount [IN]
 *  Number of PTE entried to be unpinned.
 * pGuestPfnMem [IN]
 *  Pointer to set of Guest PFN which are to be translated
 * pHostPfnMem [OUT]
 *  Pointer to set of host PFNs returned by VFIO for Guest PFNs
 */
#define NV_VFIO_VGPU_PIN_PAGES                                NV_VGPU_IOCTL(0x3)

typedef struct
{
    NvP64 pGuestPfnMem NV_ALIGN_BYTES(8);
    NvP64 pHostPfnMem  NV_ALIGN_BYTES(8);
    NvU32 pageCount;
    VGPU_ADDR_TYPE_T addrType;
} NV_VFIO_VGPU_PIN_PAGES_PARAMS;


/*
 * NV_VFIO_VGPU_UNPIN_PAGES
 *
 * This command unpins a set of GPU PTEs provided by this ioctl
 * It calls into nvidia-vgpu-vfio module to unpin pages for vGPU
 * on KVM.
 *
 * Parameters:
 *
 * addrType [IN]
 *  enum to specify the type of translated address.
 * pageCount [IN]
 *  Number of PTE entried to be unpinned.
 * pGuestPfnMem [IN]
 *  Pointer to set of Guest PFN which are to be unpinned
 */
#define NV_VFIO_VGPU_UNPIN_PAGES                              NV_VGPU_IOCTL(0x4)

typedef struct
{
    NvP64 pGuestPfnMem NV_ALIGN_BYTES(8);
    NvU32 pageCount;
    VGPU_ADDR_TYPE_T addrType;
} NV_VFIO_VGPU_UNPIN_PAGES_PARAMS;


/*
 * NV_VFIO_VGPU_REG_ACCESS_GET_DATA
 *
 * This command retrieves the register access information from RM to do register access
 *
 * Parameters:
 *
 * offset [OUT]
 *  This parameters represents the starting register offset for register access
 *
 * width [OUT]
 *  This paramter represents the no. bytes to be read / write from starting offset
 *
 * data [OUT]
 *  This paramter specifies the data in case of register write.
 *
 * emulSpace [OUT]
 *  This paramter specifies whether region accessed is PCI config space / MMIO /
 *  IO space
 *
 * isWrite [OUT]
 *  This parameter sopecifies whether the operation is register write or not
 */
#define NV_VFIO_VGPU_REG_ACCESS_GET_DATA                     NV_VGPU_IOCTL(0x05)

typedef struct
{
    NvU64 offset;
    NvU32 width;
    VGPU_EMUL_SPACE_T emulSpace;
    NvU8 data[4];
    NvBool isWrite;
} NV_VFIO_VGPU_REG_ACCESS_GET_DATA_PARAMS;


/* NV_VFIO_VGPU_REG_ACCESS_SET_DATA
 *
 * This command specifies the register accesss information to be provided to RM
 *
 * Parameters:
 *
 * data [IN]
 *  This parameter represents the data read in case of register read
 *
 * returnStatus [IN]
 *  This parameter specifies the return status of the register access operation.
 */
#define NV_VFIO_VGPU_REG_ACCESS_SET_DATA                     NV_VGPU_IOCTL(0x06)

typedef struct
{
    NvU8 data[4];
    NV_STATUS returnStatus;
} NV_VFIO_VGPU_REG_ACCESS_SET_DATA_PARAMS;


/* NV_VFIO_VGPU_ADD_MMIO_MAPPING
 *
 * This command specifies the MMIO mapping information required for
 * creating host to guest BAR mapping.
 *
 * Parameters:
 *
 * virtualMMIOStart [IN]
 *  memory mapped address as seen by guest
 *
 * physicalMMIOStart [IN]
 *  corresponding memory mapped address as seen by host
 *
 * mmioSize [IN]
 *  Size of the mapped region
 */
#define NV_VFIO_VGPU_ADD_MMIO_MAPPING                        NV_VGPU_IOCTL(0x07)


/* NV_VFIO_VGPU_REMOVE_MMIO_MAPPING
 *
 * This command specifies the MMIO mapping information required for
 * removing host to guest BAR mapping.
 *
 * Parameters:
 *
 * virtualMMIOStart [IN]
 *  memory mapped address as seen by guest
 *
 * physicalMMIOStart [IN]
 *  corresponding memory mapped address as seen by host
 *
 * mmioSize [IN]
 *  Size of the mapped region
 */
#define NV_VFIO_VGPU_REMOVE_MMIO_MAPPING                     NV_VGPU_IOCTL(0x08)

typedef struct
{
    NvU64 virtualMMIOStart NV_ALIGN_BYTES(8);
    NvU64 physicalMMIOStart NV_ALIGN_BYTES(8);
    NvU64 mmioSize NV_ALIGN_BYTES(8);
} NV_VFIO_VGPU_MMIO_MAPPING_PARAMS;


/*
 * NV_VFIO_VGPU_INJECT_INTERRUPT
 *
 * Inject interrupt from vgpu process for KVM.
 * vgpu process uses this ioctl to inject interrupt in guest VM
 * for KVM
 */
#define NV_VFIO_VGPU_INJECT_INTERRUPT                        NV_VGPU_IOCTL(0x09)


/*
 * NV_VFIO_VGPU_NOTIFY_POWER_OP
 *
 * This command notifies the nvidia-vgpu-vfio module with stop or reboot status.
 * It notifies whether stop or reset has been successfull or not.
 *
 *   returnStatus [IN]
 *     This parameter species whether plugin is shutdown/reset successfully.
 *     it specifies the error code in case plugin shutdown/reset has failed
 *
 * Possible status values returned are:
 *   NV_OK
 *   NV_ERR_OBJECT_NOT_FOUND
 */
#define NV_VFIO_VGPU_NOTIFY_POWER_OP                         NV_VGPU_IOCTL(0x0B)

typedef struct
{
    NV_STATUS returnStatus;
} NV_VFIO_VGPU_NOTIFY_POWER_OP_PARAMS;

#define NV_PCI_BDF_DOMAIN   31:16
#define NV_PCI_BDF_BUS      15:8
#define NV_PCI_BDF_DEVICE    7:3
#define NV_PCI_BDF_FUNCTION  2:0
#define NV_PCI_BDF_DEVFN     7:0


/*
 * NV_VFIO_VGPU_GET_ATTACH_DEVICE_DATA
 *
 * This command retrieves the device data of the corresponding vgpu which is
 * to be attached in the nvidia-vgpu-vfio module.

 *  mdevUuid [OUT]
 *    This parameter specifies mdev devices uuid
 *
 *  configParams [OUT]
 *    This parameter specifies config and extra prams.
 *
 *  qemuPid [OUT]
 *    This parameter specifies the processId of the VM/qemu to which it is
 *    attached.
 *
 *  vgpuId [OUT]
 *    This parameter specifiese the Id of the vgpu device.
 *
 *  gpuPciId [OUT]
 *    This parameter specifies the GPU PCI ID of the vgpu device (PCI ID of PF for SR-IOV).
 *
 *  gpuPciBdf [OUT]
 *    This parameter specifies the Bus, Device, Function of the vgpu device.
 */
#define NV_VFIO_VGPU_GET_ATTACH_DEVICE_DATA                  NV_VGPU_IOCTL(0x0C)

typedef struct
{
    NvU8 mdevUuid[VM_UUID_SIZE];
    NvU8 configParams[VGPU_CONFIG_PARAMS_MAX_LENGTH];
    NvU32 qemuPid;
    NvU16 vgpuId;
    NvU32 gpuPciId;
    NvU32 gpuPciBdf;
} NV_VFIO_VGPU_GET_ATTACH_DEVICE_DATA_PARAMS;


/*
 * NV_VFIO_VGPU_ATTACH_DEVICE_ACK
 *
 * This command notifies the nvidia-vgpu-vfio module that the attach device is
 * completed. This acknowlegment further wakes up the mdev on which attach was
 * called from its wait queue.
 *
 *     instance_id [IN]
 *       This parameter passes on the instanceId vgpu_t to nvidia-vgpu-vfio
 *       module.
 *
 *     return_status [IN]
 *       This parameter specifies whether plugin initalize has succeeded or
 *       failed and contains the error code for it.
 */
#define NV_VFIO_VGPU_ATTACH_DEVICE_ACK                      NV_VGPU_IOCTL(0x0D)

typedef struct
{
    NvU32 instanceId;
    NV_STATUS returnStatus;
} NV_VFIO_VGPU_ATTACH_DEVICE_ACK_PARAMS;

/*
 * NV_VFIO_VGPU_ALLOC_CONSOLE_BUFFER
 * This command allocates system memory for console buffer
 *      size [IN]
 *        Size of console buffer
 *
 */
#define NV_VFIO_VGPU_ALLOC_CONSOLE_BUFFER                   NV_VGPU_IOCTL(0x0E)
#define NV_VFIO_VGPU_FREE_CONSOLE_BUFFER                    NV_VGPU_IOCTL(0x0F)

typedef struct
{
    NvU64 size;
} NV_VFIO_VGPU_CONSOLE_BUFFER_PARAMS;

#define NV_VFIO_VGPU_CONSOLE_SURFACE_SIZE_MAX               (16 * 1024 * 1024)

/*
 *  NV_VFIO_VGPU_SET_CONSOLE_SURFACE_PROP
 *  This command sets console surface properties copied to console buffer.
 *      width [IN]
 *          Width of surface
 *      height [IN]
 *          Height of surface
 *      depth [IN]
 *          Depth of surface
 *      size [IN]
 *          Size of surface
 */
#define NV_VFIO_VGPU_SET_CONSOLE_SURFACE_PROP               NV_VGPU_IOCTL(0x10)

typedef struct
{
    NvU32 width;
    NvU32 height;
    NvU32 depth;
    NvU32 size;
    NvU32 lineSize;
} NV_VFIO_VGPU_CONSOLE_SURFACE_PARAMS;

/*
 * NV_VFIO_VGPU_GET_MIGRATION_STATE
 * This command gets migration state which is set by QEMU
 *      device_state [OUT]
 *          device_state with respect to migration
 */
#define NV_VFIO_VGPU_GET_MIGRATION_STATE                   NV_VGPU_IOCTL(0x11)

typedef struct
{
    NvU32 deviceState;
} NV_VFIO_VGPU_MIGRATION_STATE_PARAMS;

/*
 * NV_VFIO_VGPU_NOTIFY_MIGRATION_STATE_STATUS
 * This command provides the returnStatus of the migration related operation
 * and wakes up the wait_queue
 *      returnStatus [IN]
 *         status of migration related operation.
 */
#define NV_VFIO_VGPU_NOTIFY_MIGRATION_STATE_STATUS        NV_VGPU_IOCTL(0x12)

typedef struct
{
    NV_STATUS returnStatus;
} NV_VFIO_VGPU_NOTIFY_MIGRATION_STATE_STATUS_PARAMS;

/*
 * NV_VFIO_VGPU_GET_MIGRATION_BUFFER_SIZE
 * This commands returns threshold size in case of save VM and number of bytes
 * written in case of resume VM
 * During Save VM:
 *      threshold [OUT] : threshold size received from QEMU
 * During Resume VM:
 *      written [OUT] : number of bytes written in migration region
 */

#define NV_VFIO_VGPU_GET_MIGRATION_BUFFER_SIZE              NV_VGPU_IOCTL(0x13)

/*
 * NV_VFIO_VGPU_SET_MIGRATION_BUFFER_SIZE
 * This commands sets number of bytes written in migration region during Save VM
 * During Save VM:
 *      written [IN] : set number of bytes written in migration region.
 *      pending [IN] : set number of bytes pending.
 */

#define NV_VFIO_VGPU_SET_MIGRATION_BUFFER_SIZE              NV_VGPU_IOCTL(0x14)

typedef struct
{
    NvU64 written;
    NvU64 pending;
    NV_STATUS returnStatus;
} NV_VFIO_VGPU_MIGRATION_BUFFER_SIZE_PARAMS;


/*
 * NV_VFIO_VGPU_VF_REG_ACCESS_HW
 *
 * This command is issued by the nvidia-vgpu-mgr to do VF hardware access.
 *
 * Parameters:
 *
 * offset [IN]
 *  This parameters represents the starting register offset for register access
 *
 * width [IN]
 *  This paramter represents the no. bytes to be read / write from starting offset
 *
 * data [INOUT]
 *  This paramter specifies the data to be read to / written from.
 *  This parameter is IN for read operation and OUT for write operation.
 *
 * emulSpace [IN]
 *  This paramter specifies whether region accessed is PCI config space / MMIO /
 *  IO space
 *
 * isWrite [IN]
 *  This parameter sopecifies whether the operation is register write or not
 */
#define NV_VFIO_VGPU_VF_REG_ACCESS_HW                      NV_VGPU_IOCTL(0x15)

typedef struct
{
    NvU64 offset;
    NvU32 width;
    VGPU_EMUL_SPACE_T emulSpace;
    NvU8 data[4];
    NvBool isWrite;
} NV_VFIO_VGPU_VF_REG_ACCESS_HW_PARAMS;

#endif /* _NV_VGPU_IOCTL_H_ */
