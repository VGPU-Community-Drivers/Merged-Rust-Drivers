/* _NVRM_COPYRIGHT_BEGIN_
 *
 * Copyright 2016-2018 by NVIDIA Corporation.  All rights reserved.  All
 * information contained herein is proprietary and confidential to NVIDIA
 * Corporation.  Any use, reproduction, or disclosure without the written
 * permission of NVIDIA Corporation is prohibited.
 *
 * _NVRM_COPYRIGHT_END_
 */

#ifndef _NV_VGPU_VMBUS_H_
#define _NV_VGPU_VMBUS_H_
#if (defined(NV_GRID_BUILD) && defined(NV_VGPU_HYPERV_BUILD))
#include <linux/hyperv.h>

/********* DEFINES NEEDED BY VMBUS *********/
#define NV_INTERRUPT_SOURCE_MAX         16
#define NV_MSG_MAX_BYTE_COUNT           240
#define VERSION_WIN10_V5                ((5 << 16) | (0))
#define RING_BUFFER_IN_PAGE_COUNT       256
#define RING_BUFFER_OUT_PAGE_COUNT      256
#define GPFN_MFN_VMBUS_REQ_ID           1
#define SEND_RINGBUFFER_SIZE            (RING_BUFFER_OUT_PAGE_COUNT*PAGE_SIZE)
#define RECV_RINGBUFFER_SIZE            (RING_BUFFER_IN_PAGE_COUNT*PAGE_SIZE)
/* We are just reading the message/event pages from CPU0 and carrying out all
 * communication there for our SINT. Hence we will always be using CPU #0
 */
#define CPU_ID                          0
#define NV_RECV_MESSAGE_WAIT_MS         100
#define NV_MAX_RETRIES                  10      // Took a minimum value which never failed in my testing
#define NV_MESSAGE_PAYLOAD_QWORD_COUNT  30
#define NV_HYPERV_MSG_NONE              0
/* Guest-initiated messages cannot send messages with a hypervisor message type
 * as they are reserved by hypervisor. Whatever guest has specified this
 * message type value in message header is passed to destination SIMP
 * as it is. So receiver can handle it accordingly based on message type.
 * In our case, receiver is root/parent partition. We don’t have anything specific
 * here, so we just used ‘1’ similar to VMBus-P
 */
#define NV_HYPERV_POST_MSG_TYPE         1
#define NUM_SENDPAGEBUFFER_ELEMENTS     3
#define NV_VMBUS_MESSAGE_SINT_3         3
#define NV_HYPERCALL_FAST_BIT           NVBIT(16)

/* hypercall status code */
#define NV_HYPERV_STATUS_SUCCESS                   0
#define NV_HYPERV_STATUS_INVALID_HYPERCALL_CODE    2
#define NV_HYPERV_STATUS_INVALID_HYPERCALL_INPUT   3
#define NV_HYPERV_STATUS_INVALID_ALIGNMENT         4
#define NV_HYPERV_STATUS_INSUFFICIENT_MEMORY       11
#define NV_HYPERV_STATUS_INVALID_CONNECTION_ID     18
#define NV_HYPERV_STATUS_INSUFFICIENT_BUFFERS      19

/*********************************************/

typedef struct
{
    NvU32 len;
    NvU32 offset;
    NvU64 pfn_array[0];
} nv_mpb_array;

typedef struct
{
    NvU16 type;
    NvU16 dataoffset8;
    NvU16 length8;
    NvU16 flags;
    NvU64 transactionid;
    NvU32 reserved;
    NvU32 rangecount;         /* Always 1 in this case */
    nv_mpb_array range;
} nv_hyperv_channel_packet_mpb;

/* Define port identifier type. */
union nv_hyperv_port_id {
    NvU32 asu32;
    struct {
        NvU32 id:24;
        NvU32 reserved:8;
    } u ;
};

union nv_hyperv_message_flags
{
    NvU8 asu8;
    struct
    {
        NvU8 msg_pending:1;
        NvU8 reserved:7;
    };
};

/* Define synthetic interrupt controller message header. */
typedef struct
{
    NvU32 message_type;
    NvU8 payload_size;
    union nv_hyperv_message_flags message_flags;
    NvU8 reserved[2];
    union
    {
        NvU64 sender;
        union nv_hyperv_port_id port;
    };
} nv_hyperv_message_header_t;

/* Define synthetic interrupt controller message format. */
typedef struct
{
    nv_hyperv_message_header_t header;
    union
    {
        NvU64 payload[NV_MESSAGE_PAYLOAD_QWORD_COUNT];
    } u;
} nv_hyperv_message_t;

/* Declare the various hypercall operations
 * The hypercall identifies the operation to be performed
 * based on this. More information present in
 * Section 17: Appendix A: Hypercall Code Reference
 */
enum nv_hypercall_operation
{
    NV_HYPERV_POST_MESSAGE     = 0x005c,
    NV_HYPERV_SIGNAL_EVENT     = 0x005d,
};

typedef struct
{
    struct vmbus_channel_message_header header;
    NvU8 version_supported;
    NvU8 connection_state;
    NvU16 padding;
    /*
     * This new field is used on new hosts that support VMBus 5.0.
     * On old hosts, we should always use VMBUS_MESSAGE_CONNECTION_ID (1).
     */
    NvU32 msg_conn_id;
} nv_vmbus_channel_version_response_t;

/* The Initiate Contact Message, sent by each of the client drivers,
 * is modified to include a new field specifying the SINT for the
 * host-to-guest signaling. This field replaces part of the existing
 * ‘Interrupt Page’ field, which has not been used since VMBus
 * protocol 2.4.
 */
typedef struct
{
    struct vmbus_channel_message_header header;
    NvU32 vmbus_version_requested;
    NvU32 target_vcpu; /* The VCPU the host should respond to */
    union
    {
        NvU64 interrupt_page;
        struct
        {
            NvU8      msg_sint;
            NvU8      padding1[3];
            NvU32     padding2;
        };
    };
    NvU64 monitor_page1;
    NvU64 monitor_page2;
} nv_vmbus_channel_initiate_contact_t;

enum
{
    NV_VMBUS_MESSAGE_CONNECTION_ID      = 1,
    NV_VMBUS_MESSAGE_CONNECTION_ID_4    = 4,
    NV_VMBUS_MESSAGE_PORT_ID            = 1,
    NV_VMBUS_EVENT_CONNECTION_ID        = 2,
    NV_VMBUS_EVENT_PORT_ID              = 2,
    NV_VMBUS_MONITOR_CONNECTION_ID      = 3,
    NV_VMBUS_MONITOR_PORT_ID            = 3,
    NV_VMBUS_MESSAGE_SINT               = 2,
};

typedef struct
{
    union hv_connection_id connectionid;
    NvU32 reserved;
    NvU32 message_type;
    NvU32 payload_size;
    NvU64 payload[NV_MESSAGE_PAYLOAD_QWORD_COUNT];
} nv_hyperv_input_post_message_t;

/* MSR used to setup pages used to communicate with the hypervisor */
union nv_hyperv_x64_msr_hypercall_contents {
    NvU64 as_uint64;
    struct {
        NvU64 enable:1;
        NvU64 reserved:11;
        NvU64 guest_physical_address:52;
    };
};

/* Define synthetic interrupt source. */
union nv_hyperv_synic_sint
{
    NvU64 as_uint64;
    struct
    {
        NvU64 vector:8;
        NvU64 reserved1:8;
        NvU64 masked:1;
        NvU64 auto_eoi:1;
        NvU64 polling:1;
        NvU64 reserved2:45;
    };
};

/* Define the format of the SIMP register */
union nv_hyperv_synic_simp
{
    NvU64 as_uint64;
    struct
    {
        NvU64 simp_enabled:1;
        NvU64 preserved:11;
        NvU64 base_simp_gpa:52;
    };
};

/* Define the format of the SIEFP register */
union nv_hyperv_synic_siefp
{
    NvU64 as_uint64;
    struct
    {
        NvU64 siefp_enabled:1;
        NvU64 preserved:11;
        NvU64 base_siefp_gpa:52;
    };
};

/* Define SynIC control register. */
union nv_hyperv_synic_scontrol
{
    NvU64 as_uint64;
    struct
    {
        NvU64 enable:1;
        NvU64 reserved:63;
    };
};

typedef struct
{
    /* Interrupt source */
    unsigned int intr_src;
    /* Save the status of SYNIC setting */
    NvBool synic_initialized;
    /* The SIM (synthetic interrupt message) page consists of a 16-element array of
     * 256-byte messages. Each array element (also known as a message slot) corresponds
     * to a single synthetic interrupt source (SINTx).
     */
    nv_hyperv_message_t *synic_message_page;
    /* Used to Post a message using the hypervisor message IPC. We maintain only one
     * post msg page as we always use CPU #0 for all the communications from guest
     */
    void *post_msg_page;
    /* Used to communicate with the hypervisor */
    void *nv_hypercall_pg;
    /* Handle which represents the GPA ranges */
    atomic_t next_gpadl_handle;
    /* If a protocol version 5.0 request is accepted (Version Supported is
     * TRUE), the version response message will return a new field indicating
     * which message connection ID the client must use to send messages to
     * the host. That connection Id is stored in msg_conn_id
     */
    NvU32 msg_conn_id;
    /* We are always using CPU #0. This will store the vCPU ID for CPU #0 */
    int target_vcpu;
    /* Channel associated with the offer from NV_GUID device */
    struct vmbus_channel *guest_channel;
    /* Save the status of offer reciept */
    NvBool offer_received;
} nv_hyperv_context_t;

/* Unmap the rungbuffer */
static inline void nv_hyperv_unmap_ring_buffer(struct hv_ring_buffer_info *ring_info)
{
    vunmap(ring_info->ring_buffer);
}

/* Get the start of the ring buffer. */
static inline void *
nv_hyperv_get_ring_buffer(const struct hv_ring_buffer_info *ring_info)
{
    return ring_info->ring_buffer->buffer;
}

/* Available space in ringbuffer */
static inline NvU32
nv_hyperv_get_available_bytes_in_ring(const struct hv_ring_buffer_info *ring_info)
{
    NvU32 read_loc, write_loc, ring_size, avail_bytes;

    ring_size = ring_info->ring_datasize;
    read_loc = ring_info->ring_buffer->read_index;
    write_loc = ring_info->ring_buffer->write_index;

    if (write_loc >= read_loc)
    {
        avail_bytes = ring_size - (write_loc - read_loc);
    }
    else
    {
        avail_bytes = read_loc - write_loc;
    }

    return avail_bytes;
}

#endif /*NV_VGPU_HYPERV_BUILD  && NV_GRID_BUILD */
#endif /* _NV_VGPU_VMBUS_H_ */
