/* _NVRM_COPYRIGHT_BEGIN_
 *
 * Copyright 1999-2018 by NVIDIA Corporation.  All rights reserved.  All
 * information contained herein is proprietary and confidential to NVIDIA
 * Corporation.  Any use, reproduction, or disclosure without the written
 * permission of NVIDIA Corporation is prohibited.
 *
 * _NVRM_COPYRIGHT_END_
 */
#include <nv-linux.h>
#include "nv-vgpu-vmbus.h"

#if (defined(NV_GRID_BUILD) && defined(NV_VGPU_HYPERV_BUILD))
#include <linux/vmalloc.h>
#include <asm/mshyperv.h>
#include <asm/asm.h>
#include <linux/uio.h>
#include "nv-hypervisor.h"

static nv_hyperv_context_t nv_hyperv_ctx = {
    .synic_initialized      = NV_FALSE,
    .next_gpadl_handle      = ATOMIC_INIT(0xE1E10),
    .intr_src               = NV_VMBUS_MESSAGE_SINT_3,
    .offer_received         = NV_FALSE,
};

static uuid_le nv_guid;
static NvBool all_offers_delivered;

/*
 * Hypercalls are an interface for communication with the hypervisor
 *
 * Arguments:
 * control - Hypercall operation
 * input   - Input buffer address
 * output  - Output buffer Address
 *
 * Return Value:
 * Hypercall status codes -
 * - HV_STATUS_SUCCESS                       0
 * - HV_STATUS_INVALID_HYPERCALL_CODE        2
 * - HV_STATUS_INVALID_HYPERCALL_INPUT       3
 * - HV_STATUS_INVALID_ALIGNMENT             4
 * - HV_STATUS_INSUFFICIENT_MEMORY           11
 * - HV_STATUS_INVALID_CONNECTION_ID         18
 * - HV_STATUS_INSUFFICIENT_BUFFERS          19
 */

/*
 * hv_do_fast_hypercall - hypercall with 8 bytes of input and no output
 *
 * Arguments:
 * control - Hypercall operation
 * input   - Connection Id
 *
 * Return Value:
 * Hypercall status codes
 */
static inline u64 hv_do_fast_hypercall(u16 code, u64 input)
{
    u64 hv_status, control = (u64)code | NV_HYPERCALL_FAST_BIT;

    /* Register mapping when the Fast flag is one:
    * +-----+--------------------------------+
    * | x64 |          Contents              |
    * +-----+--------------------------------+
    * |RCX  | Hypercall Input Value          |
    * |RDX  | Input Parameter                |
    * |R8   | Input Parameters               |
    * +-----+--------------------------------+
    */
    __asm__ __volatile__("call *%3"
                         : "=a" (hv_status),
                           "+c" (control), "+d" (input)
                         : "m" (nv_hyperv_ctx.nv_hypercall_pg)
                         : "cc", "r8", "r9", "r10", "r11");
    return hv_status;
}

/*
 * nv_hyperv_hypercall - Perform hypercall for the desired operation
 *
 * Arguments:
 * control - Hypercall operation
 * input   - Input buffer address
 * output  - Output buffer Address
 *
 * Return Value:
 * Hypercall status codes
 */
static inline NvU64 nv_hyperv_hypercall(NvU64 control, void *input, void *output)
{
    NvU64 input_address = input ? virt_to_phys(input) : 0;
    NvU64 output_address = output ? virt_to_phys(output) : 0;
    NvU64 status = 0;

    /* Register mapping for hypercall inputs:
    * +-----+--------------------------------+
    * | x64 |          Contents              |
    * +-----+--------------------------------+
    * |RCX  | Hypercall Input Value          |
    * |RDX  | Input Parameters GPA           |
    * |R8   | Output Parameters GPA          |
    * +-----+--------------------------------+
    */
    __asm__ __volatile__("mov %3, %%r8\n"        // Move output_address to r8 register
                         "call *%4"              // Call function placed at nv_hyperv_ctx.nv_hypercall_pg
                         : "=a" (status),     // Return value is stored in status
                           "+c" (control), "+d" (input_address)  // Values stored in ecx and edx
                         :  "r" (output_address), "m" (nv_hyperv_ctx.nv_hypercall_pg) // Values stored in reg and mem location
                         : "cc", "memory", "r8", "r9", "r10", "r11"); // vals in these reg/mem may b changed in the call

    return status;
}

/*
 * nv_hyperv_copyto_ringbuffer - Helper routine to copy from source to ring buffer.
 *
 * Arguments:
 * ring_info          - Pointer to the ring buffer
 * start_write_offset - Offset to start the copy of data
 * src                - source from which to copy the contents
 * srclen             - Length of data
 *
 * Return Value:
 * NV_ERR_INVALID_ARGUMENT  - Invalid argument received
 * NV_ERR_NO_MEMORY         - Error accessing ring buffer
 * NV_OK                    - Success
 *
 */
static NV_STATUS  nv_hyperv_copyto_ringbuffer(struct hv_ring_buffer_info *ring_info,
                                              NvU32 *start_write_offset, const void *src,
                                              NvU32 srclen)
{
    void *ring_buffer = NULL;
    NvU32 ring_buffer_size = 0;

    /* Validate the arguments */
    if ((ring_info == NULL) || (start_write_offset == NULL) ||
        (src == NULL) || (srclen == 0))
    {
        return NV_ERR_INVALID_ARGUMENT;
    }

    ring_buffer = nv_hyperv_get_ring_buffer(ring_info);
    if (ring_buffer == NULL)
    {
        return NV_ERR_NO_MEMORY;
    }

    ring_buffer_size = ring_info->ring_datasize;

    if (((*start_write_offset) + srclen) > ring_buffer_size)
    {
        /* Wrap around */
        NvU32 bytes_before_end = ring_buffer_size - (*start_write_offset);
        NvU32 bytes_at_start = srclen - bytes_before_end;

        /* Copy data till the end of buffer */
        memcpy(ring_buffer + (*start_write_offset), src, bytes_before_end);

        /* Wrap around and copy remaining bytes from the start */
        memcpy(ring_buffer, src + bytes_before_end, bytes_at_start);

        *start_write_offset = bytes_at_start;
    }
    else
    {
        memcpy(ring_buffer + (*start_write_offset), src, srclen);
        *start_write_offset += srclen;
    }

    return NV_OK;
}

/*
 * nv_hyperv_ringbuffer_write - Write to the ring buffer
 *
 * Arguments:
 * data_list          - Pointer to the buffer which contains data
 * list_count         - # of elements in the data_list
 *
 * Return Value:
 * NV_ERR_INVALID_ARGUMENT -  Invalid argument received
 * NV_ERR_BUFFER_TOO_SMALL - Not enough room to write into the ringbuffer
 * NV_OK                   - Success
 *
 */
static NV_STATUS nv_hyperv_ringbuffer_write(const struct kvec *data_list, u32 list_count)
{
    NV_STATUS status = NV_OK;
    NvU32 bytes_avail_towrite, next_write_location, old_write, i;
    NvU32 totalbytes_towrite = sizeof(u64);
    NvU64 prev_indices;
    unsigned long flags;
    struct vmbus_channel *channel = nv_hyperv_ctx.guest_channel;
    struct hv_ring_buffer_info *outring_info = &channel->outbound;

    /* Validate the arguments */
    if ((data_list == NULL) || (list_count == 0))
    {
        return NV_ERR_INVALID_ARGUMENT;
    }

    for (i = 0; i < list_count; i++)
    {
        totalbytes_towrite += data_list[i].iov_len;
    }

    /* We need to write the previous write index as well */
    totalbytes_towrite += sizeof(NvU64);

    spin_lock_irqsave(&outring_info->ring_lock, flags);

    bytes_avail_towrite = nv_hyperv_get_available_bytes_in_ring(outring_info);

    /*
     * Check if there is enough room
     */
    if (bytes_avail_towrite <= totalbytes_towrite)
    {
        spin_unlock_irqrestore(&outring_info->ring_lock, flags);
        return NV_ERR_BUFFER_TOO_SMALL;
    }

    /* Write to the ring buffer */
    next_write_location = outring_info->ring_buffer->write_index;

    old_write = next_write_location;

    for (i = 0; i < list_count; i++)
    {
        /* Check if there is anything to write */
        if (data_list[i].iov_len != 0)
        {
            status = nv_hyperv_copyto_ringbuffer(outring_info,
                                                 &next_write_location,
                                                 data_list[i].iov_base,
                                                 data_list[i].iov_len);
            if (status != NV_OK)
            {
                return status;
            }
        }
    }

    /* Get the previous write index as u64 of the specified ring buffer. */
    prev_indices = (NvU64)outring_info->ring_buffer->write_index << 32;

    status = nv_hyperv_copyto_ringbuffer(outring_info, &next_write_location,
                                         &prev_indices, sizeof(NvU64));
    if (status != NV_OK)
    {
        return status;
    }

    /* Update the write location */
    outring_info->ring_buffer->write_index = next_write_location;

    spin_unlock_irqrestore(&outring_info->ring_lock, flags);

    /* Signal only if the host needs to be interrupted */
    if (outring_info->ring_buffer->interrupt_mask == 0)
    {
        /*
         * This is the only case we need to signal when the
         * ring transitions from being empty to non-empty.
         */
        if (old_write == outring_info->ring_buffer->read_index)
        {
            NvU64 ret = 0;

            ret = hv_do_fast_hypercall(NV_HYPERV_SIGNAL_EVENT, nv_hyperv_ctx.guest_channel->offermsg.connection_id);
            if (ret != 0)
            {
                return NV_ERR_OPERATING_SYSTEM;
            }
        }
    }

    return NV_OK;
}

/*
 * nv_hyperv_post_msg - Invoke nv_hyperv_hypercall for the desired operation
 * Retry the invocation in case of INSUFFICIENT_MEMORY/BUFFER issue
 * More information about the steps taken by hypervisor for posting message
 * and the working of message buffers is present in section 11 of TLFS named
 * Inter-Partition Communication
 *
 * Arguments:
 * msg_buff  - Actual message to be sent
 * msg_size  - Size of message to be sent
 *
 * Return Value:
 * NV_ERR_INVALID_ARGUMENT - Message size exceeds max allowed payload size
 * NV_ERR_OPERATING_SYSTEM - nv_hyperv_hypercall did not succeed
 * NV_ERR_NO_MEMORY        - Post message/ hypercall page is NULL
 * NV_OK                   - Success
 *
 */
static NV_STATUS nv_hyperv_post_msg(void *msg_buff, size_t msg_size)
{
    nv_hyperv_input_post_message_t *aligned_msg;
    union hv_connection_id conn_id;
    NvU32 retries = 0;
    int ret = HV_STATUS_SUCCESS;

    if (msg_size > NV_MSG_MAX_BYTE_COUNT)
    {
        /* Message size exceeds max allowed payload size*/
        return NV_ERR_INVALID_ARGUMENT;
    }
    if ((nv_hyperv_ctx.post_msg_page == NULL) || (nv_hyperv_ctx.nv_hypercall_pg == NULL))
    {
        /* Post message/ hypercall page is NULL */
        return NV_ERR_NO_MEMORY;
    }

    conn_id.asu32 = 0;
    conn_id.u.id = nv_hyperv_ctx.msg_conn_id;
    aligned_msg = nv_hyperv_ctx.post_msg_page;
    aligned_msg->connectionid = conn_id;
    aligned_msg->reserved = 0;
    aligned_msg->message_type = NV_HYPERV_POST_MSG_TYPE;
    aligned_msg->payload_size = msg_size;
    memcpy((void *)aligned_msg->payload, msg_buff, msg_size);

    for (retries = 0; retries < NV_MAX_RETRIES; retries++)
    {
        ret = nv_hyperv_hypercall(NV_HYPERV_POST_MESSAGE, aligned_msg, NULL);
        if (ret == HV_STATUS_SUCCESS)
        {
            return NV_OK;
        }
        else if ((ret == NV_HYPERV_STATUS_INSUFFICIENT_MEMORY) ||
                 (ret == NV_HYPERV_STATUS_INSUFFICIENT_BUFFERS))
        {
            /* For each VMBus client SINTx is unique. So message buffers are also
             * separate for each client. As POST_MESSAGE is asynchronous hyper
             * call so sender may send multiple message with the same SINTx which
             * can be queued to a virtual processor. So till the time receiver
             * (in our case root/parent partition) reads the message from SIMP
             * page and sets EOM, these messages are kept queued in message buffer
             * queue by hypervisor.
             * Hence, hypercall may fail intermittently due to insufficient
             * resources. In this case, try again
             */
            msleep(1);
            continue;
        }
        else
        {
            /* For any other error, exit */
            break;
        }
    }

    nv_printf(NV_DBG_ERRORS, "NVRM: hypercall failed with error: 0x%x\n", ret);

    return NV_ERR_OPERATING_SYSTEM;
}

/*
 * handle_fetch_offer - Callback invoked on getting CHANNELMSG_OFFERCHANNEL
 * This function checks if the device from which the offer is recieved is the
 * one which we want. If it is some other device, then we skip processing the
 * offer. Else we create the channel for the offer and copy the offer to the
 * channel.
 *
 * Arguments:
 * offer_channel - Pointer to the message header of type CHANNELMSG_OFFERCHANNEL
 *
 * Return Value:
 * NV_ERR_INVALID_ARGUMENT   - offer_channel is NULL
 * NV_ERR_OTHER_DEVICE_FOUND - Offer recieved from device other than the one which we want
 * NV_ERR_NO_MEMORY          - Unable to allocate channel object
 * NV_OK                     - Success
 */
static NV_STATUS handle_fetch_offer(struct vmbus_channel_offer_channel *offer_channel)
{
    uuid_le *guid;

    if (offer_channel == NULL)
    {
        return NV_ERR_INVALID_ARGUMENT;
    }

    guid = &offer_channel->offer.if_type;

    nv_printf(NV_DBG_INFO,"NVRM: Offer recieved from device: {%pUl}\n", guid);

    /* Check if the offer is recieved from the desired device */
    if (uuid_le_cmp(*guid, nv_guid))
    {
        /* No need to process the offer */
        return NV_ERR_OTHER_DEVICE_FOUND;
    }

    /* Offer recieved from the desired device */
    if (nv_hyperv_ctx.offer_received)
    {
        /* We have already received the offer from desired device.
         * Print the GUID for info and return. Currently we do not handle
         * the multi-vGPU scenario
         */
        nv_printf(NV_DBG_INFO,"NVRM: Already received offer for Nvidia vGPU\n");
        return NV_OK;

    }
    NV_KMALLOC_ATOMIC(nv_hyperv_ctx.guest_channel, sizeof(*nv_hyperv_ctx.guest_channel));
    if (nv_hyperv_ctx.guest_channel == NULL)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: Unable to allocate channel object\n");
        return NV_ERR_NO_MEMORY;
    }

    memset(nv_hyperv_ctx.guest_channel, 0, sizeof(*nv_hyperv_ctx.guest_channel));

    memcpy(&nv_hyperv_ctx.guest_channel->offermsg, offer_channel,
           sizeof(struct vmbus_channel_offer_channel));

    nv_hyperv_ctx.offer_received = NV_TRUE;

    return NV_OK;
}

/*
 * handle_version_response - Callback invoked on getting message of type
 * CHANNELMSG_VERSION_RESPONSE
 *
 * Arguments:
 * data  - Pointer to the message header of type CHANNELMSG_OFFERCHANNEL
 *
 * Return Value:
 * NV_ERR_NOT_SUPPORTED    - Request is unsuccessful
 * NV_ERR_INVALID_ARGUMENT - version_response is NULL
 * NV_OK                   - Success
 */
static NV_STATUS handle_version_response(nv_vmbus_channel_version_response_t *version_response)
{
    if (version_response == NULL)
    {
        return NV_ERR_INVALID_ARGUMENT;
    }

    /* Check if successful */
    if (version_response->version_supported)
    {
        /* If a protocol version 5.0 request is accepted (Version Supported is
         * TRUE), the version response message will return a new field indicating
         * which message connection ID the client must use to send messages to
         * the host. The protocol version is mentioned in the call to initiate
         * contact, which was VERSION_WIN10_V5 in our case.
         */
        nv_hyperv_ctx.msg_conn_id = version_response->msg_conn_id;
    }
    else
    {
        return NV_ERR_NOT_SUPPORTED;
    }

    return NV_OK;
}

/*
 * mark_msg_as_read - Inform that the message was read
 *
 * Arguments:
 * message_type - Type of message
 *
 * Return Value:
 * void
 *
 */
static inline void mark_msg_as_read(enum vmbus_channel_message_type *message_type)
{
    *message_type = NV_HYPERV_MSG_NONE;
    wrmsrl(HV_X64_MSR_EOM, 0);
}

/*
 * handle_all_offers_delivered - Callback invoked on getting message of type
 * CHANNELMSG_ALLOFFERS_DELIVERED
 *
 * Arguments:
 * None
 *
 * Return Value:
 * void
 */
static void handle_all_offers_delivered(void)
{
    /* All offers are delivered */
    all_offers_delivered = NV_TRUE;
}

/*
 * nv_vmbus_wait_for_message - Keeps an eye on the synic_message_page to check if
 * there is any message recieved which is meant for our interrupt source
 * If the message type doesn't match with the one which is expected, an
 * explicit EOM is signalled, which will cause the current message to be
 * discarded and the next one in queue will be fetched. The number of retries
 * done is NV_RECV_MESSAGE_WAIT_MS. An error is thrown if we dont find message
 * of type message_type even after all the retries.
 *
 * Arguments:
 * message_type   - Type of message to lookout for
 * message_copy   - To copy the message into before marking it as read.
 *                  This can be NULL is not postprocessing is needed.
 *
 * Return Value:
 * NV_ERR_INVALID_ARGUMENT - msg or chan_msg_hdr are NULL
 * NV_ERR_OBJECT_NOT_FOUND - Did not find message of type message_type
 * NV_OK                   - Success
 */
static NV_STATUS nv_vmbus_wait_for_message(enum vmbus_channel_message_type message_type,
                                           void *message_copy)
{
    nv_hyperv_message_t *msg = nv_hyperv_ctx.synic_message_page + nv_hyperv_ctx.intr_src;
    struct vmbus_channel_message_header *chan_msg_hdr = (struct vmbus_channel_message_header *)msg->u.payload;
    NvU32 retries = 0;

    /* Validate the msg and chan_msg_hdr before accessing them */
    if ((msg == NULL) || (chan_msg_hdr == NULL))
    {
        return NV_ERR_INVALID_ARGUMENT;
    }

    for (retries = 0; retries < NV_RECV_MESSAGE_WAIT_MS; retries++)
    {
        if (msg->header.message_type != NV_HYPERV_MSG_NONE)
        {
            /* There is a valid message in our message slot */
            if (chan_msg_hdr->msgtype == message_type)
            {
                /* Copy the message only if some post-processing is needed */
                if (message_copy)
                {
                    memcpy(message_copy, chan_msg_hdr, msg->header.payload_size);
                }

                /* Inform that the message was read */
                mark_msg_as_read(&msg->header.message_type);

                return NV_OK;
            }
            /* Received ALLOFFERS_DELIVERED message while waiting for offer */
            else if ((message_type == CHANNELMSG_OFFERCHANNEL) &&
                     (chan_msg_hdr->msgtype == CHANNELMSG_ALLOFFERS_DELIVERED))
            {
                /* All offers are delivered */
                handle_all_offers_delivered();

                /* Inform that the message was read */
                mark_msg_as_read(&msg->header.message_type);

                return NV_OK;
            }

            /* Empty the message slot to get the next message */
            mark_msg_as_read(&msg->header.message_type);
        }
        msleep(1);
    }
    return NV_ERR_OBJECT_NOT_FOUND;
}

/*
 * nv_vmbus_create_gpadl_header - Creates and inits the GPADL header and body.
 * There is only a fixed nunmber of pfns that can fit in the GPADL header.
 * If the count goes beyond that, then the pfns are added in followup packets.
 * nv_gpadl_body are those followup packets which we send.
 *
 * Arguments:
 * buffer    - Pointer to ringbuffer
 * msginfo   - Save the GPADL header and body info
 *
 * Return Value:
 * NV_ERR_NO_MEMORY - Error while allocating GPADL header/body
 * NV_OK            - Success
 */
static NV_STATUS nv_vmbus_create_gpadl_header(void *buffer, struct vmbus_channel_msginfo **msginfo)
{
    struct vmbus_channel_gpadl_header *gpadl_header = NULL;
    struct vmbus_channel_gpadl_body *gpadl_body     = NULL;
    struct vmbus_channel_msginfo *msg_header        = NULL;
    struct vmbus_channel_msginfo *msg_body          = NULL;
    NvU32 msg_size, pfn, pfn_size, page_count;
    NvU32 pfn_added, pfn_count, pfn_pending, pfn_curr;

    page_count = (SEND_RINGBUFFER_SIZE + RECV_RINGBUFFER_SIZE) >> PAGE_SHIFT;

    pfn_size = NV_MSG_MAX_BYTE_COUNT - sizeof(struct vmbus_channel_gpadl_header)
               - sizeof(struct gpa_range);
    pfn_count = pfn_size / sizeof(NvU64);

    /* As we are writing minimum pfn_count pfns to the buffer, ensure that
     * pfn_count is <= page_count
     */
    if (pfn_count > page_count)
    {
        return NV_ERR_NO_MEMORY;
    }

    msg_size = sizeof(struct vmbus_channel_msginfo) +
               sizeof(struct vmbus_channel_gpadl_header) +
               sizeof(struct gpa_range) + pfn_count * sizeof(NvU64);

    NV_KMALLOC(msg_header, msg_size);
    if (!msg_header)
    {
        goto error;
    }

    memset(msg_header, 0, msg_size);

    INIT_LIST_HEAD(&msg_header->submsglist);
    msg_header->msgsize = msg_size;

    gpadl_header = (struct vmbus_channel_gpadl_header *)
                      msg_header->msg;
    gpadl_header->rangecount = 1;
    gpadl_header->range_buflen = sizeof(struct gpa_range) +
                                    page_count * sizeof(NvU64);
    gpadl_header->range[0].byte_offset = 0;
    gpadl_header->range[0].byte_count = SEND_RINGBUFFER_SIZE
                                           + RECV_RINGBUFFER_SIZE;

    for (pfn = 0; pfn < pfn_count; pfn++)
    {
        gpadl_header->range[0].pfn_array[pfn] = virt_to_phys(buffer + PAGE_SIZE * pfn)
                                                   >> PAGE_SHIFT;
    }

    *msginfo = msg_header;
    pfn_added = pfn_count;
    pfn_pending = page_count - pfn_count;

    pfn_size = NV_MSG_MAX_BYTE_COUNT -
               sizeof(struct vmbus_channel_gpadl_body);
    pfn_count = pfn_size / sizeof(NvU64);

    while (pfn_pending)
    {
        pfn_curr = (pfn_pending > pfn_count) ? pfn_count : pfn_pending;

        msg_size = sizeof(struct vmbus_channel_msginfo) +
                   sizeof(struct vmbus_channel_gpadl_body) +
                   pfn_curr * sizeof(NvU64);

        NV_KMALLOC_ATOMIC(msg_body, msg_size);
        if (!msg_body)
        {
            goto error;
        }

        memset(msg_body, 0, msg_size);

        msg_body->msgsize = msg_size;
        gpadl_body = (struct vmbus_channel_gpadl_body *)msg_body->msg;

        for (pfn = 0; pfn < pfn_curr; pfn++)
        {
            gpadl_body->pfn[pfn] = virt_to_phys(buffer + PAGE_SIZE * (pfn_added + pfn))
                                      >> PAGE_SHIFT;
        }

        list_add_tail(&msg_body->msglistentry, &msg_header->submsglist);
        pfn_added += pfn_curr;
        pfn_pending -= pfn_curr;
    }

    return NV_OK;

error:

    if (msg_header)
    {
        struct vmbus_channel_msginfo *msg = NULL;
        struct vmbus_channel_msginfo *entry = NULL;

        /*
         * Free up all the allocated messages.
         */
        list_for_each_entry_safe(msg, entry, &msg_header->submsglist,
                                 msglistentry)
        {
            list_del(&msg->msglistentry);
            NV_KFREE(msg, msg->msgsize);
        }
        NV_KFREE(msg_header, msg_header->msgsize);
    }

    return NV_ERR_NO_MEMORY;
}

/*
 * nv_vmbus_establish_gpadl - Creates a Guest Physical Address Descriptor List (GPADL)
 * and sends CHANNELMSG_GPADL_HEADER and CHANNELMSG_GPADL_BODY messages informing
 * about the GPADL. It waits to recieve the CHANNELMSG_GPADL_CREATED message
 * from hypervisor.
 *
 * Arguments:
 * buffer    - Pointer to ringbuffer
 *
 * Return Value:
 * NV_ERR_NO_MEMORY        - Error while allocating GPADL header/body
 * NV_ERR_OPERATING_SYSTEM - Error returned from hypercall
 * NV_OK                   - Success
 */
static NV_STATUS nv_vmbus_establish_gpadl(void *buffer)
{
    struct vmbus_channel_gpadl_header *gpadlmsg;
    struct vmbus_channel_gpadl_body *gpadl_body;
    struct vmbus_channel_msginfo *msginfo = NULL;
    struct vmbus_channel_msginfo *submsginfo;
    struct list_head *curr;
    NvU32 next_gpadl_handle = atomic_inc_return(&nv_hyperv_ctx.next_gpadl_handle) - 1;
    NV_STATUS status = NV_OK;

    status = nv_vmbus_create_gpadl_header(buffer, &msginfo);
    if (status != NV_OK)
    {
        return status;
    }

    gpadlmsg = (struct vmbus_channel_gpadl_header *)msginfo->msg;
    gpadlmsg->header.msgtype = CHANNELMSG_GPADL_HEADER;
    gpadlmsg->child_relid = nv_hyperv_ctx.guest_channel->offermsg.child_relid;
    gpadlmsg->gpadl = next_gpadl_handle;

    status = nv_hyperv_post_msg(gpadlmsg, msginfo->msgsize - sizeof(*msginfo));
    if (status != NV_OK)
    {
        goto cleanup;
    }

    list_for_each(curr, &msginfo->submsglist)
    {
        submsginfo = (struct vmbus_channel_msginfo *)curr;
        gpadl_body = (struct vmbus_channel_gpadl_body *)submsginfo->msg;

        gpadl_body->header.msgtype = CHANNELMSG_GPADL_BODY;
        gpadl_body->gpadl = next_gpadl_handle;

        status = nv_hyperv_post_msg(gpadl_body, submsginfo->msgsize - sizeof(*submsginfo));
        if (status != NV_OK)
        {
            goto cleanup;
        }
    }

    status = nv_vmbus_wait_for_message(CHANNELMSG_GPADL_CREATED, NULL);
    if (status != NV_OK)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: Failed to establish GPADL!\n");
        return status;
    }

    nv_hyperv_ctx.guest_channel->ringbuffer_gpadlhandle = gpadlmsg->gpadl;

cleanup:

    /* Free up the message list */
    if (msginfo)
    {
        struct vmbus_channel_msginfo *msg = NULL;
        struct vmbus_channel_msginfo *entry = NULL;
        /*
         * Free up all the allocated messages.
         */
        list_for_each_entry_safe(msg, entry, &msginfo->submsglist,
                                 msglistentry)
        {
            list_del(&msg->msglistentry);
            NV_KFREE(msg, msg->msgsize);
        }

        NV_KFREE(msginfo, msginfo->msgsize);
    }

    return status;
}

/*
 * nv_vmbus_init_ringbuffer - Maps the ringbuffer pages using vmap, initialises
 * the read and write indexes of the ringbuffer and updates the ring_size
 * and ring_datasize.
 * The ring buffer is used to communicate with the parent partition
 *
 * Arguments:
 * ring_info - Ring buffer info is store here
 * pages     - Pointer to Ring buffer allocated
 * page_cnt  - # of pages in the allocated ring buffer
 *
 * Return Value:
 * NV_ERR_NO_MEMORY - Error while allocating/mapping GPADL header/body
 * NV_OK            - Success
 */
static NV_STATUS nv_vmbus_init_ringbuffer(struct hv_ring_buffer_info *ring_info,
                       struct page *pages, NvU32 page_cnt)
{
    int i = 0;
    struct page **page_addr;

    memset(ring_info, 0, sizeof(struct hv_ring_buffer_info));

    NV_KMALLOC_ATOMIC(page_addr, sizeof(struct page *) * (page_cnt));
    if (!page_addr)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: Failed to allocate ring buffer\n");
        return NV_ERR_NO_MEMORY;
    }

    memset(page_addr, 0, sizeof(struct page *) * (page_cnt));

    for (i = 0; i < page_cnt; i++)
    {
        page_addr[i] = &pages[i];
    }

    ring_info->ring_buffer = (struct hv_ring_buffer *)
                             vmap(page_addr, page_cnt, VM_MAP, PAGE_KERNEL);

    NV_KFREE(page_addr, sizeof(struct page *) * (page_cnt));

    if (ring_info->ring_buffer == NULL)
    {
        return NV_ERR_NO_MEMORY;
    }

    ring_info->ring_buffer->read_index = ring_info->ring_buffer->write_index = 0;

    ring_info->ring_size = page_cnt << PAGE_SHIFT;
    ring_info->ring_datasize = ring_info->ring_size - sizeof(struct hv_ring_buffer);

    return NV_OK;
}

/*
 * nv_vmbus_open - Opens the channel offer.
 * When requested via a request offer message, all clients receive the
 * same pool of channel offers. New hot-added channel offers are sent to
 * all active clients in an unspecified order. The first client to open
 * a channel offer owns that offer.
 *
 * Arguments:
 * None
 *
 * Return Value:
 * NV_ERR_NO_MEMORY        - Error while allocating the ring buffer
 * NV_ERR_OPERATING_SYSTEM - Error returned from hypercall
 * NV_OK                   - Success
 */
static NV_STATUS nv_vmbus_open(void)
{
    NV_STATUS status = NV_OK;
    struct vmbus_channel_open_channel open_msg;
    struct page *page;

    /* Allocate the ring buffer */
    page = alloc_pages_node(cpu_to_node(CPU_ID),
                            GFP_KERNEL|__GFP_ZERO,
                            get_order(SEND_RINGBUFFER_SIZE +
                            RECV_RINGBUFFER_SIZE));
    if (!page)
    {
        return NV_ERR_NO_MEMORY;
    }

#ifdef NV_VMBUS_CHANNEL_HAS_RING_BUFFER_PAGE
    nv_hyperv_ctx.guest_channel->ringbuffer_page = page;
#else
    nv_hyperv_ctx.guest_channel->ringbuffer_pages = page_address(page);
#endif

    nv_hyperv_ctx.guest_channel->ringbuffer_pagecount = (SEND_RINGBUFFER_SIZE +
                                                  RECV_RINGBUFFER_SIZE)
                                                  >> PAGE_SHIFT;


    status = nv_vmbus_init_ringbuffer(&nv_hyperv_ctx.guest_channel->outbound, page,
                                   SEND_RINGBUFFER_SIZE >> PAGE_SHIFT);
    if (status != NV_OK)
    {
        return status;
    }

    status = nv_vmbus_init_ringbuffer(&nv_hyperv_ctx.guest_channel->inbound,
                                      &page[SEND_RINGBUFFER_SIZE >> PAGE_SHIFT],
                                      RECV_RINGBUFFER_SIZE >> PAGE_SHIFT);
    if (status != NV_OK)
    {
        return status;
    }

    nv_hyperv_ctx.guest_channel->ringbuffer_gpadlhandle = 0;

    status = nv_vmbus_establish_gpadl(page_address(page));
    if (status != NV_OK)
    {
        return status;
    }

    open_msg.header.msgtype = CHANNELMSG_OPENCHANNEL;
    open_msg.openid = nv_hyperv_ctx.guest_channel->offermsg.child_relid;
    open_msg.child_relid = nv_hyperv_ctx.guest_channel->offermsg.child_relid;
    open_msg.ringbuffer_gpadlhandle = nv_hyperv_ctx.guest_channel->ringbuffer_gpadlhandle;
    open_msg.downstream_ringbuffer_pageoffset = SEND_RINGBUFFER_SIZE >> PAGE_SHIFT;
    open_msg.target_vp = nv_hyperv_ctx.guest_channel->target_vp;

    status = nv_hyperv_post_msg(&open_msg, sizeof(struct vmbus_channel_open_channel));
    if (status != NV_OK)
    {
        return status;
    }

    status = nv_vmbus_wait_for_message(CHANNELMSG_OPENCHANNEL_RESULT, NULL);
    if (status != NV_OK)
    {
        return status;
    }

    return status;
}

/*
 * nv_vmbus_initiate_contact - Initiates contact by sending a message of type
 * CHANNELMSG_INITIATE_CONTACT for the version specified. The connection ID
 * used is NV_VMBUS_MESSAGE_CONNECTION_ID_4. Once the message is sent, it waits
 * for CHANNELMSG_VERSION_RESPONSE. The version response message will return a
 * new field indicating which message connection ID the client must use to
 * send messages to the host.
 *
 * Arguments:
 * version  - Protocol Version for which initiate request is to be sent
 *
 * Return Value:
 * NV_ERR_NOT_SUPPORTED    - Request is unsuccessful
 * NV_ERR_OPERATING_SYSTEM - Error returned from hypercall
 * NV_OK                   - Successful setup
 *
 */
static NV_STATUS nv_vmbus_initiate_contact(NvU32 version)
{
    NV_STATUS status = NV_OK;
    nv_vmbus_channel_initiate_contact_t initiate_msg;
    nv_vmbus_channel_version_response_t version_response;

    memset(&initiate_msg, 0, sizeof(initiate_msg));
    initiate_msg.header.msgtype = CHANNELMSG_INITIATE_CONTACT;
    initiate_msg.vmbus_version_requested = version;

    /* The Initiate Contact Message, sent by each of the client drivers,
     * is modified to include a new field specifying the SINT for the host-to-guest
     * signaling. This field replaces part of the existing ‘Interrupt Page’
     * field, which has not been used since VMBus protocol 2.4
     */
    initiate_msg.msg_sint = nv_hyperv_ctx.intr_src;
    nv_hyperv_ctx.msg_conn_id = NV_VMBUS_MESSAGE_CONNECTION_ID_4;
    initiate_msg.target_vcpu = nv_hyperv_ctx.target_vcpu;

    status = nv_hyperv_post_msg(&initiate_msg, sizeof(nv_vmbus_channel_initiate_contact_t));
    if (status != NV_OK)
    {
        return status;
    }

    /* Wait for the connection response */
    status = nv_vmbus_wait_for_message(CHANNELMSG_VERSION_RESPONSE, (void *)&version_response);
    if (status != NV_OK)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: No response recieved for INITIATE_CONTACT\n");
        return status;
    }

    status = handle_version_response(&version_response);
    if (status != NV_OK)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: Unsupported protocol version\n");
        return status;
    }

    return status;
}

/*
 * nv_vmbus_request_offers - Request for any pending offers
 * This is achieved by sending a message of type CHANNELMSG_REQUESTOFFERS. It
 * then waits till it recieves a message CHANNELMSG_OFFERCHANNEL. In the
 * handler for this message, it checks if the offer is recieved from NV_GUID.
 * If not, we keep on polling till we get the offer from the desired device.
 *
 * Arguments:
 * None
 *
 * Return Value:
 * NV_ERR_OBJECT_NOT_FOUND - Offer recieved from device other than the one which we want
 * NV_ERR_OPERATING_SYSTEM - Error returned from hypercall
 * NV_ERR_NO_MEMORY        - Unable to allocate channel object
 * NV_OK                   - Successful setup
 *
 */
static NV_STATUS nv_vmbus_request_offers(void)
{
    struct vmbus_channel_message_header msg;
    struct vmbus_channel_offer_channel offer_channel;
    NV_STATUS status = NV_OK;

    msg.msgtype = CHANNELMSG_REQUESTOFFERS;

    status = nv_hyperv_post_msg(&msg, sizeof(struct vmbus_channel_message_header));
    if (status != NV_OK)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: Unable to request offers - STATUS: 0x%x\n", status);
        return status;
    }

    all_offers_delivered = NV_FALSE;

    /* We will get offers from all those devices for which nobody has called
     * open yet. Hence, keep fetching the offers till we get the one from NV_GUID
     */
    do
    {
        status = nv_vmbus_wait_for_message(CHANNELMSG_OFFERCHANNEL, (void *)&offer_channel);

        if ((all_offers_delivered) || (status != NV_OK))
        {
            /* No Need to process further messages */
            break;
        }

        /* Handle the offer only if we found the message */
        status = handle_fetch_offer(&offer_channel);
    } while (1);  /* Consume all the offers */

    if ((status != NV_OK) || (!nv_hyperv_ctx.offer_received))
    {
        nv_printf(NV_DBG_ERRORS,
                  "NVRM: No response recieved for OFFERCHANNEL: Status - 0x%x\n",
                  status);

        return status;
    }

    return NV_OK;
}

/* is_sint_available - Check if nobody else is using the desired SINT
 *
 * Arguments
 * None
 *
 * Return Values
 * NV_FALSE - Desired SINT is used by some other VMBUS client
 * NV_TRUE  - Desired SINT is Available
 */
static inline NvBool is_sint_available(void)
{
    union nv_hyperv_synic_sint sint_state;

    rdmsrl(HV_X64_MSR_SINT0 + nv_hyperv_ctx.intr_src, sint_state.as_uint64);
    if (sint_state.masked)
    {
        /* SINT is not in-use */
        return NV_TRUE;
    }

    return NV_FALSE;
}

/*
 * nv_hyperv_synic_init - Read the MSRs for CPU #0 and fetch the Message and Event
 * pages addresses. Set the polling bit and unmask the interrupt source
 * for the SINT which we will be using. Set the enable bit in the scontrol
 * register
 * MSR (model-specific registers): Used for status and control values
 *
 * Arguments:
 * pData - Pointer to the buffer containing any args
 *
 * Return Values:
 * void
 */
static void nv_hyperv_synic_init(void *data)
{
    NvU32 cpu = get_cpu();

    if (cpu == CPU_ID)
    {
        union nv_hyperv_synic_simp simp;
        union nv_hyperv_synic_sint sint_state;
        union nv_hyperv_synic_scontrol sctrl;

        if (!is_sint_available())
        {
            /* SINT is not available */
            goto exit;
        }

        /* The event and message pages are already allocated by VMBUS-P client.
         * We just need to query the offset (physical location is stored)
         */

        /* Message Page */
        rdmsrl(HV_X64_MSR_SIMP, simp.as_uint64);
        nv_hyperv_ctx.synic_message_page = phys_to_virt(simp.base_simp_gpa << PAGE_SHIFT);

        /* Set the polling bit and unmask the interrupt source */
        rdmsrl(HV_X64_MSR_SINT0 + nv_hyperv_ctx.intr_src, sint_state.as_uint64);
        sint_state.polling = true;
        sint_state.masked = false;

        wrmsrl(HV_X64_MSR_SINT0 + nv_hyperv_ctx.intr_src, sint_state.as_uint64);

        /* Set the scontrol register (if not already set) to allow message
         * queuing and event flag  notifications to be posted to its SynIC
         */
        rdmsrl(HV_X64_MSR_SCONTROL, sctrl.as_uint64);

        if (sctrl.enable != 1)
        {
            sctrl.enable = 1;
            wrmsrl(HV_X64_MSR_SCONTROL, sctrl.as_uint64);
        }

        nv_hyperv_ctx.synic_initialized = NV_TRUE;
    }

exit:
    put_cpu();
}

/*
 * nv_hyperv_synic_cleanup - Cleanup routine for nv_hyperv_synic_init
 *
 * Arguments:
 * pData - Pointer to the buffer containing any args
 *
 * Return Values:
 * void
 */
static void nv_hyperv_synic_cleanup(void *data)
{
    NvU32 cpu = get_cpu();

    if (cpu == CPU_ID)
    {
        /* Mask the interrupt source only if we were using it */
        if (nv_hyperv_ctx.synic_initialized)
        {
            union nv_hyperv_synic_sint sint_state;

            rdmsrl(HV_X64_MSR_SINT0 + nv_hyperv_ctx.intr_src, sint_state.as_uint64);
            sint_state.polling = false;
            sint_state.masked = true;
            wrmsrl(HV_X64_MSR_SINT0 + nv_hyperv_ctx.intr_src, sint_state.as_uint64);
            nv_hyperv_ctx.synic_message_page = NULL;
            nv_hyperv_ctx.synic_initialized = false;
        }
    }

    put_cpu();
}

/*
 * nv_vmbus_sendpacket_multi_pagebuffer - Send a multi-page buffer
 * using a GPADL Direct packet type.
 *
 * Arguments:
 * pagebuffers - Pointer to the page buffer
 * pagecount   - Number of pages
 * buffer      - User defined buffer
 * bufferlen   - Length of user defined buffer
 * requestid   - Request ID of the message
 *
 * Return Values:
 * NV_ERR_BUFFER_TOO_SMALL  - Not enough room to write into the ringbuffer
 * NV_OK                    - Success
 */
NV_STATUS nv_vmbus_sendpacket_multi_pagebuffer(NvU32 request_id, NvU32 pagecount, NvU64 *pPfns,
                                               void *buffer, NvU32 bufferlen)
{
    NV_STATUS status = NV_OK;
    nv_hyperv_channel_packet_mpb *desc;
    NvU32 descsize, packetlen, packetlen_aligned, i;
    struct kvec bufferlist[NUM_SENDPAGEBUFFER_ELEMENTS];
    NvU64 aligned_data = 0;

    descsize = sizeof(nv_hyperv_channel_packet_mpb) +
               (pagecount * sizeof(NvU64));

    NV_KMALLOC(desc, descsize);
    if (desc == NULL)
    {
        return NV_ERR_NO_MEMORY;
    }

    packetlen = descsize + bufferlen;
    packetlen_aligned = ALIGN(packetlen, sizeof(NvU64));

    /* Setup the descriptor */
    desc->type = VM_PKT_DATA_USING_GPA_DIRECT;
    desc->flags = VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED;
    desc->dataoffset8 = descsize >> 3; /* in 8-bytes granularity */
    desc->length8 = (NvU16)(packetlen_aligned >> 3);
    desc->transactionid = request_id;
    desc->reserved = 0;
    desc->rangecount = 1;
    desc->range.len = PAGE_SIZE * pagecount;
    desc->range.offset = 0;

    for (i = 0; i < pagecount; i++)
    {
        desc->range.pfn_array[i] = pPfns[i];
    }

    bufferlist[0].iov_base = desc;
    bufferlist[0].iov_len = descsize;
    bufferlist[1].iov_base = buffer;
    bufferlist[1].iov_len = bufferlen;
    bufferlist[2].iov_base = &aligned_data;
    bufferlist[2].iov_len = (packetlen_aligned - packetlen);

    status = nv_hyperv_ringbuffer_write(bufferlist, NUM_SENDPAGEBUFFER_ELEMENTS);

    if (desc)
    {
        NV_KFREE(desc, descsize);
    }

    return status;
}

/*
 * nv_vmbus_setup - Do the required setup for VMBUS client
 * - Setup Hypercall page
 * - Setup post message page
 * - Unmask the interrupt source which we will be using (SINT)
 * - Setup Message and Event pages
 * - Enable polling for our SINT
 *
 * Arguments:
 * None
 *
 * Return Value:
 * NV_ERR_NOT_SUPPORTED    - Error while accessing hypercall page
 * NV_ERR_NO_MEMORY        - Unable to allocate post msg page
 * NV_ERR_INVALID_ARGUMENT - Invalid SINT passed in module param
 * NV_ERR_BUSY_RETRY       - SINT is already being used by some other VMBUS client
 * NV_ERR_GENERIC          - Error in setting the callbacks for CPU
 * NV_OK                   - Successful setup
 *
 */
NV_STATUS nv_vmbus_setup(NvU32 override_sint)
{
    NV_STATUS status = NV_OK;
    union nv_hyperv_x64_msr_hypercall_contents hypercall_msr;
    struct page *page = NULL;
    int num_pages = 0;

    /* Use the hypercall page setup by VMBus-P:
     * The physical offset of hypercall page is saved to the
     * HV_X64_MSR_HYPERCALL location. As this page is vmalloc'ed
     * by VMBUS-P, we need to vmap it before we can use it
     */
    rdmsrl(HV_X64_MSR_HYPERCALL, hypercall_msr.as_uint64);
    page = pfn_to_page(hypercall_msr.guest_physical_address);
    num_pages = 1;
    nv_hyperv_ctx.nv_hypercall_pg = vmap(&page, num_pages, VM_MAP, PAGE_KERNEL_RX);
    if (!nv_hyperv_ctx.nv_hypercall_pg)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: Error while accessing hypercall page\n");
        return NV_ERR_NOT_SUPPORTED;
    }

    /* Set up the post message page used for guest -> host communication */
    nv_hyperv_ctx.post_msg_page = (void *)get_zeroed_page(GFP_ATOMIC);
    if (nv_hyperv_ctx.post_msg_page == NULL)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: Unable to allocate post msg page\n");
        return NV_ERR_NO_MEMORY;
    }

    /* Check if the user has passed SINT# to override SINT3
     * This functionality exists so that if the SINT3 is not available
     * due to any reason, we have a way to workaround the issue.
     * If no valid SINT is provided in module param, we will be using SINT3
     * by default
     */
    if (override_sint != 0)
    {
        /* Check if the SINT is a valid one */
        if ((override_sint > NV_VMBUS_MESSAGE_SINT) &&
            (override_sint < NV_INTERRUPT_SOURCE_MAX))
        {
            nv_hyperv_ctx.intr_src = override_sint;
        }
        else
        {
            nv_printf(NV_DBG_ERRORS,
                      "NVRM: Invalid SINT (%d) provided! Valid Range: 3..15\n",
                      override_sint);
            return NV_ERR_INVALID_ARGUMENT;
        }
    }

    /* We will be using CPU#0 for event/message polling.
     * Setup the event/message pages and SINT for CPU#0
     */
    on_each_cpu(nv_hyperv_synic_init, NULL, 1);

    if (!nv_hyperv_ctx.synic_initialized)
    {
        /* We will be using Interrupt source 3 for all the message/event
         * handling. In case if it is already being used by some other
         * VMBUS client, do not proceed
         */
        nv_printf(NV_DBG_ERRORS,
                  "NVRM: SINT (%d) found busy!\n", nv_hyperv_ctx.intr_src);
        return NV_ERR_BUSY_RETRY;
    }

    status = nv_vmbus_initiate_contact(VERSION_WIN10_V5);
    if (status != NV_OK)
    {
        nv_printf(NV_DBG_ERRORS,
                  "NVRM: Failed to initiate contact with error code: 0x%x", status);
        return status;
    }

    /* When requested via a request offer message, all clients receive the
     * same pool of channel offers. New hot-added channel offers are sent to
     * all active clients in an unspecified order. The first client to open
     * a channel offer owns that offer and causes a rescind message for that
     * offer to be sent to all other active clients.
     */
    status = nv_vmbus_request_offers();
    if (status != NV_OK)
    {
        nv_printf(NV_DBG_ERRORS,
                  "NVRM: Failed to request offers with error code: 0x%x", status);
        return status;
    }

    /* Open the offer associated with NV_VMBUS_VGPU_GUID */
    status = nv_vmbus_open();
    if (status != NV_OK)
    {
        nv_printf(NV_DBG_ERRORS,
                  "NVRM: Failed to open VMBus channel with error code: 0x%x\n", status);
        return status;
    }

    return status;
}

/*
 * nv_vmbus_exit - Clean up all the state associated with the channel,
 * and our SINTx
 * - Send CHANNELMSG_CLOSECHANNEL
 * - Teardown GPADL by sending CHANNELMSG_GPADL_TEARDOWN
 * - Cleanup the ring buffers
 * - Unload the channel by sending CHANNELMSG_UNLOAD
 * - Release relid by sending CHANNELMSG_RELID_RELEASED
 * - Free the channel
 * - Clean up SINTx state
 *
 * Arguments:
 * None
 *
 * Return Value:
 * NV_ERR_OPERATING_SYSTEM - nv_hyperv_hypercall did not succeed
 * NV_ERR_NO_MEMORY        - Post message/ hypercall page is NULL
 * NV_OK                   - Success
 *
 */
NV_STATUS nv_vmbus_exit(void)
{
    NV_STATUS status = NV_OK;
    struct vmbus_channel_close_channel *close_channel_msg = NULL;
    struct vmbus_channel_gpadl_teardown gpadl_teardown_msg;
    struct vmbus_channel *channel = nv_hyperv_ctx.guest_channel;

    if ((!nv_hyperv_ctx.synic_initialized) || (channel == NULL))
    {
        /* No need to close channel, teardown GPADL and unload channel
         * This case can happen if there was an issue in vmbus_setup
         */
        goto exit;
    }

    /* Send a closing message */
    close_channel_msg = &channel->close_msg.msg;
    close_channel_msg->header.msgtype = CHANNELMSG_CLOSECHANNEL;
    close_channel_msg->child_relid = channel->offermsg.child_relid;

    status = nv_hyperv_post_msg(close_channel_msg,
                                sizeof(struct vmbus_channel_close_channel));
    if (status)
    {
        nv_printf(NV_DBG_ERRORS,
                  "NVRM: Failed to post close channel message(0x%x)\n",
                  status);
        goto exit;
    }

    nv_hyperv_ctx.offer_received = NV_FALSE;

    /* Tear down the gpadl for the channel's ring buffer */
    if (channel->ringbuffer_gpadlhandle)
    {
        gpadl_teardown_msg.header.msgtype = CHANNELMSG_GPADL_TEARDOWN;
        gpadl_teardown_msg.child_relid = channel->offermsg.child_relid;
        gpadl_teardown_msg.gpadl = nv_hyperv_ctx.guest_channel->ringbuffer_gpadlhandle;

        status = nv_hyperv_post_msg(&gpadl_teardown_msg,
                                    sizeof(struct vmbus_channel_gpadl_teardown));
        if (status)
        {
            nv_printf(NV_DBG_ERRORS,
                      "NVRM: Failed to post GPADL teardown message(0x%x)\n",
                      status);
            goto exit;
        }

        status = nv_vmbus_wait_for_message(CHANNELMSG_GPADL_TORNDOWN, NULL);
        if (status)
        {
            nv_printf(NV_DBG_ERRORS,
                      "NVRM: Failed to recieve GPADL torndown response(0x%x)\n",
                      status);
            goto exit;
        }
    }

    /* Cleanup the ring buffers for this channel */
    nv_hyperv_unmap_ring_buffer(&(channel->outbound));
    nv_hyperv_unmap_ring_buffer(&(channel->inbound));

#ifdef NV_VMBUS_CHANNEL_HAS_RING_BUFFER_PAGE
    __free_pages(channel->ringbuffer_page,
                get_order(channel->ringbuffer_pagecount << PAGE_SHIFT));
#else
    free_pages((unsigned long)channel->ringbuffer_pages,
                get_order(channel->ringbuffer_pagecount * PAGE_SIZE));
#endif

exit:
    /* Free the channel */
    if (nv_hyperv_ctx.guest_channel)
    {
        NV_KFREE(nv_hyperv_ctx.guest_channel,
                 sizeof(*nv_hyperv_ctx.guest_channel));
        nv_hyperv_ctx.guest_channel = NULL;
    }

    /* Freeing post message page */
    if (nv_hyperv_ctx.post_msg_page)
    {
        free_page((unsigned long)nv_hyperv_ctx.post_msg_page);
        nv_hyperv_ctx.post_msg_page = NULL;
    }

    /* Cleanup the interrupt source state */
    on_each_cpu(nv_hyperv_synic_cleanup, NULL, 1);

    return status;
}

NV_STATUS os_call_nv_vmbus(NvU32 vmbus_cmd, void *input)
{
    NV_STATUS status = NV_OK;

    switch(vmbus_cmd)
    {
        case VMBUS_CMD_TYPE_SETUP:
        {
            vmbus_setup_cmd_params *setup_info = NULL;
            if ((input == NULL) ||
               (((vmbus_setup_cmd_params *)input)->nv_guid == NULL))
            {
                return NV_ERR_INVALID_ARGUMENT;
            }

            setup_info = (vmbus_setup_cmd_params *)input;
            nv_guid = *((uuid_le *)(setup_info->nv_guid));

            status = nv_vmbus_setup(setup_info->override_sint);
            break;
        }
        case VMBUS_CMD_TYPE_SENDPACKET:
        {
            vmbus_send_packet_cmd_params *info = NULL;

            if (input == NULL)
            {
                return NV_ERR_INVALID_ARGUMENT;
            }

            info = (vmbus_send_packet_cmd_params *)input;

            status = nv_vmbus_sendpacket_multi_pagebuffer(info->request_id, info->page_count,
                                                          info->pPfns, info->buffer,
                                                          info->bufferlen);
            break;
        }
        case VMBUS_CMD_TYPE_CLEANUP:
        {
            status = nv_vmbus_exit();
            break;
        }
        default:
            /* Error */
            return NV_ERR_NOT_SUPPORTED;
    }

    return status;
}
#endif /*NV_VGPU_HYPERV_BUILD && NV_GRID_BUILD */
