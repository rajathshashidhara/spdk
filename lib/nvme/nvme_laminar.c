/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2018 Intel Corporation. All rights reserved.
 *   Copyright (c) 2020 Mellanox Technologies LTD. All rights reserved.
 *   Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

/*
 * NVMe/Laminar-TCP transport
 */

#include "nvme_internal.h"

#include "spdk/endian.h"
#include "spdk/likely.h"
#include "spdk/string.h"
#include "spdk/stdinc.h"
#include "spdk/crc32.h"
#include "spdk/assert.h"
#include "spdk/trace.h"
#include "spdk/util.h"
#include "spdk/nvmf.h"
#include "spdk/dma.h"

#include "spdk_internal/nvme_tcp.h"

#include "switchtoe.h"

/* NVMe Laminar transport extensions for spdk_nvme_ctrlr */
struct nvme_laminar_ctrlr {
    struct spdk_nvme_ctrlr  ctrlr;
    struct switchtoe_context *sock_group;   /*> For pending adminq connections. */
};

struct nvme_laminar_poll_group {
	struct spdk_nvme_transport_poll_group group;
    struct switchtoe_context *sock_group;
	uint32_t completions_per_qpair;
	int64_t num_completions;

	TAILQ_HEAD(, nvme_laminar_qpair) needs_poll;
	struct spdk_nvme_tcp_stat stats;
};

/* NVMe Laminar qpair extensions for spdk_nvme_qpair */
struct nvme_laminar_qpair {
    struct spdk_nvme_qpair  qpair;
    struct switchtoe_connection *sock;

    TAILQ_HEAD(, nvme_tcp_req)		free_reqs;
	TAILQ_HEAD(, nvme_tcp_req)		outstanding_reqs;

	TAILQ_HEAD(, nvme_tcp_pdu)		send_queue;
	struct nvme_tcp_pdu			*recv_pdu;
	struct nvme_tcp_pdu			*send_pdu; /* only for error pdu and init pdu */
    struct nvme_tcp_pdu			*send_pdus; /* Used by tcp_reqs */
    struct nvme_tcp_req			*tcp_reqs;
    uint16_t num_entries;
};

enum nvme_tcp_req_state {
	NVME_TCP_REQ_FREE,
	NVME_TCP_REQ_ACTIVE,
	NVME_TCP_REQ_ACTIVE_R2T,
};

struct nvme_tcp_req {
	struct nvme_request			*req;
	enum nvme_tcp_req_state			state;
	uint16_t				cid;
	uint16_t				ttag;
	uint32_t				datao;
	uint32_t				expected_datao;
	uint32_t				r2tl_remain;
	uint32_t				active_r2ts;
	/* Used to hold a value received from subsequent R2T while we are still
	 * waiting for H2C complete */
	uint16_t				ttag_r2t_next;
	bool					in_capsule_data;
	/* It is used to track whether the req can be safely freed */
	union {
		uint8_t raw;
		struct {
			/* The last send operation completed - kernel released send buffer */
			uint8_t				send_ack : 1;
			/* Data transfer completed - target send resp or last data bit */
			uint8_t				data_recv : 1;
			/* tcp_req is waiting for completion of the previous send operation (buffer reclaim notification
			 * from kernel) to send H2C */
			uint8_t				h2c_send_waiting_ack : 1;
			/* tcp_req received subsequent r2t while it is still waiting for send_ack.
			 * Rare case, actual when dealing with target that can send several R2T requests.
			 * SPDK TCP target sends 1 R2T for the whole data buffer */
			uint8_t				r2t_waiting_h2c_complete : 1;
			/* Accel operation is in progress */
			uint8_t				in_progress_accel : 1;
			uint8_t				domain_in_use: 1;
			uint8_t				reserved : 2;
		} bits;
	} ordering;
	struct nvme_tcp_pdu			*pdu;
	struct iovec				iov[NVME_TCP_MAX_SGL_DESCRIPTORS];
	uint32_t				iovcnt;
	/* Used to hold a value received from subsequent R2T while we are still
	 * waiting for H2C ack */
	uint32_t				r2tl_remain_next;
	struct nvme_laminar_qpair		*lqpair;
	TAILQ_ENTRY(nvme_tcp_req)		link;
	struct spdk_nvme_cpl			rsp;
	uint8_t					rsvd1[32];
};
SPDK_STATIC_ASSERT(sizeof(struct nvme_tcp_req) % SPDK_CACHE_LINE_SIZE == 0, "unaligned size");

static inline struct nvme_laminar_qpair *
nvme_laminar_qpair(struct spdk_nvme_qpair *qpair)
{
	assert(qpair->trtype == SPDK_NVME_TRANSPORT_LAMINAR);
	return SPDK_CONTAINEROF(qpair, struct nvme_laminar_qpair, qpair);
}

static inline struct nvme_laminar_ctrlr *
nvme_laminar_ctrlr(struct spdk_nvme_ctrlr *ctrlr)
{
	assert(ctrlr->trid.trtype == SPDK_NVME_TRANSPORT_LAMINAR);
	return SPDK_CONTAINEROF(ctrlr, struct nvme_laminar_ctrlr, ctrlr);
}

static void
nvme_laminar_free_reqs(struct nvme_laminar_qpair *lqpair)
{
	free(lqpair->tcp_reqs);
	lqpair->tcp_reqs = NULL;

	spdk_free(lqpair->send_pdus);
	lqpair->send_pdus = NULL;
}

static int
nvme_laminar_alloc_reqs(struct nvme_laminar_qpair *lqpair)
{
    uint16_t i;
    struct nvme_tcp_req *tcp_req;

	lqpair->tcp_reqs = aligned_alloc(SPDK_CACHE_LINE_SIZE,
        lqpair->num_entries * sizeof(*tcp_req));
    if (lqpair->tcp_reqs == NULL) {
        SPDK_ERRLOG("Failed to allocate tcp_reqs on lqpair=%p\n", lqpair);
        goto fail;
    }

    /* Add additional 2 member for the send_pdu, recv_pdu owned by the lqpair */
	lqpair->send_pdus = spdk_zmalloc((lqpair->num_entries + 2) * sizeof(struct nvme_tcp_pdu),
                            0x1000, NULL,
                            SPDK_ENV_NUMA_ID_ANY, SPDK_MALLOC_DMA);

    if (lqpair->send_pdus == NULL) {
        SPDK_ERRLOG("Failed to allocate send_pdus on lqpair=%p\n", lqpair);
        goto fail;
    }

	memset(lqpair->tcp_reqs, 0, lqpair->num_entries * sizeof(*tcp_req));
	TAILQ_INIT(&lqpair->send_queue);
	TAILQ_INIT(&lqpair->free_reqs);
	TAILQ_INIT(&lqpair->outstanding_reqs);
	lqpair->qpair.queue_depth = 0;
	for (i = 0; i < lqpair->num_entries; i++) {
		tcp_req = &lqpair->tcp_reqs[i];
		tcp_req->cid = i;
		tcp_req->lqpair = lqpair;
		tcp_req->pdu = &lqpair->send_pdus[i];
		TAILQ_INSERT_TAIL(&lqpair->free_reqs, tcp_req, link);
	}

	lqpair->send_pdu = &lqpair->send_pdus[i];
	lqpair->recv_pdu = &lqpair->send_pdus[i + 1];

	return 0;
fail:
    nvme_laminar_free_reqs(lqpair);
    return -ENOMEM;
}

static void
nvme_laminar_qpair_abort_reqs(struct spdk_nvme_qpair *qpair, uint32_t dnr)
{
    /* TODO: Not yet implemented. */
}

static int
nvme_laminar_ctrlr_delete_io_qpair(struct spdk_nvme_ctrlr *ctrlr, struct spdk_nvme_qpair *qpair)
{
    /* TODO: Not yet implemented. */
    struct nvme_laminar_qpair *lqpair = nvme_laminar_qpair(qpair);

    assert(qpair != NULL);
    nvme_laminar_qpair_abort_reqs(qpair, qpair->abort_dnr);
    assert(TAILQ_EMPTY(&lqpair->outstanding_reqs));

    nvme_qpair_deinit(qpair);
    nvme_laminar_free_reqs(lqpair);
    free(lqpair);

    return 0;
}

static int
nvme_laminar_ctrlr_enable(struct spdk_nvme_ctrlr *ctrlr)
{
	return 0;
}

static int
nvme_laminar_ctrlr_destruct(struct spdk_nvme_ctrlr *ctrlr)
{
    struct nvme_laminar_ctrlr *lctrlr = nvme_laminar_ctrlr(ctrlr);

    if (ctrlr->adminq) {
        nvme_laminar_ctrlr_delete_io_qpair(ctrlr, ctrlr->adminq);
    }

    nvme_ctrlr_destruct_finish(ctrlr);

    free(lctrlr);

    return 0;
}

static int
nvme_laminar_ctrlr_connect_qpair(struct spdk_nvme_ctrlr *ctrlr, struct spdk_nvme_qpair *qpair)
{
    int rc = 0;
    struct nvme_laminar_qpair *lqpair;
    struct nvme_laminar_poll_group *lgroup;

    lqpair = nvme_laminar_qpair(qpair);


    return 0;
}

static struct spdk_nvme_qpair *
nvme_laminar_ctrlr_create_qpair(struct spdk_nvme_ctrlr *ctrlr,
                uint16_t qid, uint32_t qsize,
                enum spdk_nvme_qprio qprio,
                uint32_t num_requests, bool async)
{
	struct nvme_laminar_qpair *lqpair;
	struct spdk_nvme_qpair *qpair;
	int rc;

    if (qsize < SPDK_NVME_QUEUE_MIN_ENTRIES) {
		SPDK_ERRLOG("Failed to create qpair with size %u. Minimum queue size is %d.\n",
			    qsize, SPDK_NVME_QUEUE_MIN_ENTRIES);
		return NULL;
	}

	lqpair = calloc(1, sizeof(struct nvme_laminar_qpair));
	if (!lqpair) {
		SPDK_ERRLOG("failed to get create lqpair\n");
		return NULL;
	}

	/* Set num_entries one less than queue size. According to NVMe
	 * and NVMe-oF specs we can not submit queue size requests,
	 * one slot shall always remain empty.
	 */
    lqpair->num_entries = qsize - 1;
    qpair = &lqpair->qpair;
	rc = nvme_qpair_init(qpair, qid, ctrlr, qprio, num_requests, async);
	if (rc != 0) {
		free(lqpair);
		return NULL;
	}

    rc = nvme_laminar_alloc_reqs(lqpair);
    if (rc) {
        nvme_laminar_ctrlr_delete_io_qpair(ctrlr, qpair);
        return NULL;
    }

    /* NOTE: Don't create socket here. */
    return qpair;
}

static struct spdk_nvme_qpair *
nvme_laminar_ctrlr_create_io_qpair(struct spdk_nvme_ctrlr *ctrlr, uint16_t qid,
			        const struct spdk_nvme_io_qpair_opts *opts)
{
	return nvme_laminar_ctrlr_create_qpair(ctrlr, qid, opts->io_queue_size, opts->qprio,
					    opts->io_queue_requests, opts->async_mode);
}

/* We have to use the typedef in the function declaration to appease astyle. */
typedef struct spdk_nvme_ctrlr spdk_nvme_ctrlr_t;

static spdk_nvme_ctrlr_t *
nvme_laminar_ctrlr_construct(const struct spdk_nvme_transport_id *trid,
            const struct spdk_nvme_ctrlr_opts *opts,
            void *devhandle)
{
    struct nvme_laminar_ctrlr *lctrlr;
    static int __init_done = 0;
    int rc;

    /* Init only once. */
    if (__sync_bool_compare_and_swap(&__init_done, 0, 1)) {
        if (switchtoe_init() != 0) {
            SPDK_ERRLOG("could not initialize laminar\n");
            return NULL;
        }
    }

    lctrlr = calloc(1, sizeof(*lctrlr));
    if (lctrlr == NULL) {
		SPDK_ERRLOG("could not allocate ctrlr\n");
		return NULL;        
    }

    lctrlr->ctrlr.opts = *opts;
    lctrlr->ctrlr.trid = *trid;

    /* TODO: What are Laminar's transport options? */
    SPDK_NOTICELOG("handling transport options unimplemented.");

    rc = nvme_ctrlr_construct(&lctrlr->ctrlr);
    if (rc != 0) {
        free(lctrlr);
        return NULL;
    }

    /* Create context before creating qpair. */
    if (switchtoe_context_create(&lctrlr->sock_group, (uintptr_t) lctrlr) != 0) {
        SPDK_ERRLOG("failed to create context\n");
        nvme_laminar_ctrlr_destruct(&lctrlr->ctrlr);
        return NULL;
    }

    lctrlr->ctrlr.adminq = nvme_laminar_ctrlr_create_qpair(&lctrlr->ctrlr, 0,
                lctrlr->ctrlr.opts.admin_queue_size, 0,
                lctrlr->ctrlr.opts.admin_queue_size, true);
    if (!lctrlr->ctrlr.adminq) {
        SPDK_ERRLOG("failed to create admin qpair\n");
        nvme_laminar_ctrlr_destruct(&lctrlr->ctrlr);
        return NULL;
    }

    /* TODO: Set tctrlr->ctrlr.numa.id ? */

	if (nvme_ctrlr_add_process(&lctrlr->ctrlr, 0) != 0) {
		SPDK_ERRLOG("nvme_ctrlr_add_process() failed\n");
		nvme_ctrlr_destruct(&lctrlr->ctrlr);
		return NULL;
	}

    SPDK_DEBUGLOG(nvme, "successfully initialized the nvmf ctrlr\n");
    return &lctrlr->ctrlr;
}

static uint32_t
nvme_laminar_ctrlr_get_max_xfer_size(struct spdk_nvme_ctrlr *ctrlr)
{
	/* Laminar transport doesn't limit maximum IO transfer size. */
	return UINT32_MAX;
}

static uint16_t
nvme_laminar_ctrlr_get_max_sges(struct spdk_nvme_ctrlr *ctrlr)
{
	return NVME_TCP_MAX_SGL_DESCRIPTORS;
}

const struct spdk_nvme_transport_ops laminar_ops = {
    .name = "LAMINAR",
    .type = SPDK_NVME_TRANSPORT_LAMINAR,
    .ctrlr_construct = nvme_laminar_ctrlr_construct,
    .ctrlr_scan = nvme_fabric_ctrlr_scan,
    .ctrlr_destruct = nvme_laminar_ctrlr_destruct,
    .ctrlr_enable = nvme_laminar_ctrlr_enable,

	.ctrlr_set_reg_4 = nvme_fabric_ctrlr_set_reg_4,
	.ctrlr_set_reg_8 = nvme_fabric_ctrlr_set_reg_8,
	.ctrlr_get_reg_4 = nvme_fabric_ctrlr_get_reg_4,
	.ctrlr_get_reg_8 = nvme_fabric_ctrlr_get_reg_8,
	.ctrlr_set_reg_4_async = nvme_fabric_ctrlr_set_reg_4_async,
	.ctrlr_set_reg_8_async = nvme_fabric_ctrlr_set_reg_8_async,
	.ctrlr_get_reg_4_async = nvme_fabric_ctrlr_get_reg_4_async,
	.ctrlr_get_reg_8_async = nvme_fabric_ctrlr_get_reg_8_async,

	.ctrlr_get_max_xfer_size = nvme_laminar_ctrlr_get_max_xfer_size,
    .ctrlr_get_max_sges = nvme_laminar_ctrlr_get_max_sges,

    .ctrlr_create_io_qpair = nvme_laminar_ctrlr_create_io_qpair,
    .ctrlr_delete_io_qpair = nvme_laminar_ctrlr_delete_io_qpair,
    .ctrlr_connect_qpair = nvme_laminar_ctrlr_connect_qpair,
};

SPDK_NVME_TRANSPORT_REGISTER(laminar, &laminar_ops);