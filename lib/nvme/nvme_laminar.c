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

#include "laminar.h"

#define NVME_LAMINAR_DEFAULT_POLL_BATCH_SIZE  32

enum nvme_laminar_qpair_state {
  NVME_LAMINAR_QPAIR_STATE_INVALID = 0,
  NVME_LAMINAR_QPAIR_STATE_INITIALIZING = 1,
  NVME_LAMINAR_QPAIR_STATE_FABRIC_CONNECT_SEND = 2,
  NVME_LAMINAR_QPAIR_STATE_FABRIC_CONNECT_POLL = 3,
  NVME_LAMINAR_QPAIR_STATE_AUTHENTICATING = 4,
  NVME_LAMINAR_QPAIR_STATE_RUNNING = 5,
  NVME_LAMINAR_QPAIR_STATE_EXITING = 6,
  NVME_LAMINAR_QPAIR_STATE_EXITED = 7,
};

/* NVMe Laminar transport extensions for spdk_nvme_ctrlr */
struct nvme_laminar_ctx {
  struct laminar_context *ctx;
  struct laminar_event   *ev_buffer;
  uint32_t n_events;
};

struct nvme_laminar_ctrlr {
  struct spdk_nvme_ctrlr  ctrlr;
  struct nvme_laminar_ctx *ctx_group; /*> For pending adminq connections. */

  TAILQ_HEAD(, nvme_laminar_qpair) connecting_qpairs;
};

struct nvme_laminar_poll_group {
  struct spdk_nvme_transport_poll_group group;
  struct nvme_laminar_ctx *ctx_group;
  uint32_t completions_per_qpair;
  int64_t num_completions;

  TAILQ_HEAD(, nvme_laminar_qpair) needs_poll;
  TAILQ_HEAD(, nvme_laminar_qpair) connecting_qpairs;
  TAILQ_HEAD(, nvme_laminar_qpair) active_qpairs;
  struct spdk_nvme_tcp_stat stats;
};

/* NVMe Laminar qpair extensions for spdk_nvme_qpair */
struct nvme_laminar_qpair {
  struct spdk_nvme_qpair  qpair;
  struct laminar_connection *conn;

  TAILQ_HEAD(, nvme_tcp_req)    free_reqs;
  TAILQ_HEAD(, nvme_tcp_req)    outstanding_reqs;

  TAILQ_HEAD(, nvme_tcp_pdu)		send_queue;
  struct nvme_tcp_pdu			*recv_pdu;
  struct nvme_tcp_pdu			*send_pdu; /* only for error pdu and init pdu */
  struct nvme_tcp_pdu			*send_pdus; /* Used by tcp_reqs */
  struct nvme_tcp_req			*tcp_reqs;
  uint16_t num_entries;
  bool  in_connect_poll;

  enum nvme_laminar_qpair_state		state;
  TAILQ_ENTRY(nvme_rdma_qpair)    link_active;
  TAILQ_ENTRY(nvme_laminar_qpair) link_connecting;
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

static struct nvme_laminar_ctx*
nvme_laminar_ctx_create(uint32_t poll_batch_size, void *opaque)
{
  struct nvme_laminar_ctx *context;

  context = calloc(1, sizeof(*context));
  if (!context) {
    return NULL;
  }

  context->n_events = poll_batch_size;
  context->ev_buffer = calloc(poll_batch_size, sizeof(*context->ev_buffer));
  if (!context->ev_buffer) {
    goto destroy_ctx;
  }

  if (laminar_context_create(&context->ctx, (uint64_t) opaque) != 0) {
    goto destroy_ev_buf;
  }

  return context;

destroy_ev_buf:
  free(context->ev_buffer);
destroy_ctx:
  free(context);
  return NULL;
}

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

static inline struct nvme_laminar_poll_group *
nvme_laminar_poll_group(struct spdk_nvme_transport_poll_group *group)
{
  return SPDK_CONTAINEROF(group, struct nvme_laminar_poll_group, group);
}

static struct nvme_tcp_req *
nvme_laminar_req_get(struct nvme_laminar_qpair *lqpair)
{
	struct nvme_tcp_req *tcp_req;

	tcp_req = TAILQ_FIRST(&lqpair->free_reqs);
	if (!tcp_req) {
		return NULL;
	}

	assert(tcp_req->state == NVME_TCP_REQ_FREE);
	tcp_req->state = NVME_TCP_REQ_ACTIVE;
	TAILQ_REMOVE(&lqpair->free_reqs, tcp_req, link);
	tcp_req->datao = 0;
	tcp_req->expected_datao = 0;
	tcp_req->req = NULL;
	tcp_req->in_capsule_data = false;
	tcp_req->r2tl_remain = 0;
	tcp_req->r2tl_remain_next = 0;
	tcp_req->active_r2ts = 0;
	tcp_req->iovcnt = 0;
	tcp_req->ordering.raw = 0;
	memset(tcp_req->pdu, 0, sizeof(struct nvme_tcp_pdu));
	memset(&tcp_req->rsp, 0, sizeof(struct spdk_nvme_cpl));

	return tcp_req;
}

static void
nvme_laminar_req_put(struct nvme_laminar_qpair *lqpair, struct nvme_tcp_req *tcp_req)
{
	assert(tcp_req->state != NVME_TCP_REQ_FREE);
	tcp_req->state = NVME_TCP_REQ_FREE;
	TAILQ_INSERT_HEAD(&lqpair->free_reqs, tcp_req, link);
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
  struct sockaddr_storage dst_addr;
  struct nvme_laminar_ctrlr *lctrlr;
  struct nvme_laminar_qpair *lqpair;
  struct nvme_laminar_poll_group *lgroup;
  int rc;
  int family;
  long int port;
  struct in_addr addr;

  lqpair = nvme_laminar_qpair(qpair);
  lctrlr = nvme_laminar_ctrlr(ctrlr);
  lgroup = (qpair->poll_group ? nvme_laminar_poll_group(qpair->poll_group) : NULL);

  switch (ctrlr->trid.adrfam) {
  case SPDK_NVMF_ADRFAM_IPV4:
    family = AF_INET;
    break;
  case SPDK_NVMF_ADRFAM_IPV6:
  default:
    SPDK_ERRLOG("Unhandled ADRFAM %d\n", ctrlr->trid.adrfam);
    rc = -1;
    return rc;
  }

  SPDK_DEBUGLOG(nvme, "adrfam %d ai_family %d\n", ctrlr->trid.adrfam, family);

  memset(&dst_addr, 0, sizeof(dst_addr));

  SPDK_DEBUGLOG(nvme, "trsvcid is %s\n", ctrlr->trid.trsvcid);
  rc = nvme_parse_addr(&dst_addr, family, ctrlr->trid.traddr, ctrlr->trid.trsvcid, &port);
  if (rc != 0) {
    SPDK_ERRLOG("dst_addr nvme_parse_addr() failed\n");
    return rc;
  }

  if (ctrlr->opts.src_addr[0] || ctrlr->opts.src_svcid[0]) {
    SPDK_ERRLOG("src_addr unsupported\n");
    rc = -1;
    return rc;
  }

  if (inet_aton(ctrlr->trid.traddr, &addr) == 0) {
    SPDK_ERRLOG("traddr (%s) parse failed\n", ctrlr->trid.traddr);
    rc = -1;
    return rc;
  }
  port = htons(port);

  if (lgroup != NULL) {
    if (laminar_connection_open(lgroup->ctx_group->ctx,
                                &lqpair->conn, addr.s_addr, port,
                                (uint64_t) lqpair) != 0) {
      SPDK_ERRLOG("laminar_connection_open() failed.");
      rc = -1;
      return rc;
    }
    TAILQ_INSERT_TAIL(&lgroup->connecting_qpairs, lqpair, link_connecting);
  }
  else {
    if (laminar_connection_open(lctrlr->ctx_group->ctx,
                                &lqpair->conn, addr.s_addr, port,
                                (uint64_t) lqpair) != 0) {
      SPDK_ERRLOG("laminar_connection_open() failed.");
      rc = -1;
      return rc;
    }
    TAILQ_INSERT_TAIL(&lctrlr->connecting_qpairs, lqpair, link_connecting);
  }

  lqpair->state = NVME_LAMINAR_QPAIR_STATE_INITIALIZING;
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
    if (laminar_init() != 0) {
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
  if ((lctrlr->ctx_group = nvme_laminar_ctx_create(NVME_LAMINAR_DEFAULT_POLL_BATCH_SIZE, (void *) lctrlr)) == NULL) {
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

  /* FIXME! */
  lctrlr->ctrlr.numa.id_valid = 0;
  lctrlr->ctrlr.numa.id = SPDK_ENV_NUMA_ID_ANY;

  TAILQ_INIT(&lctrlr->connecting_qpairs);

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

static void
dummy_disconnected_qpair_cb(struct spdk_nvme_qpair *qpair, void *poll_group_ctx)
{
  /* TODO: What do we do here! */
  assert(false);
}

static int 
nvme_laminar_ctrlr_poll(struct nvme_laminar_ctrlr *lctrlr)
{
  struct nvme_laminar_ctx *lctx;
  struct nvme_laminar_qpair *lqpair;
  struct laminar_event *ev;
  int ret;
  int count;
  int i;
  
  lctx = lctrlr->ctx_group;
  ret = laminar_context_poll(lctx->ctx, lctx->n_events, lctx->ev_buffer, &count);
  if (ret < 0 && ret != -EAGAIN) {
    SPDK_ERRLOG("Fail in laminar ctrlr socket group poll\n");
    return ret;
  }

  for (i = 0; i < count; i++) {
    ev = &lctx->ev_buffer[i];

    switch(ev->type) {
    case LAMINAR_EV_CONN_OPEN:
      if (ev->return_code != 0) {
        SPDK_ERRLOG("Laminar connect error %d\n", ev->return_code);
        /* TODO: How to gracefully handle this? */
        assert(false);
        return -ENOTCONN;
      }

      /* TODO: Handle connection open! */
      lqpair = (struct nvme_laminar_qpair *) laminar_connection_opaque(ev->conn_open.conn);
      assert(lqpair->state == NVME_LAMINAR_QPAIR_STATE_INITIALIZING);
      lqpair->state = NVME_LAMINAR_QPAIR_STATE_FABRIC_CONNECT_SEND;
      break;
    default:
      SPDK_ERRLOG("invalid event: %d on ctrlr poll group\n", ev->type);
      break;
    }
  }

  return ret;
}

static int
nvme_laminar_process_event_poll(struct nvme_laminar_qpair *lqpair)
{
  int rc = nvme_laminar_ctrlr_poll(nvme_laminar_ctrlr(lqpair->qpair.ctrlr));

  /* TODO: Do something here? */
  return rc;
}

static int
nvme_laminar_ctrlr_connect_qpair_poll(struct spdk_nvme_ctrlr *ctrlr,
           struct spdk_nvme_qpair *qpair)
{
  struct nvme_laminar_qpair *lqpair = nvme_laminar_qpair(qpair);
  struct nvme_laminar_ctrlr *lctrlr = nvme_laminar_ctrlr(qpair->ctrlr);
  int rc = 0;

  if (lqpair->in_connect_poll) {
    return -EAGAIN;
  }

  lqpair->in_connect_poll = true;

  switch (lqpair->state) {
  case NVME_LAMINAR_QPAIR_STATE_INVALID:
    rc = -EAGAIN;
    break;
  
  case NVME_LAMINAR_QPAIR_STATE_INITIALIZING:
  case NVME_LAMINAR_QPAIR_STATE_EXITING:
		if (!nvme_qpair_is_admin_queue(qpair)) {
			nvme_ctrlr_lock(ctrlr);
		}

		rc = nvme_laminar_process_event_poll(lqpair);

		if (!nvme_qpair_is_admin_queue(qpair)) {
			nvme_ctrlr_unlock(ctrlr);
		}

		if (rc == 0) {
			rc = -EAGAIN;
		}
    break;

  case NVME_LAMINAR_QPAIR_STATE_FABRIC_CONNECT_SEND:
		rc = nvme_fabric_qpair_connect_async(qpair, lqpair->num_entries + 1);
		if (rc == 0) {
			lqpair->state = NVME_LAMINAR_QPAIR_STATE_FABRIC_CONNECT_POLL;
			rc = -EAGAIN;
		} else {
			SPDK_ERRLOG("Failed to send an NVMe-oF Fabric CONNECT command\n");
		}
		break;

	case NVME_LAMINAR_QPAIR_STATE_FABRIC_CONNECT_POLL:
		rc = nvme_fabric_qpair_connect_poll(qpair);
		if (rc == 0) {
			if (nvme_fabric_qpair_auth_required(qpair)) {
        assert(false);
			} else {
				lqpair->state = NVME_LAMINAR_QPAIR_STATE_RUNNING;
				nvme_qpair_set_state(qpair, NVME_QPAIR_CONNECTED);
			}
		} else if (rc != -EAGAIN) {
			SPDK_ERRLOG("Failed to poll NVMe-oF Fabric CONNECT command\n");
		}
		break;
	case NVME_LAMINAR_QPAIR_STATE_RUNNING:
		rc = 0;
		break;
	default:
		assert(false);
		rc = -EINVAL;
		break;
  }

  lqpair->in_connect_poll = false;
  return rc;
}

static int
nvme_laminar_qpair_process_completions(struct spdk_nvme_qpair *qpair, uint32_t max_completions)
{
  struct nvme_laminar_qpair *lqpair = nvme_laminar_qpair(qpair);
  struct nvme_laminar_ctrlr *lctrlr = nvme_laminar_ctrlr(qpair->ctrlr);
  int rc = 0;

  /*
   * This is used during the connection phase. It's possible that we are still reaping error completions
   * from other qpairs so we need to call the poll group function. Also, it's more correct since the cq
   * is shared.
   */
  /*
   * Used during the connection phase. If already associated with a poll_group, use
   * the appropriate laminar_context to poll.
   */
  if (qpair->poll_group != NULL) {
    return spdk_nvme_poll_group_process_completions(qpair->poll_group->group, max_completions,
        dummy_disconnected_qpair_cb);
  }

  if (max_completions == 0) {
    max_completions = spdk_max(lqpair->num_entries, 1);
  } else {
    max_completions = spdk_min(max_completions, lqpair->num_entries);
  }

  switch (nvme_qpair_get_state(qpair)) {
  case NVME_QPAIR_CONNECTING:
    rc = nvme_laminar_ctrlr_connect_qpair_poll(qpair->ctrlr, qpair);
    if (rc == 0) {
      /* Once the connection is completed, we can submit queued requests */
      nvme_qpair_resubmit_requests(qpair, lqpair->num_entries);
    } else if (rc != -EAGAIN) {
      SPDK_ERRLOG("Failed to connect lqpair=%p\n", lqpair);
      goto failed;
    } else if (lqpair->state <= NVME_LAMINAR_QPAIR_STATE_INITIALIZING) {
      return 0;
    }
    break;

  default:
    /* TODO: */
    assert(false);
    break;
  }

  return 0;

failed:
  assert(false);
  return 0;
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

  .qpair_process_completions = nvme_laminar_qpair_process_completions,
};

SPDK_NVME_TRANSPORT_REGISTER(laminar, &laminar_ops);