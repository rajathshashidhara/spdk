/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2016 Intel Corporation. All rights reserved.
 *   Copyright (c) 2019-2021 Mellanox Technologies LTD. All rights reserved.
 *   Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "spdk/stdinc.h"

#include "spdk/config.h"
#include "spdk/crc32.h"
#include "spdk/endian.h"
#include "spdk/thread.h"
#include "spdk/likely.h"
#include "spdk/log.h"
#include "spdk/nvmf_transport.h"
#include "spdk/string.h"
#include "spdk/trace.h"
#include "spdk/tree.h"
#include "spdk/util.h"

#include "spdk_internal/assert.h"
#include "spdk_internal/nvme_tcp.h"

#include "nvmf_internal.h"
#include "transport.h"

#include "laminar.h"

#define SPDK_NVMF_LAMINAR_DEFAULT_CONTROL_MSG_NUM 32
#define SPDK_NVMF_LAMINAR_DEFAULT_MAX_IO_QUEUE_DEPTH 128
#define SPDK_NVMF_LAMINAR_DEFAULT_MAX_ADMIN_QUEUE_DEPTH 128
#define SPDK_NVMF_LAMINAR_DEFAULT_MAX_QPAIRS_PER_CTRLR 128
#define SPDK_NVMF_LAMINAR_DEFAULT_IN_CAPSULE_DATA_SIZE 8192
#define SPDK_NVMF_LAMINAR_DEFAULT_MAX_IO_SIZE 131072
#define SPDK_NVMF_LAMINAR_DEFAULT_IO_UNIT_SIZE 131072
#define SPDK_NVMF_LAMINAR_DEFAULT_NUM_SHARED_BUFFERS 511
#define SPDK_NVMF_LAMINAR_DEFAULT_BUFFER_CACHE_SIZE UINT32_MAX
#define SPDK_NVMF_LAMINAR_DEFAULT_DIF_INSERT_OR_STRIP false
#define SPDK_NVMF_LAMINAR_DEFAULT_ABORT_TIMEOUT_SEC 1
#define SPDK_NVMF_LAMINAR_DEFAULT_POLL_BATCH_SIZE 32
#define SPDK_NVMF_LAMINAR_ACCEPTOR_BACKLOG 32

const struct spdk_nvmf_transport_ops spdk_nvmf_transport_laminar;

/* spdk nvmf related structure */
struct spdk_laminar_ctx {
  struct laminar_context *ctx;
  struct laminar_event   *ev_buffer;
  uint32_t n_events;
};

/* spdk nvmf related structure */
enum spdk_nvmf_tcp_req_state {

  /* The request is not currently in use */
  TCP_REQUEST_STATE_FREE = 0,

  /* Initial state when request first received */
  TCP_REQUEST_STATE_NEW = 1,

  /* The request is queued until a data buffer is available. */
  TCP_REQUEST_STATE_NEED_BUFFER = 2,

  /* The request has the data buffer available */
  TCP_REQUEST_STATE_HAVE_BUFFER = 3,

  /* The request is waiting for zcopy_start to finish */
  TCP_REQUEST_STATE_AWAITING_ZCOPY_START = 4,

  /* The request has received a zero-copy buffer */
  TCP_REQUEST_STATE_ZCOPY_START_COMPLETED = 5,

  /* The request is currently transferring data from the host to the controller. */
  TCP_REQUEST_STATE_TRANSFERRING_HOST_TO_CONTROLLER = 6,

  /* The request is waiting for the R2T send acknowledgement. */
  TCP_REQUEST_STATE_AWAITING_R2T_ACK = 7,

  /* The request is ready to execute at the block device */
  TCP_REQUEST_STATE_READY_TO_EXECUTE = 8,

  /* The request is currently executing at the block device */
  TCP_REQUEST_STATE_EXECUTING = 9,

  /* The request is waiting for zcopy buffers to be committed */
  TCP_REQUEST_STATE_AWAITING_ZCOPY_COMMIT = 10,

  /* The request finished executing at the block device */
  TCP_REQUEST_STATE_EXECUTED = 11,

  /* The request is ready to send a completion */
  TCP_REQUEST_STATE_READY_TO_COMPLETE = 12,

  /* The request is currently transferring final pdus from the controller to the host. */
  TCP_REQUEST_STATE_TRANSFERRING_CONTROLLER_TO_HOST = 13,

  /* The request is waiting for zcopy buffers to be released (without committing) */
  TCP_REQUEST_STATE_AWAITING_ZCOPY_RELEASE = 14,

  /* The request completed and can be marked free. */
  TCP_REQUEST_STATE_COMPLETED = 15,

  /* Terminator */
  TCP_REQUEST_NUM_STATES,
};

enum nvmf_laminar_qpair_state {
  NVMF_LAMINAR_QPAIR_STATE_INVALID = 0,
  NVMF_LAMINAR_QPAIR_STATE_MOVED = 1,
  NVMF_LAMINAR_QPAIR_STATE_INITIALIZING = 2,
  NVMF_LAMINAR_QPAIR_STATE_RUNNING = 3,
  NVMF_LAMINAR_QPAIR_STATE_EXITING = 4,
  NVMF_LAMINAR_QPAIR_STATE_EXITED = 5,
};

struct spdk_nvmf_tcp_req  {
  struct spdk_nvmf_request		req;
  struct spdk_nvme_cpl			rsp;
  struct spdk_nvme_cmd			cmd;

  /* A PDU that can be used for sending responses. This is
   * not the incoming PDU! */
  struct nvme_tcp_pdu			*pdu;

  /* In-capsule data buffer */
  uint8_t					*buf;

  struct spdk_nvmf_tcp_req		*fused_pair;

  /*
   * The PDU for a request may be used multiple times in serial over
   * the request's lifetime. For example, first to send an R2T, then
   * to send a completion. To catch mistakes where the PDU is used
   * twice at the same time, add a debug flag here for init/fini.
   */
  bool					pdu_in_use;
  bool					has_in_capsule_data;
  bool					fused_failed;

  /* transfer_tag */
  uint16_t				ttag;

  enum spdk_nvmf_tcp_req_state		state;

  /*
   * h2c_offset is used when we receive the h2c_data PDU.
   */
  uint32_t				h2c_offset;

  STAILQ_ENTRY(spdk_nvmf_tcp_req)		link;
  TAILQ_ENTRY(spdk_nvmf_tcp_req)		state_link;
  STAILQ_ENTRY(spdk_nvmf_tcp_req)		control_msg_link;
};

struct spdk_nvmf_laminar_qpair {
  struct spdk_nvmf_qpair              qpair;
  struct spdk_nvmf_laminar_poll_group	*group;
  struct laminar_connection           *conn;

  enum nvme_tcp_pdu_recv_state        recv_state;
  enum nvmf_laminar_qpair_state       state;

  /* PDU being actively received */
  struct nvme_tcp_pdu                 *pdu_in_progress;

  /* Queues to track the requests in all states */
  TAILQ_HEAD(, spdk_nvmf_tcp_req)   tcp_req_working_queue;
  TAILQ_HEAD(, spdk_nvmf_tcp_req)   tcp_req_free_queue;
  SLIST_HEAD(, nvme_tcp_pdu)        tcp_pdu_free_queue;
  /* Number of working pdus */
  uint32_t				tcp_pdu_working_count;

  /* Number of requests in each state */
  uint32_t				state_cntr[TCP_REQUEST_NUM_STATES];

  uint8_t         cpda;
  bool            host_hdgst_enable;
  bool            host_ddgst_enable;

  /* This is a spare PDU used for sending special management
   * operations. Primarily, this is used for the initial
   * connection response and c2h termination request. */
  struct nvme_tcp_pdu			*mgmt_pdu;

  void                            *bufs;
  struct spdk_nvmf_tcp_req    *reqs;
  struct nvme_tcp_pdu             *pdus;
  uint32_t				resource_count;
  uint32_t				recv_buf_size;

  struct spdk_nvmf_laminar_port       *port;

  /* IP address */
  char          initiator_addr[SPDK_NVMF_TRADDR_MAX_LEN];
  char          target_addr[SPDK_NVMF_TRADDR_MAX_LEN];

  /* IP port */
  uint16_t      initiator_port;
  uint16_t      target_port;

  TAILQ_ENTRY(spdk_nvmf_laminar_qpair) link;
};

struct spdk_nvmf_laminar_poll_group {
  struct spdk_nvmf_transport_poll_group group;
  struct spdk_laminar_ctx *context;

  TAILQ_HEAD(, spdk_nvmf_laminar_qpair)		qpairs;
  TAILQ_ENTRY(spdk_nvmf_laminar_poll_group)	link;
};

struct spdk_nvmf_laminar_port {
  const struct spdk_nvme_transport_id *trid;
  struct laminar_listener *listener;
  struct spdk_nvmf_transport *transport;

  TAILQ_ENTRY(spdk_nvmf_laminar_port)		link;
};

struct laminar_transport_opts {
  uint32_t poll_batch_size;
  uint32_t acceptor_backlog;
  uint16_t control_msg_num;
};

struct spdk_nvmf_laminar_transport {
  struct spdk_nvmf_transport	transport;
  struct laminar_transport_opts laminar_opts;

  struct spdk_nvmf_laminar_poll_group 	*next_pg;

  struct spdk_poller 			   *accept_poller;
  struct spdk_laminar_ctx 	   *listen_context;

  TAILQ_HEAD(, spdk_nvmf_laminar_port) ports;
  TAILQ_HEAD(, spdk_nvmf_laminar_poll_group)	poll_groups;
};

static void
nvmf_laminar_poll_group_destroy(struct spdk_nvmf_transport_poll_group *group);
static bool
nvmf_tcp_req_process(struct spdk_nvmf_laminar_transport *ltransport,
         struct spdk_nvmf_tcp_req *tcp_req);

static int
nvmf_laminar_trsvcid_to_int(const char *trsvcid)
{
  unsigned long long ull;
  char *end = NULL;

  ull = strtoull(trsvcid, &end, 10);
  if (end == NULL || end == trsvcid || *end != '\0') {
    return -1;
  }

  /* Valid TCP/IP port numbers are in [1, 65535] */
  if (ull == 0 || ull > 65535) {
    return -1;
  }

  return (int)ull;
}

/**
 * Canonicalize a listen address trid.
 */
static int
nvmf_laminar_canon_listen_trid(struct spdk_nvme_transport_id *canon_trid,
                    const struct spdk_nvme_transport_id *trid)
{
  int trsvcid_int;

  trsvcid_int = nvmf_laminar_trsvcid_to_int(trid->trsvcid);
  if (trsvcid_int < 0) {
    return -EINVAL;
  }

  memset(canon_trid, 0, sizeof(*canon_trid));
  spdk_nvme_trid_populate_transport(canon_trid, SPDK_NVME_TRANSPORT_LAMINAR);
  canon_trid->adrfam = trid->adrfam;
  snprintf(canon_trid->traddr, sizeof(canon_trid->traddr), "%s", trid->traddr);
  snprintf(canon_trid->trsvcid, sizeof(canon_trid->trsvcid), "%d", trsvcid_int);

  return 0;
}

/**
 * Find an existing listening port.
 */
static struct spdk_nvmf_laminar_port *
nvmf_laminar_find_port(struct spdk_nvmf_laminar_transport *ltransport,
              const struct spdk_nvme_transport_id *trid)
{
  struct spdk_nvme_transport_id canon_trid;
  struct spdk_nvmf_laminar_port *port;

  if (nvmf_laminar_canon_listen_trid(&canon_trid, trid) != 0) {
    return NULL;
  }

  TAILQ_FOREACH(port, &ltransport->ports, link) {
    if (spdk_nvme_transport_id_compare(&canon_trid, port->trid) == 0) {
      return port;
    }
  }

  return NULL;
}

static struct spdk_laminar_ctx*
spdk_laminar_ctx_create(uint32_t poll_batch_size, void *opaque)
{
  struct spdk_laminar_ctx* context;

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

static int
spdk_laminar_ctx_close(struct spdk_laminar_ctx **ctxp)
{
  struct spdk_laminar_ctx *context = *ctxp;
  if (context == NULL) {
    errno = EBADF;
    return -1;
  }

  /* TODO: Laminar does not support context close. */
  if (context->ctx != NULL) {
    laminar_context_destroy(context->ctx);
    context->ctx = NULL;
  }

  free(context->ev_buffer);
  free(context);
  *ctxp = NULL;

  return 0;
}

static void
nvmf_laminar_qpair_set_state(struct spdk_nvmf_laminar_qpair *lqpair,
    enum nvmf_laminar_qpair_state state)
{
  lqpair->state = state;
}

static void
nvmf_laminar_qpair_set_recv_state(struct spdk_nvmf_laminar_qpair *lqpair,
                              enum nvme_tcp_pdu_recv_state state)
{
  if (lqpair->recv_state == state) {
    SPDK_ERRLOG("The recv state of lqpair=%p is same with the state(%d) to be set\n",
          lqpair, state);
    return;
  }

  if (spdk_unlikely(state == NVME_TCP_PDU_RECV_STATE_QUIESCING)) {
    if (lqpair->recv_state == NVME_TCP_PDU_RECV_STATE_AWAIT_PDU_CH && lqpair->pdu_in_progress) {
      SLIST_INSERT_HEAD(&lqpair->tcp_pdu_free_queue, lqpair->pdu_in_progress, slist);
      lqpair->tcp_pdu_working_count--;
    }
  }

  if (spdk_unlikely(state == NVME_TCP_PDU_RECV_STATE_ERROR)) {
    assert(lqpair->tcp_pdu_working_count == 0);
  }

  SPDK_DEBUGLOG(laminar, "lqpair(%p) recv state=%d\n", lqpair, state);
  lqpair->recv_state = state;

}

static inline void
nvmf_tcp_req_set_state(struct spdk_nvmf_tcp_req *tcp_req,
           enum spdk_nvmf_tcp_req_state state)
{
  struct spdk_nvmf_qpair *qpair;
  struct spdk_nvmf_laminar_qpair *lqpair;

  qpair = tcp_req->req.qpair;
  lqpair = SPDK_CONTAINEROF(qpair, struct spdk_nvmf_laminar_qpair, qpair);

  assert(lqpair->state_cntr[tcp_req->state] > 0);
  lqpair->state_cntr[tcp_req->state]--;
  lqpair->state_cntr[state]++;

  tcp_req->state = state;
}

static inline struct nvme_tcp_pdu *
nvmf_tcp_req_pdu_init(struct spdk_nvmf_tcp_req *tcp_req)
{
  assert(tcp_req->pdu_in_use == false);

  memset(tcp_req->pdu, 0, sizeof(*tcp_req->pdu));
  tcp_req->pdu->qpair = SPDK_CONTAINEROF(tcp_req->req.qpair, struct spdk_nvmf_laminar_qpair, qpair);

  return tcp_req->pdu;
}

static struct spdk_nvmf_tcp_req *
nvmf_tcp_req_get(struct spdk_nvmf_laminar_qpair *lqpair)
{
  struct spdk_nvmf_tcp_req *tcp_req;

  tcp_req = TAILQ_FIRST(&lqpair->tcp_req_free_queue);
  if (spdk_unlikely(!tcp_req)) {
    return NULL;
  }

  memset(&tcp_req->rsp, 0, sizeof(tcp_req->rsp));
  tcp_req->h2c_offset = 0;
  tcp_req->has_in_capsule_data = false;

  TAILQ_REMOVE(&lqpair->tcp_req_free_queue, tcp_req, state_link);
  TAILQ_INSERT_TAIL(&lqpair->tcp_req_working_queue, tcp_req, state_link);
  lqpair->qpair.queue_depth++;
  nvmf_tcp_req_set_state(tcp_req, TCP_REQUEST_STATE_NEW);
  return tcp_req;
}

static inline void
nvmf_tcp_req_put(struct spdk_nvmf_laminar_qpair *lqpair, struct spdk_nvmf_tcp_req *tcp_req)
{
  assert(!tcp_req->pdu_in_use);

  TAILQ_REMOVE(&lqpair->tcp_req_working_queue, tcp_req, state_link);
  TAILQ_INSERT_TAIL(&lqpair->tcp_req_free_queue, tcp_req, state_link);
  lqpair->qpair.queue_depth--;
  nvmf_tcp_req_set_state(tcp_req, TCP_REQUEST_STATE_FREE);
}

static void
nvmf_tcp_request_free(void *cb_arg)
{
  struct spdk_nvmf_laminar_transport *ltransport;
  struct spdk_nvmf_tcp_req *tcp_req = cb_arg;

  assert(tcp_req != NULL);

  SPDK_DEBUGLOG(laminar, "tcp_req=%p will be freed\n", tcp_req);

  ltransport = SPDK_CONTAINEROF(tcp_req->req.qpair->transport,
              struct spdk_nvmf_laminar_transport, transport);
  nvmf_tcp_req_set_state(tcp_req, TCP_REQUEST_STATE_COMPLETED);
  nvmf_tcp_req_process(ltransport, tcp_req);
}

static int
nvmf_laminar_accept_poll(void *ctx)
{
  struct spdk_nvmf_transport *transport = ctx;
  struct spdk_nvmf_laminar_transport *ltransport;
  struct spdk_laminar_ctx *lctx;
  struct spdk_nvmf_laminar_port *port;
  struct spdk_nvmf_laminar_qpair *lqpair;
  struct laminar_event *ev;
  struct laminar_listener *lst;
  struct laminar_connection *conn;
  int count;
  int ret;
  int i;
  uint16_t p;
  struct in_addr addr;

  ltransport = SPDK_CONTAINEROF(transport, struct spdk_nvmf_laminar_transport, transport);
  lctx = ltransport->listen_context;

  /* TODO: Poll the context. */
  ret = laminar_context_poll(lctx->ctx, lctx->n_events, lctx->ev_buffer, &count);
  if (ret < 0) {
    SPDK_ERRLOG("Fail in Laminar listen socket group poll\n");
    return SPDK_POLLER_IDLE;
  }

  for (i = 0; i < count; i++) {
    ev = &lctx->ev_buffer[i];
    switch (ev->type) {
    case LAMINAR_EV_LISTEN_OPEN:
      lst = ev->listen_open.listener;
      port = (struct spdk_nvmf_laminar_port *) laminar_listener_opaque(lst);

      if (ev->return_code) {
        SPDK_ERRLOG("laminar_listen_open() failed: %d\n",
            nvmf_laminar_trsvcid_to_int(port->trid->trsvcid));
        free(lst);
        free(port);
        continue;
      }

      /* Success! */
      SPDK_NOTICELOG("*** NVMe/Laminar Target Listening on %s port %s ***\n",
        port->trid->traddr, port->trid->trsvcid);

      TAILQ_INSERT_TAIL(&ltransport->ports, port, link);
      break;

    case LAMINAR_EV_LISTEN_NEWCONN:
      lst = ev->listen_newconn.listener;
      port = (struct spdk_nvmf_laminar_port *) laminar_listener_opaque(lst);

      if (ev->return_code) {
        /* Should not happen. */
        SPDK_ERRLOG("Error on LAMINAR_EV_LISTEN_NEWCONN\n");
        continue;
      }

      lqpair = calloc(1, sizeof(*lqpair));
      if (!lqpair) {
        SPDK_ERRLOG("QPair allocation failed\n");
        continue;
      }

      lqpair->port = port;
      lqpair->qpair.transport = port->transport;
      lqpair->qpair.numa.id_valid = 1;
      lqpair->qpair.numa.id = 0;  /* FIXME */
      if (laminar_listen_accept(lctx->ctx, lst, &lqpair->conn, (uint64_t)lqpair)) {
        SPDK_ERRLOG("laminar_listen_accept failed\n");
        free(lqpair);
        continue;
      }
      break;

    case LAMINAR_EV_LISTEN_ACCEPT:
      conn = ev->listen_accept.conn;
      lqpair = (struct spdk_nvmf_laminar_qpair *) laminar_connection_opaque(conn);
      port = lqpair->port;

      if (ev->return_code) {
        SPDK_ERRLOG("Failed to accept laminar qpair.\n");
        free(conn);
        free(lqpair);
        continue;
      }

      laminar_connection_remoteaddr(conn, &addr.s_addr, &p);
      addr.s_addr = htonl(addr.s_addr);
      strncpy(lqpair->initiator_addr,
        inet_ntoa(addr), sizeof(lqpair->initiator_addr) - 1);
      lqpair->initiator_port = p;
      laminar_connection_localaddr(conn, &addr.s_addr, &p);
      addr.s_addr = htonl(addr.s_addr);
      strncpy(lqpair->target_addr,
        inet_ntoa(addr), sizeof(lqpair->target_addr) - 1);
      lqpair->target_port = p;
      spdk_nvmf_tgt_new_qpair(port->transport->tgt, &lqpair->qpair);
      break;

    default:
      SPDK_ERRLOG("invalid event: %d on listen poll group\n", ev->type);
      break;
    }
  }

  return count != 0 ? SPDK_POLLER_BUSY : SPDK_POLLER_IDLE;
}

static int
nvmf_laminar_qpair_init(struct spdk_nvmf_qpair *qpair)
{
  struct spdk_nvmf_laminar_qpair *lqpair;

  lqpair = SPDK_CONTAINEROF(qpair, struct spdk_nvmf_laminar_qpair, qpair);

  SPDK_DEBUGLOG(laminar, "New Laminar Connection: %p\n", lqpair);

  /* Initialise request state queues of the qpair */
  TAILQ_INIT(&lqpair->tcp_req_free_queue);
  TAILQ_INIT(&lqpair->tcp_req_working_queue);
  SLIST_INIT(&lqpair->tcp_pdu_free_queue);
  lqpair->qpair.queue_depth = 0;

  lqpair->host_hdgst_enable = true;
  lqpair->host_ddgst_enable = false;

  return 0;
}

static void
nvmf_laminar_qpair_write_mgmt_pdu(struct spdk_nvmf_laminar_qpair *lqpair,
            nvme_tcp_qpair_xfer_complete_cb cb_fn,
            void *cb_arg)
{
  int hlen;
  uint32_t crc32c;
  struct nvme_tcp_pdu *pdu = lqpair->mgmt_pdu;
  struct spdk_nvmf_laminar_poll_group	*lgroup = lqpair->group;
  void *buf;
  ssize_t ret;

  assert(pdu->data_len == 0);

  /* TODO: Move this to nvmf_laminar_qpair_write_pdu? */
  hlen = pdu->hdr.common.hlen;

  /* Header Digest */
  if (g_nvme_tcp_hdgst[pdu->hdr.common.pdu_type] && lqpair->host_hdgst_enable) {
    crc32c = nvme_tcp_pdu_calc_header_digest(pdu);
    MAKE_DIGEST_WORD((uint8_t *)pdu->hdr.raw + hlen, crc32c);
    hlen += SPDK_NVME_TCP_DIGEST_LEN;
  }

  /* No data digest! */
  /* TODO: Need nvme_tcp_build_iovs? */
  assert(hlen == pdu->hdr.common.plen);

  /* Allocate TX buffer. */
  if ((ret = laminar_connection_tx_alloc(lqpair->conn, hlen, &buf)) != hlen) {
    SPDK_ERRLOG("%s failed to allocate TX buffer: %ld\n", __func__, ret);
    goto err;
  }

  /* Copy buffer! */
  memcpy(buf, (uint8_t *)&pdu->hdr.raw, hlen);
  if ((ret = laminar_connection_tx_send_range(lgroup->context->ctx, lqpair->conn, buf, hlen)) != 0) {
    SPDK_ERRLOG("%s failed to send TX buffer: %ld\n", __func__, ret);
    goto err;
  }
  
  assert(cb_fn != NULL);
  cb_fn(cb_arg);
  return;

err:
  nvmf_laminar_qpair_set_recv_state(lqpair, NVME_TCP_PDU_RECV_STATE_QUIESCING);
  return;
}

static void
nvmf_laminar_qpair_write_req_pdu(struct spdk_nvmf_laminar_qpair *lqpair,
                            struct spdk_nvmf_tcp_req *tcp_req,
                            nvme_tcp_qpair_xfer_complete_cb cb_fn,
                            void *cb_arg)
{
  int hlen, plen;
  uint32_t crc32c;
  struct nvme_tcp_pdu *pdu = tcp_req->pdu;
  struct spdk_nvmf_laminar_poll_group	*lgroup = lqpair->group;
  void *buf;
  ssize_t ret;

  assert(!tcp_req->pdu_in_use);
  tcp_req->pdu_in_use = true;

  assert(lqpair->pdu_in_progress != pdu);

  hlen = pdu->hdr.common.hlen;
  plen = pdu->hdr.common.plen;

  /* Header Digest */
  if (g_nvme_tcp_hdgst[pdu->hdr.common.pdu_type] && lqpair->host_hdgst_enable) {
    crc32c = nvme_tcp_pdu_calc_header_digest(pdu);
    MAKE_DIGEST_WORD((uint8_t *)pdu->hdr.raw + hlen, crc32c);
    hlen += SPDK_NVME_TCP_DIGEST_LEN;
  }

  /* No data digest! */
  assert(!lqpair->host_ddgst_enable);
  /* TODO: Need nvme_tcp_build_iovs? */
#if 0
  assert(hlen == pdu->hdr.common.plen);
#endif

  /* Allocate TX buffer. */
  if ((ret = laminar_connection_tx_alloc(lqpair->conn, plen, &buf)) != plen) {
    SPDK_ERRLOG("%s failed to allocate TX buffer: %ld\n", __func__, ret);
    goto err;
  }

  /* Copy header! */
  assert(pdu->data_iovcnt <= 1);
  memcpy(buf, (uint8_t *)&pdu->hdr.raw, hlen);
  if (pdu->data_len) {
    memcpy(buf + hlen, pdu->data_iov[0].iov_base, pdu->data_iov[0].iov_len);
  }
  if ((ret = laminar_connection_tx_send_range(lgroup->context->ctx, lqpair->conn, buf, plen)) != 0) {
    SPDK_ERRLOG("%s failed to send TX buffer: %ld\n", __func__, ret);
    goto err;
  }

  /* NOTE: _req_pdu_write_done() */
  assert(tcp_req->pdu_in_use);
  tcp_req->pdu_in_use = false;

  /* If the request is in a completed state, we're waiting for write completion to free it */
  if (spdk_unlikely(tcp_req->state == TCP_REQUEST_STATE_COMPLETED)) {
    nvmf_tcp_request_free(tcp_req);
    return;
  }

  assert(cb_fn != NULL);
  cb_fn(cb_arg);
  return;

err:
  nvmf_laminar_qpair_set_recv_state(lqpair, NVME_TCP_PDU_RECV_STATE_QUIESCING);
  return;
}

static int
nvmf_laminar_qpair_init_mem_resource(struct spdk_nvmf_laminar_qpair *lqpair)
{
  uint32_t i;
  struct spdk_nvmf_transport_opts *opts;
  uint32_t in_capsule_data_size;

  opts = &lqpair->qpair.transport->opts;

  in_capsule_data_size = opts->in_capsule_data_size;
  if (opts->dif_insert_or_strip) {
    in_capsule_data_size = SPDK_BDEV_BUF_SIZE_WITH_MD(in_capsule_data_size);
  }

  lqpair->resource_count = opts->max_queue_depth;

  lqpair->reqs = calloc(lqpair->resource_count, sizeof(*lqpair->reqs));
  if (!lqpair->reqs) {
    SPDK_ERRLOG("Unable to allocate reqs on lqpair=%p\n", lqpair);
    return -1;
  }

  /* TODO: Allocate in_capsule_buf? */
  if (in_capsule_data_size) {
    lqpair->bufs = spdk_zmalloc(lqpair->resource_count * in_capsule_data_size, 0x1000,
              NULL, SPDK_ENV_LCORE_ID_ANY,
              SPDK_MALLOC_DMA);
    if (!lqpair->bufs) {
      SPDK_ERRLOG("Unable to allocate bufs on lqpair=%p.\n", lqpair);
      return -1;
    }
  }

  /* prepare memory space for receiving pdus and tcp_req */
  /* Add additional 1 member, which will be used for mgmt_pdu owned by the lqpair */
  lqpair->pdus = spdk_dma_zmalloc((2 * lqpair->resource_count + 1) * sizeof(*lqpair->pdus), 0x1000,
          NULL);
  if (!lqpair->pdus) {
    SPDK_ERRLOG("Unable to allocate pdu pool on lqpair =%p.\n", lqpair);
    return -1;
  }

  /* TODO: Init TCP reqs! */
  for (i = 0; i < lqpair->resource_count; i++) {
    struct spdk_nvmf_tcp_req *tcp_req = &lqpair->reqs[i];

    tcp_req->ttag = i + 1;
    tcp_req->req.qpair = &lqpair->qpair;

    tcp_req->pdu = &lqpair->pdus[i];
    tcp_req->pdu->qpair = lqpair;

    /* Set up memory to receive commands */
    if (lqpair->bufs) {
      tcp_req->buf = (void *)((uintptr_t)lqpair->bufs + (i * in_capsule_data_size));
    }

    /* Set the cmdn and rsp */
    tcp_req->req.rsp = (union nvmf_c2h_msg *)&tcp_req->rsp;
    tcp_req->req.cmd = (union nvmf_h2c_msg *)&tcp_req->cmd;

    tcp_req->req.stripped_data = NULL;

    /* Initialize request state to FREE */
    tcp_req->state = TCP_REQUEST_STATE_FREE;
    TAILQ_INSERT_TAIL(&lqpair->tcp_req_free_queue, tcp_req, state_link);
    lqpair->state_cntr[TCP_REQUEST_STATE_FREE]++;
  }

  for (; i < 2 * lqpair->resource_count; i++) {
    struct nvme_tcp_pdu *pdu = &lqpair->pdus[i];

    pdu->qpair = lqpair;
    SLIST_INSERT_HEAD(&lqpair->tcp_pdu_free_queue, pdu, slist);
  }

  lqpair->mgmt_pdu = &lqpair->pdus[i];
  lqpair->mgmt_pdu->qpair = lqpair;
  lqpair->pdu_in_progress = SLIST_FIRST(&lqpair->tcp_pdu_free_queue);
  SLIST_REMOVE_HEAD(&lqpair->tcp_pdu_free_queue, slist);
  lqpair->tcp_pdu_working_count = 1;

#if 0
  lqpair->recv_buf_size = (in_capsule_data_size + sizeof(struct spdk_nvme_tcp_cmd) + 2 *
         SPDK_NVME_TCP_DIGEST_LEN) * SPDK_NVMF_TCP_RECV_BUF_SIZE_FACTOR;
#endif
  return 0;
}

static void
nvmf_laminar_qpair_disconnect(struct spdk_nvmf_laminar_qpair *lqpair)
{}

static void
nvmf_laminar_qpair_destroy(struct spdk_nvmf_laminar_qpair *lqpair)
{
  /* TODO: Not yet implemented. */
  /* See: _nvmf_tcp_qpair_destroy(). */
  SPDK_ERRLOG("Not yet implemented: %s\n", __func__);
}

static void
nvmf_laminar_send_c2h_term_req(struct spdk_nvmf_laminar_qpair *lqpair,
         struct nvme_tcp_pdu *pdu,
         enum spdk_nvme_tcp_term_req_fes fes, uint32_t error_offset)
{
  SPDK_ERRLOG("%s(): not implemented.\n", __func__);
  assert(false);
}

static void
nvmf_laminar_capsule_cmd_hdr_handle(struct spdk_nvmf_laminar_transport *ltransport,
        struct spdk_nvmf_laminar_qpair *lqpair,
        struct nvme_tcp_pdu *pdu)
{
  struct spdk_nvmf_tcp_req *tcp_req;

  assert(pdu->psh_valid_bytes == pdu->psh_len);
  assert(pdu->hdr.common.pdu_type == SPDK_NVME_TCP_PDU_TYPE_CAPSULE_CMD);

  tcp_req = nvmf_tcp_req_get(lqpair);
  if (!tcp_req) {
    /* Directly return and make the allocation retry again.  This can happen if we're
     * using asynchronous writes to send the response to the host or when releasing
     * zero-copy buffers after a response has been sent.  In both cases, the host might
     * receive the response before we've finished processing the request and is free to
     * send another one.
     */
    if (lqpair->state_cntr[TCP_REQUEST_STATE_TRANSFERRING_CONTROLLER_TO_HOST] > 0 ||
        lqpair->state_cntr[TCP_REQUEST_STATE_AWAITING_ZCOPY_RELEASE] > 0) {
      return;
    }

    /* The host sent more commands than the maximum queue depth. */
    SPDK_ERRLOG("Cannot allocate tcp_req on lqpair=%p\n", lqpair);
    nvmf_laminar_qpair_set_recv_state(lqpair, NVME_TCP_PDU_RECV_STATE_QUIESCING);
    return;
  }

  pdu->req = tcp_req;
  assert(tcp_req->state == TCP_REQUEST_STATE_NEW);
  nvmf_tcp_req_process(ltransport, tcp_req);
}

static void
nvmf_laminar_capsule_cmd_payload_handle(struct spdk_nvmf_laminar_transport *ltransport,
            struct spdk_nvmf_laminar_qpair *lqpair,
            struct nvme_tcp_pdu *pdu)
{
  struct spdk_nvmf_tcp_req *tcp_req;
  struct spdk_nvme_tcp_cmd *capsule_cmd;
  uint32_t error_offset = 0;
  enum spdk_nvme_tcp_term_req_fes fes;
  struct spdk_nvme_cpl *rsp;

  capsule_cmd = &pdu->hdr.capsule_cmd;
  tcp_req = pdu->req;
  assert(tcp_req != NULL);
  
  if (capsule_cmd->common.pdo > SPDK_NVME_TCP_PDU_PDO_MAX_OFFSET) {
    SPDK_ERRLOG("Expected ICReq capsule_cmd pdu offset <= %d, got %c\n",
          SPDK_NVME_TCP_PDU_PDO_MAX_OFFSET, capsule_cmd->common.pdo);
    fes = SPDK_NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD;
    error_offset = offsetof(struct spdk_nvme_tcp_common_pdu_hdr, pdo);
    goto err;
  }

  rsp = &tcp_req->req.rsp->nvme_cpl;
  if (spdk_unlikely(rsp->status.sc == SPDK_NVME_SC_COMMAND_TRANSIENT_TRANSPORT_ERROR)) {
    nvmf_tcp_req_set_state(tcp_req, TCP_REQUEST_STATE_READY_TO_COMPLETE);
  } else {
    nvmf_tcp_req_set_state(tcp_req, TCP_REQUEST_STATE_READY_TO_EXECUTE);
  }

  nvmf_tcp_req_process(ltransport, tcp_req);
  return;
err:
  nvmf_laminar_send_c2h_term_req(lqpair, pdu, fes, error_offset);
}

static void
nvmf_laminar_pdu_payload_handle(struct spdk_nvmf_laminar_qpair *lqpair, struct nvme_tcp_pdu *pdu)
{
  int rc = 0;
  struct spdk_nvmf_laminar_transport *ltransport = SPDK_CONTAINEROF(lqpair->qpair.transport,
      struct spdk_nvmf_laminar_transport, transport);
  assert(lqpair->recv_state == NVME_TCP_PDU_RECV_STATE_AWAIT_PDU_PAYLOAD);
  lqpair->pdu_in_progress = NULL;

  nvmf_laminar_qpair_set_recv_state(lqpair, NVME_TCP_PDU_RECV_STATE_AWAIT_PDU_READY);
  SPDK_DEBUGLOG(laminar, "enter\n");
  /* check data digest if need */
  if (pdu->ddgst_enable) {
    SPDK_ERRLOG("Unsupported condition. [%s:%d]\n", __FILE__, __LINE__);
    abort();
    return;
  }

  switch (pdu->hdr.common.pdu_type) {
  case SPDK_NVME_TCP_PDU_TYPE_CAPSULE_CMD:
    nvmf_laminar_capsule_cmd_payload_handle(ltransport, lqpair, pdu);
    break;
  default:
    /* The code should not go to here */
    SPDK_ERRLOG("ERROR pdu type %d\n", pdu->hdr.common.pdu_type);
    abort();
    break;
  }
  SLIST_INSERT_HEAD(&lqpair->tcp_pdu_free_queue, pdu, slist);
  lqpair->tcp_pdu_working_count--;
}

static void
nvmf_laminar_send_icresp_complete(void *cb_arg)
{
  struct spdk_nvmf_laminar_qpair *lqpair = cb_arg;

  nvmf_laminar_qpair_set_state(lqpair, NVMF_LAMINAR_QPAIR_STATE_RUNNING);
}

static void
nvmf_laminar_icreq_handle(struct spdk_nvmf_laminar_transport *ltransport,
          struct spdk_nvmf_laminar_qpair *lqpair,
          struct nvme_tcp_pdu *pdu)
{
  struct spdk_nvme_tcp_ic_req *ic_req = &pdu->hdr.ic_req;
  struct nvme_tcp_pdu *rsp_pdu;
  struct spdk_nvme_tcp_ic_resp *ic_resp;
  uint32_t error_offset = 0;
  enum spdk_nvme_tcp_term_req_fes fes;

  /* Only PFV 0 is defined currently */
  if (ic_req->pfv != 0) {
    SPDK_ERRLOG("Expected ICReq PFV %u, got %u\n", 0u, ic_req->pfv);
    fes = SPDK_NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD;
    error_offset = offsetof(struct spdk_nvme_tcp_ic_req, pfv);
    goto end;
  }

  /* This value is 0’s based value in units of dwords should not be larger than SPDK_NVME_TCP_HPDA_MAX */
  if (ic_req->hpda > SPDK_NVME_TCP_HPDA_MAX) {
    SPDK_ERRLOG("ICReq HPDA out of range 0 to 31, got %u\n", ic_req->hpda);
    fes = SPDK_NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD;
    error_offset = offsetof(struct spdk_nvme_tcp_ic_req, hpda);
    goto end;
  }

  /* MAXR2T is 0's based */
  SPDK_DEBUGLOG(nvmf_tcp, "maxr2t =%u\n", (ic_req->maxr2t + 1u));

  lqpair->host_hdgst_enable = ic_req->dgst.bits.hdgst_enable ? true : false;
  if (!lqpair->host_hdgst_enable) {
    lqpair->recv_buf_size -= SPDK_NVME_TCP_DIGEST_LEN * SPDK_NVMF_TCP_RECV_BUF_SIZE_FACTOR;
  }

  lqpair->host_ddgst_enable = ic_req->dgst.bits.ddgst_enable ? true : false;
  if (!lqpair->host_ddgst_enable) {
    lqpair->recv_buf_size -= SPDK_NVME_TCP_DIGEST_LEN * SPDK_NVMF_TCP_RECV_BUF_SIZE_FACTOR;
  }

#if 0
  /* Now that we know whether digests are enabled, properly size the receive buffer */
  lqpair->recv_buf_size = spdk_max(lqpair->recv_buf_size, MIN_SOCK_PIPE_SIZE);
  if (spdk_sock_set_recvbuf(lqpair->sock, lqpair->recv_buf_size) < 0) {
    SPDK_WARNLOG("Unable to allocate enough memory for receive buffer on lqpair=%p with size=%d\n",
           lqpair,
           lqpair->recv_buf_size);
    /* Not fatal. */
  }
#endif

  lqpair->cpda = spdk_min(ic_req->hpda, SPDK_NVME_TCP_CPDA_MAX);
  SPDK_DEBUGLOG(laminar, "cpda of lqpair=(%p) is : %u\n", lqpair, lqpair->cpda);

  rsp_pdu = lqpair->mgmt_pdu;

  ic_resp = &rsp_pdu->hdr.ic_resp;
  ic_resp->common.pdu_type = SPDK_NVME_TCP_PDU_TYPE_IC_RESP;
  ic_resp->common.hlen = ic_resp->common.plen =  sizeof(*ic_resp);
  ic_resp->pfv = 0;
  ic_resp->cpda = lqpair->cpda;
  ic_resp->maxh2cdata = ltransport->transport.opts.max_io_size;
  ic_resp->dgst.bits.hdgst_enable = lqpair->host_hdgst_enable ? 1 : 0;
  ic_resp->dgst.bits.ddgst_enable = lqpair->host_ddgst_enable ? 1 : 0;

  SPDK_DEBUGLOG(laminar, "host_hdgst_enable: %u\n", lqpair->host_hdgst_enable);
  SPDK_DEBUGLOG(laminar, "host_ddgst_enable: %u\n", lqpair->host_ddgst_enable);

  nvmf_laminar_qpair_set_state(lqpair, NVMF_LAMINAR_QPAIR_STATE_INITIALIZING);
  nvmf_laminar_qpair_write_mgmt_pdu(lqpair, nvmf_laminar_send_icresp_complete, lqpair);
  nvmf_laminar_qpair_set_recv_state(lqpair, NVME_TCP_PDU_RECV_STATE_AWAIT_PDU_READY);
  return;
end:
  nvmf_laminar_send_c2h_term_req(lqpair, pdu, fes, error_offset);
}

static void
nvmf_laminar_pdu_psh_handle(struct spdk_nvmf_laminar_qpair *lqpair,
      struct spdk_nvmf_laminar_transport *ltransport)
{
  struct nvme_tcp_pdu *pdu;
  int rc;
  uint32_t crc32c, error_offset = 0;
  enum spdk_nvme_tcp_term_req_fes fes;

  assert(lqpair->recv_state == NVME_TCP_PDU_RECV_STATE_AWAIT_PDU_PSH);
  pdu = lqpair->pdu_in_progress;

  SPDK_DEBUGLOG(laminar, "pdu type of lqpair(%p) is %d\n", lqpair,
          pdu->hdr.common.pdu_type);
  /* check header digest if needed */
  if (pdu->has_hdgst) {
    SPDK_DEBUGLOG(laminar, "Compare the header of pdu=%p on lqpair=%p\n", pdu, lqpair);
    crc32c = nvme_tcp_pdu_calc_header_digest(pdu);
    rc = MATCH_DIGEST_WORD((uint8_t *)pdu->hdr.raw + pdu->hdr.common.hlen, crc32c);
    if (rc == 0) {
      SPDK_ERRLOG("Header digest error on lqpair=(%p) with pdu=%p\n", lqpair, pdu);
      fes = SPDK_NVME_TCP_TERM_REQ_FES_HDGST_ERROR;
      nvmf_laminar_send_c2h_term_req(lqpair, pdu, fes, error_offset);
      return;
    }
  }

  switch (pdu->hdr.common.pdu_type) {
  case SPDK_NVME_TCP_PDU_TYPE_IC_REQ:
    nvmf_laminar_icreq_handle(ltransport, lqpair, pdu);
    break;
  case SPDK_NVME_TCP_PDU_TYPE_CAPSULE_CMD:
    nvmf_laminar_qpair_set_recv_state(lqpair, NVME_TCP_PDU_RECV_STATE_AWAIT_REQ);
    break;

#if 0
  case SPDK_NVME_TCP_PDU_TYPE_H2C_DATA:
    nvmf_laminar_h2c_data_hdr_handle(ltransport, lqpair, pdu);
    break;

  case SPDK_NVME_TCP_PDU_TYPE_H2C_TERM_REQ:
    nvmf_laminar_h2c_term_req_hdr_handle(lqpair, pdu);
    break;
#endif

  default:
    SPDK_ERRLOG("Unexpected PDU type 0x%02x\n", lqpair->pdu_in_progress->hdr.common.pdu_type);
    fes = SPDK_NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD;
    error_offset = 1;
    nvmf_laminar_send_c2h_term_req(lqpair, pdu, fes, error_offset);
    break;
  }
}

static void
nvmf_laminar_pdu_ch_handle(struct spdk_nvmf_laminar_qpair *lqpair)
{
  struct nvme_tcp_pdu *pdu;
  uint32_t error_offset = 0;
  enum spdk_nvme_tcp_term_req_fes fes;
  uint8_t expected_hlen, pdo;
  bool plen_error = false, pdo_error = false;

  assert(lqpair->recv_state == NVME_TCP_PDU_RECV_STATE_AWAIT_PDU_CH);
  pdu = lqpair->pdu_in_progress;
  assert(pdu);
  if (pdu->hdr.common.pdu_type == SPDK_NVME_TCP_PDU_TYPE_IC_REQ) {
    if (lqpair->state != NVMF_LAMINAR_QPAIR_STATE_MOVED) {
      SPDK_ERRLOG("Already received ICreq PDU, and reject this pdu=%p\n", pdu);
      fes = SPDK_NVME_TCP_TERM_REQ_FES_PDU_SEQUENCE_ERROR;
      goto err;
    }
    expected_hlen = sizeof(struct spdk_nvme_tcp_ic_req);
    if (pdu->hdr.common.plen != expected_hlen) {
      plen_error = true;
    }
  } else {
    if (lqpair->state != NVMF_LAMINAR_QPAIR_STATE_RUNNING) {
      SPDK_ERRLOG("The TCP/IP connection is not negotiated\n");
      fes = SPDK_NVME_TCP_TERM_REQ_FES_PDU_SEQUENCE_ERROR;
      goto err;
    }

    switch (pdu->hdr.common.pdu_type) {
    case SPDK_NVME_TCP_PDU_TYPE_CAPSULE_CMD:
      expected_hlen = sizeof(struct spdk_nvme_tcp_cmd);
      pdo = pdu->hdr.common.pdo;
      if ((lqpair->cpda != 0) && (pdo % ((lqpair->cpda + 1) << 2) != 0)) {
        pdo_error = true;
        break;
      }

      if (pdu->hdr.common.plen < expected_hlen) {
        plen_error = true;
      }
      break;
    case SPDK_NVME_TCP_PDU_TYPE_H2C_DATA:
      /* Not yet supported! */
      expected_hlen = 0;
      assert(false);
      break;

    case SPDK_NVME_TCP_PDU_TYPE_H2C_TERM_REQ:
      expected_hlen = sizeof(struct spdk_nvme_tcp_term_req_hdr);
      if ((pdu->hdr.common.plen <= expected_hlen) ||
          (pdu->hdr.common.plen > SPDK_NVME_TCP_TERM_REQ_PDU_MAX_SIZE)) {
        plen_error = true;
      }
      break;

    default:
      SPDK_ERRLOG("Unexpected PDU type 0x%02x\n", pdu->hdr.common.pdu_type);
      fes = SPDK_NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD;
      error_offset = offsetof(struct spdk_nvme_tcp_common_pdu_hdr, pdu_type);
      goto err;
    }
  }

  if (pdu->hdr.common.hlen != expected_hlen) {
    SPDK_ERRLOG("PDU type=0x%02x, Expected ICReq header length %u, got %u on lqpair=%p\n",
          pdu->hdr.common.pdu_type,
          expected_hlen, pdu->hdr.common.hlen, lqpair);
    fes = SPDK_NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD;
    error_offset = offsetof(struct spdk_nvme_tcp_common_pdu_hdr, hlen);
    goto err;
  } else if (pdo_error) {
    fes = SPDK_NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD;
    error_offset = offsetof(struct spdk_nvme_tcp_common_pdu_hdr, pdo);
  } else if (plen_error) {
    fes = SPDK_NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD;
    error_offset = offsetof(struct spdk_nvme_tcp_common_pdu_hdr, plen);
    goto err;
  } else {
    nvmf_laminar_qpair_set_recv_state(lqpair, NVME_TCP_PDU_RECV_STATE_AWAIT_PDU_PSH);
    nvme_tcp_pdu_calc_psh_len(lqpair->pdu_in_progress, lqpair->host_hdgst_enable);
    return;
  }
err:
  nvmf_laminar_send_c2h_term_req(lqpair, pdu, fes, error_offset);
}

static int
nvmf_laminar_qpair_receive_process(
        struct spdk_nvmf_laminar_poll_group *lgroup,
        struct spdk_nvmf_laminar_qpair *lqpair,
        int return_code, void *buf, size_t len)
{
  int rc = 0;
  struct nvme_tcp_pdu *pdu;
  struct spdk_nvmf_tcp_req *tcp_req;
  enum nvme_tcp_pdu_recv_state prev_state;
  uint32_t read_len, data_len;
  struct spdk_nvmf_laminar_transport *ltransport = SPDK_CONTAINEROF(lqpair->qpair.transport,
      struct spdk_nvmf_laminar_transport, transport);

  /* The loop here is to allow for several back-to-back state changes. */
  do {
#if 0
    /* No more data to process. */
    if (len == 0)
      return rc;
#endif

    prev_state = lqpair->recv_state;
    SPDK_DEBUGLOG(laminar, "lqpair(%p) recv pdu entering state %d\n", lqpair, prev_state);

    pdu = lqpair->pdu_in_progress;
    assert(pdu != NULL ||
           lqpair->recv_state == NVME_TCP_PDU_RECV_STATE_AWAIT_PDU_READY ||
           lqpair->recv_state == NVME_TCP_PDU_RECV_STATE_QUIESCING ||
           lqpair->recv_state == NVME_TCP_PDU_RECV_STATE_ERROR);

    switch (lqpair->recv_state) {
    /* Wait for the common header */
    case NVME_TCP_PDU_RECV_STATE_AWAIT_PDU_READY:
      if (!pdu) {
        pdu = SLIST_FIRST(&lqpair->tcp_pdu_free_queue);
        if (spdk_unlikely(!pdu)) {
          return NVME_TCP_PDU_IN_PROGRESS;
        }
        SLIST_REMOVE_HEAD(&lqpair->tcp_pdu_free_queue, slist);
        lqpair->pdu_in_progress = pdu;
        lqpair->tcp_pdu_working_count++;
      }
      memset(pdu, 0, offsetof(struct nvme_tcp_pdu, qpair));
      nvmf_laminar_qpair_set_recv_state(lqpair, NVME_TCP_PDU_RECV_STATE_AWAIT_PDU_CH);
      /* FALLTHROUGH */
    case NVME_TCP_PDU_RECV_STATE_AWAIT_PDU_CH:
      if (spdk_unlikely(lqpair->state == NVMF_LAMINAR_QPAIR_STATE_INITIALIZING)) {
        return rc;
      }

      if (return_code != 0) {
        SPDK_DEBUGLOG(laminar, "will disconnect lqpair=%p\n", lqpair);
        nvmf_laminar_qpair_set_recv_state(lqpair, NVME_TCP_PDU_RECV_STATE_QUIESCING);
        break;
      }

      read_len = spdk_min(len, sizeof(struct spdk_nvme_tcp_common_pdu_hdr) - pdu->ch_valid_bytes);
      memcpy((void *)&pdu->hdr.common + pdu->ch_valid_bytes, buf, read_len);
      laminar_connection_rx_free_range(lgroup->context->ctx,
                lqpair->conn, buf, read_len);

      buf += read_len;
      len -= read_len;
      pdu->ch_valid_bytes += read_len;

      if (pdu->ch_valid_bytes < sizeof(struct spdk_nvme_tcp_common_pdu_hdr)) {
        return NVME_TCP_PDU_IN_PROGRESS;
      }

      /* The command header of this PDU has now been read from the socket. */
      nvmf_laminar_pdu_ch_handle(lqpair);
      break;
    /* Wait for the PDU specific header */
    case NVME_TCP_PDU_RECV_STATE_AWAIT_PDU_PSH:
      if (return_code != 0) {
        SPDK_DEBUGLOG(laminar, "will disconnect lqpair=%p\n", lqpair);
        nvmf_laminar_qpair_set_recv_state(lqpair, NVME_TCP_PDU_RECV_STATE_QUIESCING);
        break;
      }

      read_len = spdk_min(len, pdu->psh_len - pdu->psh_valid_bytes);
      memcpy((void *)&pdu->hdr.raw + sizeof(struct spdk_nvme_tcp_common_pdu_hdr) + pdu->psh_valid_bytes,
                buf, read_len);
      laminar_connection_rx_free_range(lgroup->context->ctx,
                  lqpair->conn, buf, read_len);

      buf += read_len;
      len -= read_len;
      pdu->psh_valid_bytes += read_len;

      if (pdu->psh_valid_bytes < pdu->psh_len) {
        return NVME_TCP_PDU_IN_PROGRESS;
      }

      /* All header(ch, psh, head digits) of this PDU has now been read from the socket. */
      nvmf_laminar_pdu_psh_handle(lqpair, ltransport);
      break;
    /* Wait for the req slot */
    case NVME_TCP_PDU_RECV_STATE_AWAIT_REQ:
      nvmf_laminar_capsule_cmd_hdr_handle(ltransport, lqpair, pdu);
      break;
    /* Wait for the request processing loop to acquire a buffer for the PDU */
    case NVME_TCP_PDU_RECV_STATE_AWAIT_PDU_BUF:
      break;
    case NVME_TCP_PDU_RECV_STATE_AWAIT_PDU_PAYLOAD:
      /* check whether the data is valid, if not we just return */
      if (!pdu->data_len) {
        return NVME_TCP_PDU_IN_PROGRESS;
      }

      tcp_req = pdu->req;
      data_len = pdu->data_len;
      /* data digest */
      if (spdk_unlikely((pdu->hdr.common.pdu_type != SPDK_NVME_TCP_PDU_TYPE_H2C_TERM_REQ) &&
            lqpair->host_ddgst_enable)) {
        data_len += SPDK_NVME_TCP_DIGEST_LEN;
        pdu->ddgst_enable = true;
      }

      if (return_code != 0) {
        SPDK_DEBUGLOG(laminar, "will disconnect lqpair=%p\n", lqpair);
        nvmf_laminar_qpair_set_recv_state(lqpair, NVME_TCP_PDU_RECV_STATE_QUIESCING);
        break;
      }

      read_len = spdk_min(len, data_len - pdu->rw_offset);
      if (pdu->rw_offset == 0) {
        /* Set the buffer here! */
        assert(tcp_req->req.iovcnt == 1);
        tcp_req->req.iov[0].iov_base = buf;
      }
      
      pdu->rw_offset += read_len;

      buf += read_len;
      len -= read_len;

      if (pdu->rw_offset < data_len) {
        return NVME_TCP_PDU_IN_PROGRESS;
      }

      nvme_tcp_pdu_set_data_buf(pdu, tcp_req->req.iov,
          tcp_req->req.iovcnt, 0, tcp_req->req.length);

      /* All of this PDU has now been read from the socket. */
      nvmf_laminar_pdu_payload_handle(lqpair, pdu);
      break;

    default:
      SPDK_ERRLOG("The state(%d) is invalid\n", lqpair->recv_state);
      abort();
      break;
    }
  } while (lqpair->recv_state != prev_state);

  return rc;
}

static void
nvmf_laminar_qpair_send_process(
  struct spdk_nvmf_laminar_poll_group *lgroup,
  struct spdk_nvmf_laminar_qpair *lqpair,
  int return_code)
{
  assert(false);
}

static inline void
nvmf_tcp_req_set_cpl(struct spdk_nvmf_tcp_req *treq, int sct, int sc)
{
  treq->req.rsp->nvme_cpl.status.sct = sct;
  treq->req.rsp->nvme_cpl.status.sc = sc;
  treq->req.rsp->nvme_cpl.cid = treq->req.cmd->nvme_cmd.cid;
}

static void
nvmf_tcp_req_parse_sgl(struct spdk_nvmf_tcp_req *tcp_req,
           struct spdk_nvmf_transport *transport,
           struct spdk_nvmf_transport_poll_group *group)
{
  struct spdk_nvmf_request            *req = &tcp_req->req;
  struct spdk_nvme_cmd                *cmd;
  struct spdk_nvme_sgl_descriptor     *sgl;
  struct spdk_nvmf_laminar_poll_group *lgroup;
  enum spdk_nvme_tcp_term_req_fes      fes;
  struct nvme_tcp_pdu                 *pdu;
  struct spdk_nvmf_laminar_qpair      *lqpair;
  uint32_t length, error_offset = 0;

  cmd = &req->cmd->nvme_cmd;
  sgl = &cmd->dptr.sgl1;

  if (sgl->generic.type == SPDK_NVME_SGL_TYPE_TRANSPORT_DATA_BLOCK &&
      sgl->unkeyed.subtype == SPDK_NVME_SGL_SUBTYPE_TRANSPORT) {
    /* get request length from sgl */
    length = sgl->unkeyed.length;
    if (spdk_unlikely(length > transport->opts.max_io_size)) {
      SPDK_ERRLOG("SGL length 0x%x exceeds max io size 0x%x\n",
            length, transport->opts.max_io_size);
      fes = SPDK_NVME_TCP_TERM_REQ_FES_DATA_TRANSFER_LIMIT_EXCEEDED;
      goto fatal_err;
    }

    /* fill request length and populate iovs */
    req->length = length;

    if (spdk_nvmf_request_get_buffers(req, group, transport, length)) {
      /* No available buffers. Queue this request up. */
      SPDK_DEBUGLOG(laminar, "No available large data buffers. Queueing request %p\n",
              tcp_req);
      return;
    }

    nvmf_tcp_req_set_state(tcp_req, TCP_REQUEST_STATE_HAVE_BUFFER);
    SPDK_DEBUGLOG(laminar, "Request %p took %d buffer/s from central pool, and data=%p\n",
            tcp_req, req->iovcnt, req->iov[0].iov_base);

    return;
  } else if (sgl->generic.type == SPDK_NVME_SGL_TYPE_DATA_BLOCK &&
       sgl->unkeyed.subtype == SPDK_NVME_SGL_SUBTYPE_OFFSET) {
    uint32_t offset = sgl->address;
    uint32_t max_len = transport->opts.in_capsule_data_size;

    assert(tcp_req->has_in_capsule_data);
    /* Capsule Cmd with In-capsule Data should get data length from pdu header */
    lqpair = tcp_req->pdu->qpair;
    /* receiving pdu is not same with the pdu in tcp_req */
    pdu = lqpair->pdu_in_progress;
    length = pdu->hdr.common.plen - pdu->psh_len - sizeof(struct spdk_nvme_tcp_common_pdu_hdr);
    if (lqpair->host_ddgst_enable) {
      length -= SPDK_NVME_TCP_DIGEST_LEN;
    }
    /* This error is not defined in NVMe/TCP spec, take this error as fatal error */
    if (spdk_unlikely(length != sgl->unkeyed.length)) {
      SPDK_ERRLOG("In-Capsule Data length 0x%x is not equal to SGL data length 0x%x\n",
            length, sgl->unkeyed.length);
      fes = SPDK_NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD;
      error_offset = offsetof(struct spdk_nvme_tcp_common_pdu_hdr, plen);
      goto fatal_err;
    }

    SPDK_DEBUGLOG(laminar, "In-capsule data: offset 0x%" PRIx64 ", length 0x%x\n",
            offset, length);

    /* The NVMe/TCP transport does not use ICDOFF to control the in-capsule data offset. ICDOFF should be '0' */
    if (spdk_unlikely(offset != 0)) {
      /* Not defined fatal error in NVMe/TCP spec, handle this error as a fatal error */
      SPDK_ERRLOG("In-capsule offset 0x%" PRIx64 " should be ZERO in NVMe/TCP\n", offset);
      fes = SPDK_NVME_TCP_TERM_REQ_FES_INVALID_DATA_UNSUPPORTED_PARAMETER;
      error_offset = offsetof(struct spdk_nvme_tcp_cmd, ccsqe.dptr.sgl1.address);
      goto fatal_err;
    }

    if (spdk_unlikely(length > max_len)) {
      SPDK_ERRLOG("In-capsule data length 0x%x exceeds capsule length 0x%x\n",
            length, max_len);
      fes = SPDK_NVME_TCP_TERM_REQ_FES_DATA_TRANSFER_LIMIT_EXCEEDED;
      goto fatal_err;
    } else {
      /* TODO: Get base addr from laminar RX payload buffer. */
#if 0
      req->iov[0].iov_base = tcp_req->buf;
#else
      req->iov[0].iov_base = 0;
#endif
    }

    req->length = length;
    req->data_from_pool = false;

    req->iov[0].iov_len = length;
    req->iovcnt = 1;
    nvmf_tcp_req_set_state(tcp_req, TCP_REQUEST_STATE_HAVE_BUFFER);

    return;
  }
  /* If we want to handle the problem here, then we can't skip the following data segment.
   * Because this function runs before reading data part, now handle all errors as fatal errors. */
  SPDK_ERRLOG("Invalid NVMf I/O Command SGL:  Type 0x%x, Subtype 0x%x\n",
        sgl->generic.type, sgl->generic.subtype);
  fes = SPDK_NVME_TCP_TERM_REQ_FES_INVALID_DATA_UNSUPPORTED_PARAMETER;
  error_offset = offsetof(struct spdk_nvme_tcp_cmd, ccsqe.dptr.sgl1.generic);
fatal_err:
  nvmf_laminar_send_c2h_term_req(tcp_req->pdu->qpair, tcp_req->pdu, fes, error_offset);
}

static void
nvmf_laminar_send_capsule_resp_pdu(struct spdk_nvmf_tcp_req *tcp_req,
              struct spdk_nvmf_laminar_qpair *lqpair)
{
  struct nvme_tcp_pdu *rsp_pdu;
  struct spdk_nvme_tcp_rsp *capsule_resp;

  SPDK_DEBUGLOG(laminar, "enter, lqpair=%p\n", lqpair);

  rsp_pdu = nvmf_tcp_req_pdu_init(tcp_req);
  assert(rsp_pdu != NULL);

  capsule_resp = &rsp_pdu->hdr.capsule_resp;
  capsule_resp->common.pdu_type = SPDK_NVME_TCP_PDU_TYPE_CAPSULE_RESP;
  capsule_resp->common.plen = capsule_resp->common.hlen = sizeof(*capsule_resp);
  capsule_resp->rccqe = tcp_req->req.rsp->nvme_cpl;
  if (lqpair->host_hdgst_enable) {
    capsule_resp->common.flags |= SPDK_NVME_TCP_CH_FLAGS_HDGSTF;
    capsule_resp->common.plen += SPDK_NVME_TCP_DIGEST_LEN;
  }

  nvmf_laminar_qpair_write_req_pdu(lqpair, tcp_req, nvmf_tcp_request_free, tcp_req);
}

static void
nvmf_laminar_pdu_c2h_data_complete(void *cb_arg)
{
	struct spdk_nvmf_tcp_req *tcp_req = cb_arg;
	struct spdk_nvmf_laminar_qpair *lqpair = SPDK_CONTAINEROF(tcp_req->req.qpair,
					     struct spdk_nvmf_laminar_qpair, qpair); 

  assert(lqpair != NULL);

  assert(tcp_req->pdu->rw_offset == tcp_req->req.length);

	if (tcp_req->pdu->hdr.c2h_data.common.flags & SPDK_NVME_TCP_C2H_DATA_FLAGS_SUCCESS) {
		nvmf_tcp_request_free(tcp_req);
	} else {
		nvmf_laminar_send_capsule_resp_pdu(tcp_req, lqpair);
	}
}

static void
nvmf_laminar_send_c2h_data(struct spdk_nvmf_laminar_qpair *lqpair,
            struct spdk_nvmf_tcp_req *tcp_req)
{
  struct nvme_tcp_pdu *rsp_pdu;
  struct spdk_nvme_tcp_c2h_data_hdr *c2h_data;
  uint32_t plen, pdo, alignment;
  int rc;

  SPDK_DEBUGLOG(laminar, "enter, lqpair=%p\n", lqpair);
 
  rsp_pdu = nvmf_tcp_req_pdu_init(tcp_req);
  assert(rsp_pdu != NULL);

  c2h_data = &rsp_pdu->hdr.c2h_data;
  c2h_data->common.pdu_type = SPDK_NVME_TCP_PDU_TYPE_C2H_DATA;
  plen = c2h_data->common.hlen = sizeof(*c2h_data);

  if (lqpair->host_hdgst_enable) {
    plen += SPDK_NVME_TCP_DIGEST_LEN;
    c2h_data->common.flags |= SPDK_NVME_TCP_CH_FLAGS_HDGSTF;
  }

  /* set the psh */
  c2h_data->cccid = tcp_req->req.cmd->nvme_cmd.cid;
  c2h_data->datal = tcp_req->req.length - tcp_req->pdu->rw_offset;
  c2h_data->datao = tcp_req->pdu->rw_offset;

  /* set the padding */
  rsp_pdu->padding_len = 0;
  pdo = plen;
  if (lqpair->cpda) {
    alignment = (lqpair->cpda + 1) << 2;
    if (plen % alignment != 0) {
      pdo = (plen + alignment) / alignment * alignment;
      rsp_pdu->padding_len = pdo - plen;
      plen = pdo;
    }
  }

  c2h_data->common.pdo = pdo;
  plen += c2h_data->datal;
  if (lqpair->host_ddgst_enable) {
    c2h_data->common.flags |= SPDK_NVME_TCP_CH_FLAGS_DDGSTF;
    plen += SPDK_NVME_TCP_DIGEST_LEN;
  }

  c2h_data->common.plen = plen;

  nvme_tcp_pdu_set_data_buf(rsp_pdu, tcp_req->req.iov, tcp_req->req.iovcnt,
        c2h_data->datao, c2h_data->datal);

  c2h_data->common.flags |= SPDK_NVME_TCP_C2H_DATA_FLAGS_LAST_PDU;
  /* Need to send the capsule response if response is not all 0 */
  if (tcp_req->rsp.cdw0 == 0 && tcp_req->rsp.cdw1 == 0) {
    c2h_data->common.flags |= SPDK_NVME_TCP_C2H_DATA_FLAGS_SUCCESS;
  }

	rsp_pdu->rw_offset += c2h_data->datal;
  nvmf_laminar_qpair_write_req_pdu(lqpair, tcp_req, nvmf_laminar_pdu_c2h_data_complete, tcp_req);
}

static int
request_transfer_out(struct spdk_nvmf_request *req)
{
  struct spdk_nvmf_tcp_req        *tcp_req;
  struct spdk_nvmf_qpair          *qpair;
  struct spdk_nvmf_laminar_qpair  *lqpair;
  struct spdk_nvme_cpl            *rsp;

  SPDK_DEBUGLOG(laminar, "enter\n");

  qpair = req->qpair;
  rsp = &req->rsp->nvme_cpl;
  tcp_req = SPDK_CONTAINEROF(req, struct spdk_nvmf_tcp_req, req);

  /* Advance our sq_head pointer */
  if (qpair->sq_head == qpair->sq_head_max) {
    qpair->sq_head = 0;
  } else {
    qpair->sq_head++;
  }
  rsp->sqhd = qpair->sq_head;

  lqpair = SPDK_CONTAINEROF(tcp_req->req.qpair, struct spdk_nvmf_laminar_qpair, qpair);
  nvmf_tcp_req_set_state(tcp_req, TCP_REQUEST_STATE_TRANSFERRING_CONTROLLER_TO_HOST);
  if (rsp->status.sc == SPDK_NVME_SC_SUCCESS && req->xfer == SPDK_NVME_DATA_CONTROLLER_TO_HOST) {
    nvmf_laminar_send_c2h_data(lqpair, tcp_req);
#if 0
    SPDK_ERRLOG("Unsupported operation. [%s:%d]\n", __FILE__, __LINE__);
    abort();
    return 0;
#endif
  } else {
    nvmf_laminar_send_capsule_resp_pdu(tcp_req, lqpair);
  }

  return 0;
}

static bool
nvmf_tcp_req_process(struct spdk_nvmf_laminar_transport *ltransport,
         struct spdk_nvmf_tcp_req *tcp_req)
{
  struct spdk_nvmf_laminar_qpair *lqpair;
  uint32_t				                plen;
  struct nvme_tcp_pdu            *pdu;
  enum spdk_nvmf_tcp_req_state		prev_state;
  bool                            progress = false;
  struct spdk_nvmf_transport     *transport = &ltransport->transport;
  struct spdk_nvmf_transport_poll_group	*group;
  struct spdk_nvmf_laminar_poll_group   *lgroup;

  lqpair = SPDK_CONTAINEROF(tcp_req->req.qpair, struct spdk_nvmf_laminar_qpair, qpair);
  group = &lqpair->group->group;
  assert(tcp_req->state != TCP_REQUEST_STATE_FREE);

  /* If the qpair is not active, we need to abort the outstanding requests. */
  if (!spdk_nvmf_qpair_is_active(&lqpair->qpair)) {
    if (tcp_req->state == TCP_REQUEST_STATE_NEED_BUFFER) {
      SPDK_ERRLOG("Unhandled case. [%s:%d]\n", __FILE__, __LINE__);
      abort();
      return false;
    }
    nvmf_tcp_req_set_state(tcp_req, TCP_REQUEST_STATE_COMPLETED);
  }

  /* The loop here is to allow for several back-to-back state changes. */
  do {
    prev_state = tcp_req->state;

    SPDK_DEBUGLOG(laminar, "Request %p entering state %d on lqpair=%p\n", tcp_req, prev_state,
            lqpair);

    switch (tcp_req->state) {
    case TCP_REQUEST_STATE_FREE:
      /* Some external code must kick a request into TCP_REQUEST_STATE_NEW
       * to escape this state. */
      break;
    case TCP_REQUEST_STATE_NEW:
      /* copy the cmd from the receive pdu */
      tcp_req->cmd = lqpair->pdu_in_progress->hdr.capsule_cmd.ccsqe;
      
      /* NOTE: We do not support fusing! */
      tcp_req->req.xfer = spdk_nvmf_req_get_xfer(&tcp_req->req);

      if (spdk_unlikely(tcp_req->req.xfer == SPDK_NVME_DATA_BIDIRECTIONAL)) {
        nvmf_tcp_req_set_cpl(tcp_req, SPDK_NVME_SCT_GENERIC, SPDK_NVME_SC_INVALID_OPCODE);
        nvmf_laminar_qpair_set_recv_state(lqpair, NVME_TCP_PDU_RECV_STATE_AWAIT_PDU_READY);
        nvmf_tcp_req_set_state(tcp_req, TCP_REQUEST_STATE_READY_TO_COMPLETE);
        SPDK_DEBUGLOG(laminar, "Request %p: invalid xfer type (BIDIRECTIONAL)\n", tcp_req);
        break;
      }

      /* If no data to transfer, ready to execute. */
      if (tcp_req->req.xfer == SPDK_NVME_DATA_NONE) {
        /* Reset the lqpair receiving pdu state */
        nvmf_laminar_qpair_set_recv_state(lqpair, NVME_TCP_PDU_RECV_STATE_AWAIT_PDU_READY);
        nvmf_tcp_req_set_state(tcp_req, TCP_REQUEST_STATE_READY_TO_EXECUTE);
        break;
      }

      pdu = lqpair->pdu_in_progress;
      plen = pdu->hdr.common.hlen;
      if (lqpair->host_hdgst_enable) {
        plen += SPDK_NVME_TCP_DIGEST_LEN;
      }
      if (pdu->hdr.common.plen != plen) {
        tcp_req->has_in_capsule_data = true;
      } else {
        /* Data is transmitted by C2H PDUs */
        nvmf_laminar_qpair_set_recv_state(lqpair, NVME_TCP_PDU_RECV_STATE_AWAIT_PDU_READY);
      }
      nvmf_tcp_req_set_state(tcp_req, TCP_REQUEST_STATE_NEED_BUFFER);
      break;
    case TCP_REQUEST_STATE_NEED_BUFFER:
      assert(tcp_req->req.xfer != SPDK_NVME_DATA_NONE);

      /* Try to get a data buffer */
      nvmf_tcp_req_parse_sgl(tcp_req, transport, group);
      break;
    case TCP_REQUEST_STATE_HAVE_BUFFER:
      assert(tcp_req->req.iovcnt > 0);

      /* If data is transferring from host to controller, we need to do a transfer from the host. */
      if (tcp_req->req.xfer == SPDK_NVME_DATA_HOST_TO_CONTROLLER) {
        if (tcp_req->req.data_from_pool) {
          SPDK_ERRLOG("Unsupported condition. [%s:%d]\n", __FILE__, __LINE__);
          abort();
        } else {
          struct nvme_tcp_pdu *pdu;

          nvmf_tcp_req_set_state(tcp_req, TCP_REQUEST_STATE_TRANSFERRING_HOST_TO_CONTROLLER);
          pdu = lqpair->pdu_in_progress;
          SPDK_DEBUGLOG(laminar, "Not need to send r2t for tcp_req(%p) on lqpair=%p\n", tcp_req,
                lqpair);
#if 0
          /* No need to send r2t, contained in the capsuled data */
          nvme_tcp_pdu_set_data_buf(pdu, tcp_req->req.iov, tcp_req->req.iovcnt,
                  0, tcp_req->req.length);
#else
          /* No need to send r2t, contained in the capsuled data */
          pdu->data_len = tcp_req->req.length;
          pdu->data_iovcnt = 1;
#endif
          nvmf_laminar_qpair_set_recv_state(lqpair, NVME_TCP_PDU_RECV_STATE_AWAIT_PDU_PAYLOAD);
        }
        break;
      }
#if 0
      else {
        /* TODO: Allocate laminar TX payload buffer! */
        SPDK_ERRLOG("Unsupported condition. [%s:%d]\n", __FILE__, __LINE__);
        abort();
      }
#endif

      nvmf_tcp_req_set_state(tcp_req, TCP_REQUEST_STATE_READY_TO_EXECUTE);
      break;
    case TCP_REQUEST_STATE_TRANSFERRING_HOST_TO_CONTROLLER:
      /* Some external code must kick a request into TCP_REQUEST_STATE_READY_TO_EXECUTE
       * to escape this state. */
      break;
    case TCP_REQUEST_STATE_READY_TO_EXECUTE:
      assert(tcp_req->cmd.fuse == SPDK_NVME_CMD_FUSE_NONE);
      assert(tcp_req->req.dif_enabled == false);

      nvmf_tcp_req_set_state(tcp_req, TCP_REQUEST_STATE_EXECUTING);
      spdk_nvmf_request_exec(&tcp_req->req);
      break;
    case TCP_REQUEST_STATE_EXECUTING:
      /* Some external code must kick a request into TCP_REQUEST_STATE_EXECUTED
       * to escape this state. */
      break;
    case TCP_REQUEST_STATE_EXECUTED:
      if (tcp_req->req.xfer == SPDK_NVME_DATA_HOST_TO_CONTROLLER) {
        if (tcp_req->req.data_from_pool) {
          SPDK_ERRLOG("Unsupported condition. [%s:%d]\n", __FILE__, __LINE__);
          abort();
        } else {
          /* Free the RX buffer! */
          assert(tcp_req->req.iovcnt == 1);
          lgroup = lqpair->group;

          laminar_connection_rx_free_range(lgroup->context->ctx,
              lqpair->conn, tcp_req->req.iov[0].iov_base, tcp_req->req.iov[0].iov_len);
        }
      }
      nvmf_tcp_req_set_state(tcp_req, TCP_REQUEST_STATE_READY_TO_COMPLETE);
      break;
    case TCP_REQUEST_STATE_READY_TO_COMPLETE:
      if (request_transfer_out(&tcp_req->req) != 0) {
        assert(0);  /* No good way to handle this currently. */
      }
      break;
    case TCP_REQUEST_STATE_COMPLETED:
      assert(!tcp_req->req.data_from_pool);

      /* TODO: Free buffer for TX requests! */
      tcp_req->req.length = 0;
      tcp_req->req.iovcnt = 0;

      nvmf_tcp_req_put(lqpair, tcp_req);
      break;
    case TCP_REQUEST_NUM_STATES:
    default:
      assert(0);
      break;
    }

    if (tcp_req->state != prev_state) {
      progress = true;
    }
  } while (tcp_req->state != prev_state);
  return progress;
}

/* Public API callbacks begin here */
static void
nvmf_laminar_opts_init(struct spdk_nvmf_transport_opts *opts)
{
  opts->max_queue_depth =	SPDK_NVMF_LAMINAR_DEFAULT_MAX_IO_QUEUE_DEPTH;
  opts->max_qpairs_per_ctrlr = SPDK_NVMF_LAMINAR_DEFAULT_MAX_QPAIRS_PER_CTRLR; 
  opts->in_capsule_data_size = SPDK_NVMF_LAMINAR_DEFAULT_IN_CAPSULE_DATA_SIZE;
  opts->max_io_size =	SPDK_NVMF_LAMINAR_DEFAULT_MAX_IO_SIZE;
  opts->io_unit_size = SPDK_NVMF_LAMINAR_DEFAULT_IO_UNIT_SIZE;
  opts->max_aq_depth = SPDK_NVMF_LAMINAR_DEFAULT_MAX_ADMIN_QUEUE_DEPTH;
  opts->num_shared_buffers = SPDK_NVMF_LAMINAR_DEFAULT_NUM_SHARED_BUFFERS;
  opts->buf_cache_size = SPDK_NVMF_LAMINAR_DEFAULT_BUFFER_CACHE_SIZE;
  opts->dif_insert_or_strip = SPDK_NVMF_LAMINAR_DEFAULT_DIF_INSERT_OR_STRIP;
  opts->abort_timeout_sec = SPDK_NVMF_LAMINAR_DEFAULT_ABORT_TIMEOUT_SEC;
  opts->transport_specific = NULL;
}

static struct spdk_nvmf_transport *
nvmf_laminar_create(struct spdk_nvmf_transport_opts *opts)
{
  struct spdk_nvmf_laminar_transport *ltransport;

  if (laminar_init()) {
    SPDK_ERRLOG("failed to initialize laminar\n");
    return NULL;
  }

  ltransport = calloc(1, sizeof(*ltransport));
  if (!ltransport) {
    return NULL;
  }

  TAILQ_INIT(&ltransport->ports);
  TAILQ_INIT(&ltransport->poll_groups);

  ltransport->transport.ops = &spdk_nvmf_transport_laminar;
  ltransport->laminar_opts.acceptor_backlog = SPDK_NVMF_LAMINAR_ACCEPTOR_BACKLOG;
  ltransport->laminar_opts.poll_batch_size = SPDK_NVMF_LAMINAR_DEFAULT_POLL_BATCH_SIZE;
  ltransport->laminar_opts.control_msg_num = SPDK_NVMF_LAMINAR_DEFAULT_CONTROL_MSG_NUM;

  SPDK_NOTICELOG("*** Laminar Transport Init ***\n");

  SPDK_INFOLOG(laminar, "*** Laminar Transport Init ***\n"
    "  Transport opts:  max_ioq_depth=%d, max_io_size=%d,\n"
    "  max_io_qpairs_per_ctrlr=%d, io_unit_size=%d,\n"
    "  in_capsule_data_size=%d, max_aq_depth=%d,\n"
    "  num_shared_buffers=%d, abort_timeout_sec=%d,\n"
    "  acceptor_backlog=%d, poll_batch_size=%d\n",
    opts->max_queue_depth,
    opts->max_io_size,
    opts->max_qpairs_per_ctrlr - 1,
    opts->io_unit_size,
    opts->in_capsule_data_size,
    opts->max_aq_depth,
    opts->num_shared_buffers,
    opts->abort_timeout_sec,
    ltransport->laminar_opts.acceptor_backlog,
    ltransport->laminar_opts.poll_batch_size);

  ltransport->accept_poller = SPDK_POLLER_REGISTER(nvmf_laminar_accept_poll, &ltransport->transport,
    opts->acceptor_poll_rate);
  if (!ltransport->accept_poller) {
    free(ltransport);
    return NULL;
  }

  ltransport->listen_context = spdk_laminar_ctx_create(
    ltransport->laminar_opts.poll_batch_size, ltransport);
  if (ltransport->listen_context == NULL) {
    SPDK_ERRLOG("Failed to create context for listen sockets\n");
    spdk_poller_unregister(&ltransport->accept_poller);
    free(ltransport);
    return NULL;
  }

  return &ltransport->transport;
}

static void
nvmf_laminar_dump_opts(struct spdk_nvmf_transport *transport, struct spdk_json_write_ctx *w)
{
  struct spdk_nvmf_laminar_transport	*ltransport;
  assert(w != NULL);

  ltransport = SPDK_CONTAINEROF(transport, struct spdk_nvmf_laminar_transport, transport);
  spdk_json_write_named_int32(w, "acceptor_backlog", ltransport->laminar_opts.acceptor_backlog);
  spdk_json_write_named_uint32(w, "poll_batch_size", ltransport->laminar_opts.poll_batch_size);
}

static int
nvmf_laminar_destroy(struct spdk_nvmf_transport *transport,
  spdk_nvmf_transport_destroy_done_cb cb_fn, void *cb_arg)
{
  struct spdk_nvmf_laminar_transport *ltransport;

  assert(transport != NULL);
  ltransport = SPDK_CONTAINEROF(transport, struct spdk_nvmf_laminar_transport, transport);

  spdk_poller_unregister(&ltransport->accept_poller);
  spdk_laminar_ctx_close(&ltransport->listen_context);
  free(ltransport);

  if (cb_fn) {
    cb_fn(cb_arg);
  }
  return 0;
}

static int
nvmf_laminar_listen(struct spdk_nvmf_transport *transport, const struct spdk_nvme_transport_id *trid,
    struct spdk_nvmf_listen_opts *listen_opts)
{
  struct spdk_nvmf_laminar_transport *ltransport;
  struct spdk_nvmf_laminar_port *port;
  int trsvcid_int;

  if (!strlen(trid->trsvcid)) {
    SPDK_ERRLOG("Service id is required\n");
    return -EINVAL;
  }

  if (trid->adrfam != SPDK_NVMF_ADRFAM_IPV4) {
    SPDK_ERRLOG("Unhandled ADRFAM %d\n", trid->adrfam);
    return -EINVAL;
  }

  ltransport = SPDK_CONTAINEROF(transport, struct spdk_nvmf_laminar_transport, transport);

  trsvcid_int = nvmf_laminar_trsvcid_to_int(trid->trsvcid);
  if (trsvcid_int < 0) {
    SPDK_ERRLOG("Invalid trsvcid '%s'\n", trid->trsvcid);
    return -EINVAL;
  }

  port = calloc(1, sizeof(*port));
  if (!port) {
    SPDK_ERRLOG("Port allocation failed\n");
    return -ENOMEM;
  }

  port->transport = transport;
  port->trid = trid;

  if (laminar_listen_open(ltransport->listen_context->ctx,
    &port->listener, htons(trsvcid_int),
    ltransport->laminar_opts.acceptor_backlog, 0, (uint64_t) port) != 0) {
    SPDK_ERRLOG("laminar_listen_open() failed: %d\n", trsvcid_int);
    free(port);
    return -EIO;
  }

  SPDK_NOTICELOG("*** NVMe/Laminar Target Listening on %s port %s ***\n",
    trid->traddr, trid->trsvcid);

  TAILQ_INSERT_TAIL(&ltransport->ports, port, link);
  return 0;
}

static void
nvmf_laminar_stop_listen(struct spdk_nvmf_transport *transport,
    const struct spdk_nvme_transport_id *trid)
{
  struct spdk_nvmf_laminar_transport *ltransport;
  struct spdk_nvmf_laminar_port *port;

  ltransport = SPDK_CONTAINEROF(transport, struct spdk_nvmf_laminar_transport, transport);

  port = nvmf_laminar_find_port(ltransport, trid);
  if (port) {
    laminar_listen_close(ltransport->listen_context->ctx, port->listener);
    TAILQ_REMOVE(&ltransport->ports, port, link);
    free(port);
  }
}

static void
nvmf_laminar_discover(struct spdk_nvmf_transport *transport,
          struct spdk_nvme_transport_id *trid,
          struct spdk_nvmf_discovery_log_page_entry *entry)
{
  struct spdk_nvmf_laminar_port *port;
  struct spdk_nvmf_laminar_transport *ltransport;

#if 0
  /* XXX: Should this be TCP? */
  entry->trtype = SPDK_NVMF_TRTYPE_LAMINAR;
#else
  entry->trtype = SPDK_NVMF_TRTYPE_TCP;
#endif
  entry->adrfam = trid->adrfam;
  entry->treq.secure_channel = SPDK_NVMF_TREQ_SECURE_CHANNEL_NOT_REQUIRED;
  entry->tsas.tcp.sectype = SPDK_NVME_TCP_SECURITY_NONE;

  spdk_strcpy_pad(entry->trsvcid, trid->trsvcid, sizeof(entry->trsvcid), ' ');
  spdk_strcpy_pad(entry->traddr, trid->traddr, sizeof(entry->traddr), ' ');

  ltransport = SPDK_CONTAINEROF(transport, struct spdk_nvmf_laminar_transport, transport);
  port = nvmf_laminar_find_port(ltransport, trid);

  assert(port != NULL);
}

static struct spdk_nvmf_transport_poll_group *
nvmf_laminar_poll_group_create(struct spdk_nvmf_transport *transport,
                struct spdk_nvmf_poll_group *group)
{
  struct spdk_nvmf_laminar_transport  *ltransport;
  struct spdk_nvmf_laminar_poll_group *lgroup;

  ltransport = SPDK_CONTAINEROF(transport, struct spdk_nvmf_laminar_transport, transport);

  lgroup = calloc(1, sizeof(*lgroup));
  if (!lgroup) {
    return NULL;
  }

  lgroup->context = spdk_laminar_ctx_create(
      ltransport->laminar_opts.poll_batch_size, lgroup);
  if (lgroup->context == NULL) {
    goto cleanup;
  }

  TAILQ_INIT(&lgroup->qpairs);

  if (transport->opts.in_capsule_data_size < SPDK_NVME_TCP_IN_CAPSULE_DATA_MAX_SIZE) {
    SPDK_DEBUGLOG(laminar, "ICD %u is less than min required for admin/fabric commands (%u). "
      "Creating control messages list\n", transport->opts.in_capsule_data_size,
      SPDK_NVME_TCP_IN_CAPSULE_DATA_MAX_SIZE);
    /* FIXME: Create control msg list. */
    goto cleanup;
  }

  TAILQ_INSERT_TAIL(&ltransport->poll_groups, lgroup, link);
  if (ltransport->next_pg == NULL) {
    ltransport->next_pg = lgroup;
  }

  return &lgroup->group;

cleanup:
  nvmf_laminar_poll_group_destroy(&lgroup->group);
  return NULL;
}

static struct spdk_nvmf_transport_poll_group *
nvmf_laminar_get_optimal_poll_group(struct spdk_nvmf_qpair *qpair)
{
  struct spdk_nvmf_laminar_transport *ltransport;
  struct spdk_nvmf_laminar_poll_group **pg;
  struct spdk_nvmf_transport_poll_group *group;

  ltransport = SPDK_CONTAINEROF(qpair->transport, struct spdk_nvmf_laminar_transport, transport);

  if (TAILQ_EMPTY(&ltransport->poll_groups)) {
    return NULL;
  }

  /* Assign poll groups in rr-order. */
  pg = &ltransport->next_pg;
  assert(*pg != NULL);
  group = &((*pg)->group);

  *pg = TAILQ_NEXT(*pg, link);
  if (*pg == NULL) {
    *pg = TAILQ_FIRST(&ltransport->poll_groups);
  }

  return group;
}

static void
nvmf_laminar_poll_group_destroy(struct spdk_nvmf_transport_poll_group *group)
{
  struct spdk_nvmf_laminar_poll_group *lgroup, *next_lgroup;
  struct spdk_nvmf_laminar_transport *ltransport;

  lgroup = SPDK_CONTAINEROF(group, struct spdk_nvmf_laminar_poll_group, group);

  spdk_laminar_ctx_close(&lgroup->context);

  if (lgroup->group.transport == NULL) {
    /* Transport can be NULL when nvmf_laminar_poll_group_create()
     * calls this function directly in a failure path.
     */
    free(lgroup);
    return;
  }

  ltransport = SPDK_CONTAINEROF(lgroup->group.transport, struct spdk_nvmf_laminar_transport, transport);

  next_lgroup = TAILQ_NEXT(lgroup, link);
  TAILQ_REMOVE(&ltransport->poll_groups, lgroup, link);
  if (next_lgroup == NULL) {
    next_lgroup = TAILQ_FIRST(&ltransport->poll_groups);
  }
  if (ltransport->next_pg == lgroup) {
    ltransport->next_pg = next_lgroup;
  }

  free(lgroup);
}

static int
nvmf_laminar_poll_group_add(struct spdk_nvmf_transport_poll_group *group,
                struct spdk_nvmf_qpair *qpair)
{
  struct spdk_nvmf_laminar_poll_group *lgroup;
  struct spdk_nvmf_laminar_qpair *lqpair;
  int rc;

  lgroup = SPDK_CONTAINEROF(group, struct spdk_nvmf_laminar_poll_group, group);
  lqpair = SPDK_CONTAINEROF(qpair, struct spdk_nvmf_laminar_qpair, qpair);

  rc = nvmf_laminar_qpair_init(&lqpair->qpair);
  if (rc < 0) {
    SPDK_ERRLOG("Cannot init lqpair=%p\n", lqpair);
    return -1;
  }

  rc = nvmf_laminar_qpair_init_mem_resource(lqpair);
  if (rc < 0) {
    SPDK_ERRLOG("Cannot init memory resource info for lqpair=%p\n", lqpair);
    return -1;
  }

  rc = laminar_connection_move(lgroup->context->ctx, lqpair->conn);
  if (rc < 0) {
    SPDK_ERRLOG("Could not add qpair to pollgroup: (%d)\n", rc);
    return -1;
  }

  /* FIXME: Mark connection as move in progress. */
  lqpair->group = lgroup;
  nvmf_laminar_qpair_set_state(lqpair, NVMF_LAMINAR_QPAIR_STATE_INVALID);
  TAILQ_INSERT_TAIL(&lgroup->qpairs, lqpair, link);
  return 0;
}

static int
nvmf_laminar_poll_group_remove(struct spdk_nvmf_transport_poll_group *group,
                      struct spdk_nvmf_qpair *qpair)
{
  SPDK_ERRLOG("Removing connection from poll group not supported.");
  return -ENOTSUP;
}

static int
nvmf_laminar_poll_group_poll(struct spdk_nvmf_transport_poll_group *group)
{
  struct spdk_nvmf_laminar_poll_group *lgroup;
  struct spdk_laminar_ctx *lctx;
  struct laminar_event *ev;
  struct spdk_nvmf_laminar_qpair *lqpair;
  int num_events;
  int rc;
  int i;

  lgroup = SPDK_CONTAINEROF(group, struct spdk_nvmf_laminar_poll_group, group);
  lctx = lgroup->context;

  if (spdk_unlikely(TAILQ_EMPTY(&lgroup->qpairs))) {
    return 0;
  }

  rc = laminar_context_poll(lctx->ctx, lctx->n_events, lctx->ev_buffer, &num_events);
  if (spdk_unlikely(rc < 0)) {
    SPDK_ERRLOG("Failed to poll context=%p\n", lctx);
    return rc;
  }

  for (i = 0; i < num_events; i++) {
    ev = &lctx->ev_buffer[i];

    switch (ev->type) {
    case LAMINAR_EV_CONN_MOVED:
      if (spdk_unlikely(ev->return_code != 0)) {
        SPDK_ERRLOG("Failed to move qpair to poll group=%p\n", lctx);
        continue;
      }
      lqpair = (struct spdk_nvmf_laminar_qpair *) laminar_connection_opaque(ev->conn_moved.conn);
      nvmf_laminar_qpair_set_state(lqpair, NVMF_LAMINAR_QPAIR_STATE_MOVED);
      break;

    case LAMINAR_EV_CONN_CLOSED:
      lqpair = (struct spdk_nvmf_laminar_qpair *) laminar_connection_opaque(ev->conn_closed.conn);
      nvmf_laminar_qpair_destroy(lqpair);
      break;

    case LAMINAR_EV_CONN_RXCLOSED:
    case LAMINAR_EV_CONN_TXCLOSED:
      lqpair = (struct spdk_nvmf_laminar_qpair *) laminar_connection_opaque(ev->conn_closed.conn);
      nvmf_laminar_qpair_disconnect(lqpair);
      break;

    case LAMINAR_EV_CONN_RECEIVED:
      lqpair = (struct spdk_nvmf_laminar_qpair *) laminar_connection_opaque(ev->conn_received.conn);
      nvmf_laminar_qpair_receive_process(lgroup, lqpair, ev->return_code, ev->conn_received.buf, ev->conn_received.len);
      break;

    case LAMINAR_EV_CONN_SENDBUF:
      lqpair = (struct spdk_nvmf_laminar_qpair *) laminar_connection_opaque(ev->conn_received.conn);
      nvmf_laminar_qpair_send_process(lgroup, lqpair, ev->return_code);
      break;

    default:
      SPDK_ERRLOG("received unknown event (%d) on poll group: %p\n",
                  ev->type, lctx);
      break;
    }
  }

  return num_events;
}

static int
nvmf_laminar_req_free(struct spdk_nvmf_request *req)
{
  struct spdk_nvmf_tcp_req *tcp_req = SPDK_CONTAINEROF(req, struct spdk_nvmf_tcp_req, req);

  nvmf_tcp_request_free(tcp_req);

  return 0;
}

static int
nvmf_laminar_req_complete(struct spdk_nvmf_request *req)
{
  struct spdk_nvmf_laminar_transport *ltransport;
  struct spdk_nvmf_tcp_req *tcp_req;

  ltransport = SPDK_CONTAINEROF(req->qpair->transport, struct spdk_nvmf_laminar_transport, transport);
  tcp_req = SPDK_CONTAINEROF(req, struct spdk_nvmf_tcp_req, req);

  switch (tcp_req->state) {
  case TCP_REQUEST_STATE_EXECUTING:
    nvmf_tcp_req_set_state(tcp_req, TCP_REQUEST_STATE_EXECUTED);
    break;
  default:
    SPDK_ERRLOG("Unexpected request state %d (cntlid:%d, qid:%d)\n",
          tcp_req->state, req->qpair->ctrlr->cntlid, req->qpair->qid);
    assert(0 && "Unexpected request state");
    break;
  }

  nvmf_tcp_req_process(ltransport, tcp_req);

  return 0;
}

static int
nvmf_laminar_qpair_get_trid(struct spdk_nvmf_qpair *qpair,
          struct spdk_nvme_transport_id *trid, bool peer)
{
  struct spdk_nvmf_laminar_qpair *lqpair;
  uint16_t port;

  lqpair = SPDK_CONTAINEROF(qpair, struct spdk_nvmf_laminar_qpair, qpair);
  spdk_nvme_trid_populate_transport(trid, SPDK_NVME_TRANSPORT_LAMINAR);

  if (peer) {
    snprintf(trid->traddr, sizeof(trid->traddr), "%s", lqpair->initiator_addr);
    port = lqpair->initiator_port;
  } else {
    snprintf(trid->traddr, sizeof(trid->traddr), "%s", lqpair->target_addr);
    port = lqpair->target_port;
  }

  trid->adrfam = SPDK_NVMF_ADRFAM_IPV4;

  snprintf(trid->trsvcid, sizeof(trid->trsvcid), "%d", port);
  return 0;
}

static int
nvmf_laminar_qpair_get_local_trid(struct spdk_nvmf_qpair *qpair,
            struct spdk_nvme_transport_id *trid)
{
  return nvmf_laminar_qpair_get_trid(qpair, trid, 0);
}

static int
nvmf_laminar_qpair_get_peer_trid(struct spdk_nvmf_qpair *qpair,
           struct spdk_nvme_transport_id *trid)
{
  return nvmf_laminar_qpair_get_trid(qpair, trid, 1);
}

static int
nvmf_laminar_qpair_get_listen_trid(struct spdk_nvmf_qpair *qpair,
             struct spdk_nvme_transport_id *trid)
{
  return nvmf_laminar_qpair_get_trid(qpair, trid, 0);
}

const struct spdk_nvmf_transport_ops spdk_nvmf_transport_laminar = {
  .name = "LAMINAR",
  .type = SPDK_NVME_TRANSPORT_LAMINAR,
  .opts_init = nvmf_laminar_opts_init,
  .create = nvmf_laminar_create,
  .dump_opts = nvmf_laminar_dump_opts,
  .destroy = nvmf_laminar_destroy,

  .listen = nvmf_laminar_listen,
  .stop_listen = nvmf_laminar_stop_listen,

  .listener_discover = nvmf_laminar_discover,

  .poll_group_create = nvmf_laminar_poll_group_create,
  .get_optimal_poll_group = nvmf_laminar_get_optimal_poll_group,
  .poll_group_destroy = nvmf_laminar_poll_group_destroy,
  .poll_group_add = nvmf_laminar_poll_group_add,
  .poll_group_remove = nvmf_laminar_poll_group_remove,
  .poll_group_poll = nvmf_laminar_poll_group_poll,

  .req_free = nvmf_laminar_req_free,
  .req_complete = nvmf_laminar_req_complete,

  .qpair_fini = NULL,
  .qpair_get_local_trid = nvmf_laminar_qpair_get_local_trid,
  .qpair_get_peer_trid = nvmf_laminar_qpair_get_peer_trid,
  .qpair_get_listen_trid = nvmf_laminar_qpair_get_listen_trid,
  .qpair_abort_request = NULL,
  .subsystem_add_host = NULL,
  .subsystem_remove_host = NULL,
  .subsystem_dump_host = NULL,

  .poll_group_dump_stat = NULL,
};

SPDK_NVMF_TRANSPORT_REGISTER(laminar, &spdk_nvmf_transport_laminar);
SPDK_LOG_REGISTER_COMPONENT(laminar)

