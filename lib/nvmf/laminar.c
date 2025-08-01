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

enum nvmf_laminar_qpair_state {
  NVMF_LAMINAR_QPAIR_STATE_INVALID = 0,
  NVMF_LAMINAR_QPAIR_STATE_MOVED = 1,
  NVMF_LAMINAR_QPAIR_STATE_INITIALIZING = 2,
  NVMF_LAMINAR_QPAIR_STATE_RUNNING = 3,
  NVMF_LAMINAR_QPAIR_STATE_EXITING = 4,
  NVMF_LAMINAR_QPAIR_STATE_EXITED = 5,
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
	SLIST_HEAD(, nvme_tcp_pdu)		tcp_pdu_free_queue;
	/* Number of working pdus */
	uint32_t				tcp_pdu_working_count;

  uint8_t         cpda;
  bool            host_hdgst_enable;
  bool            host_ddgst_enable;

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
      strncpy(lqpair->initiator_addr,
        inet_ntoa(addr), sizeof(lqpair->initiator_addr) - 1);
      laminar_connection_localaddr(conn, &addr.s_addr, &p);
      strncpy(lqpair->target_addr,
        inet_ntoa(addr), sizeof(lqpair->target_addr) - 1);
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

  /* TODO: Not yet implemented. */
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

  SPDK_DEBUGLOG(laminar, "lqpair(%p) recv state=%d\n", tqpair, state);
  lqpair->recv_state = state;

}

static void
nvmf_laminar_send_c2h_term_req(struct spdk_nvmf_laminar_qpair *tqpair,
         struct nvme_tcp_pdu *pdu,
			   enum spdk_nvme_tcp_term_req_fes fes, uint32_t error_offset)
{
  assert(false);
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

static void
nvmf_laminar_qpair_receive_process(
        struct spdk_nvmf_laminar_poll_group *lgroup,
        struct spdk_nvmf_laminar_qpair *lqpair,
        int return_code, void *buf, size_t len)
{
#if 0
  int rc = 0;
  struct nvme_tcp_pdu *pdu;
  enum nvme_tcp_pdu_recv_state prev_state;
  uint32_t data_len;
  uint32_t read_len;
  struct spdk_nvmf_laminar_transport *ltransport = SPDK_CONTAINEROF(lqpair->qpair.transport,
      struct spdk_nvmf_laminar_transport, transport);

  /* The loop here is to allow for several back-to-back state changes. */
  do {
    /* No more data to process. */
    if (len == 0)
      return;

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
        nvmf_laminar_qpair_set_recv_state(tqpair, NVME_TCP_PDU_RECV_STATE_QUIESCING);
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
    }
  } while (lqpair->recv_state != prev_state);
#endif
  assert(false);
}

static void
nvmf_laminar_qpair_send_process(
  struct spdk_nvmf_laminar_poll_group *lgroup,
  struct spdk_nvmf_laminar_qpair *lqpair,
  int return_code)
{
  assert(false);
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

  /* XXX: Should this be TCP? */
  entry->trtype = SPDK_NVMF_TRTYPE_LAMINAR;
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

  .req_free = NULL,
  .req_complete = NULL,

  .qpair_fini = NULL,
  .qpair_get_peer_trid = NULL,
  .qpair_get_local_trid = NULL,
  .qpair_get_listen_trid = NULL,
  .qpair_abort_request = NULL,

  .poll_group_dump_stat = NULL,
};

SPDK_NVMF_TRANSPORT_REGISTER(laminar, &spdk_nvmf_transport_laminar);
SPDK_LOG_REGISTER_COMPONENT(laminar)

