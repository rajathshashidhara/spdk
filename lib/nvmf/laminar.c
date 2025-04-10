/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2016 Intel Corporation. All rights reserved.
 *   Copyright (c) 2019-2021 Mellanox Technologies LTD. All rights reserved.
 *   Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "spdk/stdinc.h"

#include "spdk/config.h"
#include "spdk/thread.h"
#include "spdk/likely.h"
#include "spdk/nvmf_transport.h"
#include "spdk/string.h"
#include "spdk/trace.h"
#include "spdk/tree.h"
#include "spdk/util.h"

#include "spdk_internal/assert.h"
#include "spdk/log.h"

#include "nvmf_internal.h"
#include "transport.h"

#include "switchtoe.h"

const struct spdk_nvmf_transport_ops spdk_nvmf_transport_laminar;

struct spdk_laminar_ctx {
	struct switchtoe_context *ctx;
	struct switchtoe_event   *ev_buffer;
	uint32_t n_events;
};

struct spdk_nvmf_laminar_qpair {
	struct spdk_nvmf_qpair				qpair;
	struct spdk_nvmf_laminar_poll_group	*group;
};

struct spdk_nvmf_laminar_poll_group {
	struct spdk_nvmf_transport_poll_group 		group;
	struct spdk_laminar_ctx						*context;

	TAILQ_HEAD(, spdk_nvmf_laminar_qpair)		qpairs;
	TAILQ_ENTRY(spdk_nvmf_laminar_poll_group)	link;
};

struct spdk_nvmf_laminar_port {
	const struct spdk_nvme_transport_id *trid;
	struct switchtoe_listener *listener;
	struct spdk_nvmf_transport *transport;
	int success;
	TAILQ_ENTRY(spdk_nvmf_laminar_port)		link;
};

struct laminar_transport_opts {
	uint32_t poll_batch_size;
	uint32_t acceptor_backlog;
};

struct spdk_nvmf_laminar_transport {
	struct spdk_nvmf_transport	transport;
	struct laminar_transport_opts laminar_opts;

	struct spdk_poller 			   *accept_poller;
	struct spdk_laminar_ctx 	   *listen_context;

	TAILQ_HEAD(, spdk_nvmf_laminar_port) ports;
	TAILQ_HEAD(, spdk_nvmf_laminar_poll_group)	poll_groups;
};

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

	if (switchtoe_context_create(&context->ctx, (uint64_t) opaque) != 0) {
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
	SPDK_ERRLOG("Laminar context close not implemented.");

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

	ltransport = SPDK_CONTAINEROF(transport, struct spdk_nvmf_laminar_transport, transport);

	/* TODO: Poll the context. */
	(void) ltransport;

	/* TODO: Return the result of poll. */
	return SPDK_POLLER_IDLE;
}

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

/* Public API callbacks begin here */
#define SPDK_NVMF_LAMINAR_DEFAULT_MAX_IO_QUEUE_DEPTH 128
#define SPDK_NVMF_LAMINAR_DEFAULT_MAX_ADMIN_QUEUE_DEPTH 128
#define SPDK_NVMF_LAMINAR_DEFAULT_MAX_QPAIRS_PER_CTRLR 128
#define SPDK_NVMF_LAMINAR_DEFAULT_IN_CAPSULE_DATA_SIZE 4096
#define SPDK_NVMF_LAMINAR_DEFAULT_MAX_IO_SIZE 131072
#define SPDK_NVMF_LAMINAR_DEFAULT_IO_UNIT_SIZE 131072
#define SPDK_NVMF_LAMINAR_DEFAULT_NUM_SHARED_BUFFERS 511
#define SPDK_NVMF_LAMINAR_DEFAULT_BUFFER_CACHE_SIZE UINT32_MAX
#define SPDK_NVMF_LAMINAR_DEFAULT_DIF_INSERT_OR_STRIP false
#define SPDK_NVMF_LAMINAR_DEFAULT_ABORT_TIMEOUT_SEC 1
#define SPDK_NVMF_LAMINAR_DEFAULT_POLL_BATCH_SIZE 32
#define SPDK_NVMF_LAMINAR_ACCEPTOR_BACKLOG 32

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

	if (switchtoe_init()) {
		SPDK_ERRLOG("failed to initialize laminar\n");
		return NULL;
	}

	ltransport = calloc(1, sizeof(*ltransport));
	if (!ltransport) {
		return NULL;
	}

	TAILQ_INIT(&ltransport->poll_groups);
	
	ltransport->transport.ops = &spdk_nvmf_transport_laminar;
	ltransport->laminar_opts.acceptor_backlog = SPDK_NVMF_LAMINAR_ACCEPTOR_BACKLOG;
	ltransport->laminar_opts.poll_batch_size = SPDK_NVMF_LAMINAR_DEFAULT_POLL_BATCH_SIZE;

	SPDK_NOTICELOG("*** Laminar Transport Init ***\n");
	SPDK_INFOLOG(rdma, "*** Laminar Transport Init ***\n"
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

	ltransport->listen_context = spdk_laminar_ctx_create(
		ltransport->laminar_opts.poll_batch_size, NULL);
	if (ltransport->listen_context == NULL) {
		SPDK_ERRLOG("Failed to create context for listen sockets\n");
		free(ltransport);
		return NULL;
	}

	ltransport->accept_poller = SPDK_POLLER_REGISTER(nvmf_laminar_accept_poll, &ltransport->transport,
		opts->acceptor_poll_rate);
	if (!ltransport->accept_poller) {
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
	struct spdk_nvmf_laminar_transport	*ltransport;

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
	port->success = 0; 	/* async: do not wait for it to finish. */

	if (switchtoe_listen_open(ltransport->listen_context->ctx,
		&port->listener, htons(trsvcid_int),
		ltransport->laminar_opts.acceptor_backlog, 0, (uint64_t) port) != 0) {
		SPDK_ERRLOG("switchtoe_listen_open() failed: %d\n", trsvcid_int);
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
	ltransport = SPDK_CONTAINEROF(transport, struct spdk_nvmf_laminar_transport, transport);

	(void) ltransport;
	SPDK_ERRLOG("Removing listen address %s port %s not yet implemented\n",
		      	trid->traddr, trid->trsvcid);
}

static void
nvmf_laminar_discover(struct spdk_nvmf_transport *transport,
					struct spdk_nvme_transport_id *trid,
					struct spdk_nvmf_discovery_log_page_entry *entry)
{}

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

	.poll_group_create = NULL,
	.get_optimal_poll_group = NULL,
	.poll_group_destroy = NULL,
	.poll_group_add = NULL,
	.poll_group_remove = NULL,
	.poll_group_poll = NULL,

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

