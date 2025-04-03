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

const struct spdk_nvmf_transport_ops spdk_nvmf_transport_laminar = {
	.name = "Laminar",
	.type = SPDK_NVME_TRANSPORT_LAMINAR,
	.opts_init = NULL,
	.create = NULL,
	.dump_opts = NULL,
	.destroy = NULL,

	.listen = NULL,
	.stop_listen = NULL,
	.cdata_init = NULL,

	.listener_discover = NULL,

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

