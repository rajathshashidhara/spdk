#include "spdk/stdinc.h"

#include "spdk/env.h"
#include "spdk/log.h"
#include "spdk/pipe.h"
#include "spdk/sock.h"
#include "spdk/util.h"
#include "spdk/string.h"
#include "spdk/net.h"
#include "spdk/file.h"
#include "spdk_internal/sock.h"
#include "spdk/net.h"

#include "sockets.h"

#define MAX_TMPBUF 1024
#define PORTNUMLEN 32

struct spdk_laminar_sock {
	struct spdk_sock	base;
	int			fd;

	uint32_t		sendmsg_idx;

	struct spdk_pipe	*recv_pipe;
	int			recv_buf_sz;
	bool			pipe_has_data;
	bool			socket_has_data;

	int			placement_id;

	TAILQ_ENTRY(spdk_laminar_sock)	link;

	char			interface_name[IFNAMSIZ];
};

TAILQ_HEAD(spdk_has_data_list, spdk_laminar_sock);

struct spdk_laminar_sock_group_impl {
	struct spdk_sock_group_impl	base;
	int				fd;
	struct spdk_interrupt		*intr;
	struct spdk_has_data_list	socks_with_data;
	int				placement_id;
	struct spdk_pipe_group		*pipe_group;
};

static struct spdk_sock_impl_opts g_laminar_impl_opts = {
	.recv_buf_size = DEFAULT_SO_RCVBUF_SIZE,
	.send_buf_size = DEFAULT_SO_SNDBUF_SIZE,
	.enable_recv_pipe = true,
	.enable_placement_id = PLACEMENT_NONE,
};

static struct spdk_sock_map g_map = {
	.entries = STAILQ_HEAD_INITIALIZER(g_map.entries),
	.mtx = PTHREAD_MUTEX_INITIALIZER
};

__attribute((destructor)) static void
laminar_sock_map_cleanup(void)
{
	spdk_sock_map_cleanup(&g_map);
}

#define __laminar_sock(sock) (struct spdk_laminar_sock *)sock
#define __laminar_group_impl(group) (struct spdk_laminar_sock_group_impl *)group

static void
laminar_sock_copy_impl_opts(struct spdk_sock_impl_opts *dest, const struct spdk_sock_impl_opts *src,
			  size_t len)
{
#define FIELD_OK(field) \
	offsetof(struct spdk_sock_impl_opts, field) + sizeof(src->field) <= len

#define SET_FIELD(field) \
	if (FIELD_OK(field)) { \
		dest->field = src->field; \
	}

	SET_FIELD(recv_buf_size);
	SET_FIELD(send_buf_size);
	SET_FIELD(enable_recv_pipe);
	SET_FIELD(enable_placement_id);

#undef SET_FIELD
#undef FIELD_OK
}

static int
laminar_sock_impl_get_opts(struct spdk_sock_impl_opts *opts, size_t *len)
{
	if (!opts || !len) {
		errno = EINVAL;
		return -1;
	}

	assert(sizeof(*opts) >= *len);
	memset(opts, 0, *len);

	laminar_sock_copy_impl_opts(opts, &g_laminar_impl_opts, *len);
	*len = spdk_min(*len, sizeof(g_laminar_impl_opts));

	return 0;
}

static int
laminar_sock_impl_set_opts(const struct spdk_sock_impl_opts *opts, size_t len)
{
	if (!opts) {
		errno = EINVAL;
		return -1;
	}

	assert(sizeof(*opts) >= len);
	laminar_sock_copy_impl_opts(&g_laminar_impl_opts, opts, len);

	return 0;
}

static void
laminar_opts_get_impl_opts(const struct spdk_sock_opts *opts, struct spdk_sock_impl_opts *dest)
{
	/* Copy the default impl_opts first to cover cases when user's impl_opts is smaller */
	memcpy(dest, &g_laminar_impl_opts, sizeof(*dest));

	if (opts->impl_opts != NULL) {
		assert(sizeof(*dest) >= opts->impl_opts_size);
		laminar_sock_copy_impl_opts(dest, opts->impl_opts, opts->impl_opts_size);
	}
}

static int
laminar_net_getaddr(int fd, char *laddr, int llen, uint16_t *lport,
		 char *paddr, int plen, uint16_t *pport)
{
	struct sockaddr_storage sa;
	int val;
	socklen_t len;
	int rc;

	memset(&sa, 0, sizeof(sa));
	len = sizeof(sa);
	rc = laminar_getsockname(fd, (struct sockaddr *)&sa, &len);
	if (rc != 0) {
		SPDK_ERRLOG("getsockname() failed (errno=%d)\n", errno);
		return -1;
	}

	switch (sa.ss_family) {
	case AF_UNIX:
		/* Acceptable connection types that don't have IPs */
		return 0;
	case AF_INET:
	case AF_INET6:
		/* Code below will get IP addresses */
		break;
	default:
		/* Unsupported socket family */
		return -1;
	}

	if (laddr) {
		rc = spdk_net_get_address_string((struct sockaddr *)&sa, laddr, llen);
		if (rc != 0) {
			SPDK_ERRLOG("spdk_net_get_address_string() failed (errno=%d)\n", rc);
			return -1;
		}
	}

	if (lport) {
		if (sa.ss_family == AF_INET) {
			*lport = ntohs(((struct sockaddr_in *)&sa)->sin_port);
		} else if (sa.ss_family == AF_INET6) {
			*lport = ntohs(((struct sockaddr_in6 *)&sa)->sin6_port);
		}
	}

	len = sizeof(val);
	rc = laminar_getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &val, &len);
	if (rc == 0 && val == 1) {
		/* It is an error to getaddr for a peer address on a listen socket. */
		if (paddr != NULL || pport != NULL) {
			SPDK_ERRLOG("paddr, pport not valid on listen sockets\n");
			return -1;
		}
		return 0;
	}

	memset(&sa, 0, sizeof(sa));
	len = sizeof(sa);
	rc = laminar_getpeername(fd, (struct sockaddr *)&sa, &len);
	if (rc != 0) {
		SPDK_ERRLOG("getpeername() failed (errno=%d)\n", errno);
		return -1;
	}

	if (paddr) {
		rc = spdk_net_get_address_string((struct sockaddr *)&sa, paddr, plen);
		if (rc != 0) {
			SPDK_ERRLOG("spdk_net_get_address_string() failed (errno=%d)\n", rc);
			return -1;
		}
	}

	if (pport) {
		if (sa.ss_family == AF_INET) {
			*pport = ntohs(((struct sockaddr_in *)&sa)->sin_port);
		} else if (sa.ss_family == AF_INET6) {
			*pport = ntohs(((struct sockaddr_in6 *)&sa)->sin6_port);
		}
	}

	return 0;
}


static int
laminar_sock_getaddr(struct spdk_sock *_sock, char *saddr, int slen, uint16_t *sport,
		   char *caddr, int clen, uint16_t *cport)
{
	struct spdk_laminar_sock *sock = __laminar_sock(_sock);

	assert(sock != NULL);
	return laminar_net_getaddr(sock->fd, saddr, slen, sport, caddr, clen, cport);
}

static const char *
laminar_sock_get_interface_name(struct spdk_sock *_sock)
{
	struct spdk_laminar_sock *sock = __laminar_sock(_sock);
	char saddr[64];
	int rc;

	rc = laminar_net_getaddr(sock->fd, saddr, sizeof(saddr), NULL, NULL, 0, NULL);
	if (rc != 0) {
		return NULL;
	}

	rc = spdk_net_get_interface_name(saddr, sock->interface_name,
					 sizeof(sock->interface_name));
	if (rc != 0) {
		return NULL;
	}

	return sock->interface_name;
}

static int32_t
laminar_sock_get_numa_id(struct spdk_sock *sock)
{
	const char *interface_name;
	uint32_t numa_id;
	int rc;

	interface_name = laminar_sock_get_interface_name(sock);
	if (interface_name == NULL) {
		return SPDK_ENV_NUMA_ID_ANY;
	}

	rc = spdk_read_sysfs_attribute_uint32(&numa_id,
					      "/sys/class/net/%s/device/numa_node", interface_name);
	if (rc == 0 && numa_id <= INT32_MAX) {
		return (int32_t)numa_id;
	} else {
		return SPDK_ENV_NUMA_ID_ANY;
	}
}

enum laminar_sock_create_type {
	SPDK_SOCK_CREATE_LISTEN,
	SPDK_SOCK_CREATE_CONNECT,
};

static int
laminar_sock_alloc_pipe(struct spdk_laminar_sock *sock, int sz)
{
	uint8_t *new_buf, *old_buf;
	struct spdk_pipe *new_pipe;
	struct iovec siov[2];
	struct iovec diov[2];
	int sbytes;
	ssize_t bytes;
	int rc;

	if (sock->recv_buf_sz == sz) {
		return 0;
	}

	/* If the new size is 0, just free the pipe */
	if (sz == 0) {
		old_buf = spdk_pipe_destroy(sock->recv_pipe);
		free(old_buf);
		sock->recv_pipe = NULL;
		return 0;
	} else if (sz < MIN_SOCK_PIPE_SIZE) {
		SPDK_ERRLOG("The size of the pipe must be larger than %d\n", MIN_SOCK_PIPE_SIZE);
		return -1;
	}

	/* Round up to next 64 byte multiple */
	rc = posix_memalign((void **)&new_buf, 64, sz);
	if (rc != 0) {
		SPDK_ERRLOG("socket recv buf allocation failed\n");
		return -ENOMEM;
	}
	memset(new_buf, 0, sz);

	new_pipe = spdk_pipe_create(new_buf, sz);
	if (new_pipe == NULL) {
		SPDK_ERRLOG("socket pipe allocation failed\n");
		free(new_buf);
		return -ENOMEM;
	}

	if (sock->recv_pipe != NULL) {
		/* Pull all of the data out of the old pipe */
		sbytes = spdk_pipe_reader_get_buffer(sock->recv_pipe, sock->recv_buf_sz, siov);
		if (sbytes > sz) {
			/* Too much data to fit into the new pipe size */
			old_buf = spdk_pipe_destroy(new_pipe);
			free(old_buf);
			return -EINVAL;
		}

		sbytes = spdk_pipe_writer_get_buffer(new_pipe, sz, diov);
		assert(sbytes == sz);

		bytes = spdk_iovcpy(siov, 2, diov, 2);
		spdk_pipe_writer_advance(new_pipe, bytes);

		old_buf = spdk_pipe_destroy(sock->recv_pipe);
		free(old_buf);
	}

	sock->recv_buf_sz = sz;
	sock->recv_pipe = new_pipe;
	if (sock->base.group_impl) {
		struct spdk_laminar_sock_group_impl *group;

		group = __laminar_group_impl(sock->base.group_impl);
		spdk_pipe_group_add(group->pipe_group, sock->recv_pipe);
	}
	return 0;
}

static int
laminar_sock_set_recvbuf(struct spdk_sock *_sock, int sz)
{
	struct spdk_laminar_sock *sock = __laminar_sock(_sock);
	int min_size;
	int rc;

	assert(sock != NULL);

	if (_sock->impl_opts.enable_recv_pipe) {
		rc = laminar_sock_alloc_pipe(sock, sz);
		if (rc) {
			return rc;
		}
	}

	/* Set kernel buffer size to be at least MIN_SO_RCVBUF_SIZE and
	 * _sock->impl_opts.recv_buf_size. */
	min_size = spdk_max(MIN_SO_RCVBUF_SIZE, _sock->impl_opts.recv_buf_size);

	if (sz < min_size) {
		sz = min_size;
	}

	rc = laminar_setsockopt(sock->fd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
	if (rc < 0) {
		return rc;
	}

	_sock->impl_opts.recv_buf_size = sz;

	return 0;
}

static int
laminar_sock_set_sendbuf(struct spdk_sock *_sock, int sz)
{
	struct spdk_laminar_sock *sock = __laminar_sock(_sock);
	int min_size;
	int rc;

	assert(sock != NULL);

	/* Set kernel buffer size to be at least MIN_SO_SNDBUF_SIZE and
	 * _sock->impl_opts.send_buf_size. */
	min_size = spdk_max(MIN_SO_SNDBUF_SIZE, _sock->impl_opts.send_buf_size);

	if (sz < min_size) {
		sz = min_size;
	}

	rc = setsockopt(sock->fd, SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
	if (rc < 0) {
		return rc;
	}

	_sock->impl_opts.send_buf_size = sz;

	return 0;
}

static void
laminar_sock_init(struct spdk_laminar_sock *sock)
{
#if defined(__linux__)
	spdk_sock_get_placement_id(sock->fd, sock->base.impl_opts.enable_placement_id,
				   &sock->placement_id);

	if (sock->base.impl_opts.enable_placement_id == PLACEMENT_MARK) {
		/* Save placement_id */
		spdk_sock_map_insert(&g_map, sock->placement_id, NULL);
	}
#endif
}

static struct spdk_laminar_sock *
laminar_sock_alloc(int fd, struct spdk_sock_impl_opts *impl_opts)
{
	struct spdk_laminar_sock *sock;

	sock = calloc(1, sizeof(*sock));
	if (sock == NULL) {
		SPDK_ERRLOG("sock allocation failed\n");
		return NULL;
	}

	sock->fd = fd;
	memcpy(&sock->base.impl_opts, impl_opts, sizeof(*impl_opts));
	laminar_sock_init(sock);

	return sock;
}

static int
laminar_fd_create(struct addrinfo *res, struct spdk_sock_opts *opts,
		struct spdk_sock_impl_opts *impl_opts)
{
	int fd;
	int val = 1;
	int rc, sz;

	fd = laminar_socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (fd < 0) {
		/* error */
		return -1;
	}

	sz = impl_opts->recv_buf_size;
	rc = laminar_setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
	if (rc) {
		/* Not fatal */
	}

	sz = impl_opts->send_buf_size;
	rc = laminar_setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
	if (rc) {
		/* Not fatal */
	}

	rc = laminar_setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof val);
	if (rc != 0) {
		laminar_close(fd);
		/* error */
		return -1;
	}
	rc = laminar_setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof val);
	if (rc != 0) {
		laminar_close(fd);
		/* error */
		return -1;
	}

	if (res->ai_family == AF_INET6) {
		laminar_close(fd);
		return -1;
	}

	if (opts->ack_timeout) {
		SPDK_WARNLOG("TCP_USER_TIMEOUT is not supported.\n");
	}

	return fd;
}

static struct spdk_sock *
laminar_sock_create(const char *ip, int port,
		  enum laminar_sock_create_type type,
		  struct spdk_sock_opts *opts)
{
	struct spdk_laminar_sock *sock;
	struct spdk_sock_impl_opts impl_opts;
	char buf[MAX_TMPBUF];
	char portnum[PORTNUMLEN];
	char *p;
	const char *src_addr;
	uint16_t src_port;
	struct addrinfo hints, *res, *res0, *src_ai;
	int fd, flag;
	int rc;

	assert(opts != NULL);
	laminar_opts_get_impl_opts(opts, &impl_opts);

	if (ip == NULL) {
		return NULL;
	}
	if (ip[0] == '[') {
		snprintf(buf, sizeof(buf), "%s", ip + 1);
		p = strchr(buf, ']');
		if (p != NULL) {
			*p = '\0';
		}
		ip = (const char *) &buf[0];
	}

	snprintf(portnum, sizeof portnum, "%d", port);
	memset(&hints, 0, sizeof hints);
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICSERV;
	hints.ai_flags |= AI_PASSIVE;
	hints.ai_flags |= AI_NUMERICHOST;
	rc = getaddrinfo(ip, portnum, &hints, &res0);
	if (rc != 0) {
		SPDK_ERRLOG("getaddrinfo() failed %s (%d)\n", gai_strerror(rc), rc);
		return NULL;
	}

	/* try listen */
	fd = -1;
	for (res = res0; res != NULL; res = res->ai_next) {
retry:
		fd = laminar_fd_create(res, opts, &impl_opts);
		if (fd < 0) {
			continue;
		}
		if (type == SPDK_SOCK_CREATE_LISTEN) {
			rc = laminar_bind(fd, res->ai_addr, res->ai_addrlen);
			if (rc != 0) {
				SPDK_ERRLOG("bind() failed at port %d, errno = %d\n", port, errno);
				switch (errno) {
				case EINTR:
					/* interrupted? */
					laminar_close(fd);
					goto retry;
				case EADDRNOTAVAIL:
					SPDK_ERRLOG("IP address %s not available. "
						    "Verify IP address in config file "
						    "and make sure setup script is "
						    "run before starting spdk app.\n", ip);
				/* FALLTHROUGH */
				default:
					/* try next family */
					laminar_close(fd);
					fd = -1;
					continue;
				}
			}
			/* bind OK */
			rc = laminar_listen(fd, 512);
			if (rc != 0) {
				SPDK_ERRLOG("listen() failed, errno = %d\n", errno);
				laminar_close(fd);
				fd = -1;
				break;
			}
		} else if (type == SPDK_SOCK_CREATE_CONNECT) {
			src_addr = SPDK_GET_FIELD(opts, src_addr, NULL, opts->opts_size);
			src_port = SPDK_GET_FIELD(opts, src_port, 0, opts->opts_size);
			if (src_addr != NULL || src_port != 0) {
				snprintf(portnum, sizeof(portnum), "%"PRIu16, src_port);
				memset(&hints, 0, sizeof hints);
				hints.ai_family = AF_UNSPEC;
				hints.ai_socktype = SOCK_STREAM;
				hints.ai_flags = AI_NUMERICSERV | AI_NUMERICHOST | AI_PASSIVE;
				rc = getaddrinfo(src_addr, src_port > 0 ? portnum : NULL,
						 &hints, &src_ai);
				if (rc != 0 || src_ai == NULL) {
					SPDK_ERRLOG("getaddrinfo() failed %s (%d)\n",
						    rc != 0 ? gai_strerror(rc) : "", rc);
					laminar_close(fd);
					fd = -1;
					break;
				}
				rc = laminar_bind(fd, src_ai->ai_addr, src_ai->ai_addrlen);
				if (rc != 0) {
					SPDK_ERRLOG("bind() failed errno %d (%s:%s)\n", errno,
						    src_addr ? src_addr : "", portnum);
					laminar_close(fd);
					fd = -1;
					freeaddrinfo(src_ai);
					src_ai = NULL;
					break;
				}
				freeaddrinfo(src_ai);
				src_ai = NULL;
			}
			rc = laminar_connect(fd, res->ai_addr, res->ai_addrlen);
			if (rc != 0) {
				SPDK_ERRLOG("connect() failed, errno = %d\n", errno);
				/* try next family */
				laminar_close(fd);
				fd = -1;
				continue;
			}
		}

		flag = laminar_fcntl(fd, F_GETFL);
		if (laminar_fcntl(fd, F_SETFL, flag | O_NONBLOCK) < 0) {
			SPDK_ERRLOG("fcntl can't set nonblocking mode for socket, fd: %d (%d)\n", fd, errno);
			laminar_close(fd);
			fd = -1;
			break;
		}
		break;
	}
	freeaddrinfo(res0);

	if (fd < 0) {
		return NULL;
	}

	sock = laminar_sock_alloc(fd, &impl_opts);
	if (sock == NULL) {
		SPDK_ERRLOG("sock allocation failed\n");
		laminar_close(fd);
		return NULL;
	}

	return &sock->base;
}

static struct spdk_sock *
laminar_sock_listen(const char *ip, int port, struct spdk_sock_opts *opts)
{
	return laminar_sock_create(ip, port, SPDK_SOCK_CREATE_LISTEN, opts);
}

static struct spdk_sock *
laminar_sock_connect(const char *ip, int port, struct spdk_sock_opts *opts)
{
	return laminar_sock_create(ip, port, SPDK_SOCK_CREATE_CONNECT, opts);
}

static struct spdk_sock *
_laminar_sock_accept(struct spdk_sock *_sock)
{
	struct spdk_laminar_sock		*sock = __laminar_sock(_sock);
	struct spdk_laminar_sock_group_impl *group = __laminar_group_impl(sock->base.group_impl);
	struct sockaddr_storage		sa;
	socklen_t			salen;
	int				rc, fd;
	struct spdk_laminar_sock		*new_sock;
	int				flag;

	memset(&sa, 0, sizeof(sa));
	salen = sizeof(sa);

	assert(sock != NULL);

	/* epoll_wait will trigger again if there is more than one request */
	if (group && sock->socket_has_data) {
		sock->socket_has_data = false;
		TAILQ_REMOVE(&group->socks_with_data, sock, link);
	}

	rc = laminar_accept(sock->fd, (struct sockaddr *)&sa, &salen);

	if (rc == -1) {
		return NULL;
	}

	fd = rc;

	flag = laminar_fcntl(fd, F_GETFL);
	if ((!(flag & O_NONBLOCK)) && (laminar_fcntl(fd, F_SETFL, flag | O_NONBLOCK) < 0)) {
		SPDK_ERRLOG("fcntl can't set nonblocking mode for socket, fd: %d (%d)\n", fd, errno);
		laminar_close(fd);
		return NULL;
	}

	/* Inherit the zero copy feature from the listen socket */
	new_sock = laminar_sock_alloc(fd, &sock->base.impl_opts);
	if (new_sock == NULL) {
		laminar_close(fd);
		return NULL;
	}

	return &new_sock->base;
}

static struct spdk_sock *
laminar_sock_accept(struct spdk_sock *_sock)
{
	return _laminar_sock_accept(_sock);
}

static int
laminar_sock_close(struct spdk_sock *_sock)
{
	struct spdk_laminar_sock *sock = __laminar_sock(_sock);
	void *pipe_buf;

	assert(TAILQ_EMPTY(&_sock->pending_reqs));

	/* If the socket fails to close, the best choice is to
	 * leak the fd but continue to free the rest of the sock
	 * memory. */
	laminar_close(sock->fd);

	pipe_buf = spdk_pipe_destroy(sock->recv_pipe);
	free(pipe_buf);
	free(sock);

	return 0;
}

static int
_sock_flush(struct spdk_sock *sock)
{
	struct spdk_laminar_sock *psock = __laminar_sock(sock);
	struct msghdr msg = {};
	int flags;
	struct iovec iovs[IOV_BATCH_SIZE];
	int iovcnt;
	int retval;
	struct spdk_sock_request *req;
	int i;
	ssize_t rc, sent;
	unsigned int offset;
	size_t len;

	/* Can't flush from within a callback or we end up with recursive calls */
	if (sock->cb_cnt > 0) {
		errno = EAGAIN;
		return -1;
	}


	/* FIXME: How to handle this? */
	flags = 0;
#if 0
	{
		flags = MSG_NOSIGNAL;
	}
#endif

	iovcnt = spdk_sock_prep_reqs(sock, iovs, 0, NULL, &flags);
	if (iovcnt == 0) {
		return 0;
	}

	/* Perform the vectored write */
	msg.msg_iov = iovs;
	msg.msg_iovlen = iovcnt;


	rc = laminar_sendmsg(psock->fd, &msg, flags);
	if (rc <= 0) {
		if (rc == 0 || errno == EAGAIN || errno == EWOULDBLOCK) {
			errno = EAGAIN;
		}
		return -1;
	}

	sent = rc;

	/* Consume the requests that were actually written */
	req = TAILQ_FIRST(&sock->queued_reqs);
	while (req) {
		offset = req->internal.offset;


		for (i = 0; i < req->iovcnt; i++) {
			/* Advance by the offset first */
			if (offset >= SPDK_SOCK_REQUEST_IOV(req, i)->iov_len) {
				offset -= SPDK_SOCK_REQUEST_IOV(req, i)->iov_len;
				continue;
			}

			/* Calculate the remaining length of this element */
			len = SPDK_SOCK_REQUEST_IOV(req, i)->iov_len - offset;

			if (len > (size_t)rc) {
				/* This element was partially sent. */
				req->internal.offset += rc;
				return sent;
			}

			offset = 0;
			req->internal.offset += len;
			rc -= len;
		}

		/* Handled a full request. */
		spdk_sock_request_pend(sock, req);

		if (req == TAILQ_FIRST(&sock->pending_reqs)) {
			/* The sendmsg syscall above isn't currently asynchronous,
			* so it's already done. */
			retval = spdk_sock_request_put(sock, req, 0);
			if (retval) {
				break;
			}
		} else {
			/* Re-use the offset field to hold the sendmsg call index. The
			 * index is 0 based, so subtract one here because we've already
			 * incremented above. */
			req->internal.offset = psock->sendmsg_idx - 1;
		}

		if (rc == 0) {
			break;
		}

		req = TAILQ_FIRST(&sock->queued_reqs);
	}

	return sent;
}

static int
laminar_sock_flush(struct spdk_sock *sock)
{
	return _sock_flush(sock);
}

static ssize_t
laminar_sock_recv_from_pipe(struct spdk_laminar_sock *sock, struct iovec *diov, int diovcnt)
{
	struct iovec siov[2];
	int sbytes;
	ssize_t bytes;
	struct spdk_laminar_sock_group_impl *group;

	sbytes = spdk_pipe_reader_get_buffer(sock->recv_pipe, sock->recv_buf_sz, siov);
	if (sbytes < 0) {
		errno = EINVAL;
		return -1;
	} else if (sbytes == 0) {
		errno = EAGAIN;
		return -1;
	}

	bytes = spdk_iovcpy(siov, 2, diov, diovcnt);

	if (bytes == 0) {
		/* The only way this happens is if diov is 0 length */
		errno = EINVAL;
		return -1;
	}

	spdk_pipe_reader_advance(sock->recv_pipe, bytes);

	/* If we drained the pipe, mark it appropriately */
	if (spdk_pipe_reader_bytes_available(sock->recv_pipe) == 0) {
		assert(sock->pipe_has_data == true);

		group = __laminar_group_impl(sock->base.group_impl);
		if (group && !sock->socket_has_data) {
			TAILQ_REMOVE(&group->socks_with_data, sock, link);
		}

		sock->pipe_has_data = false;
	}

	return bytes;
}

static inline ssize_t
laminar_sock_read(struct spdk_laminar_sock *sock)
{
	struct iovec iov[2];
	int bytes_avail, bytes_recvd;
	struct spdk_laminar_sock_group_impl *group;

	bytes_avail = spdk_pipe_writer_get_buffer(sock->recv_pipe, sock->recv_buf_sz, iov);

	if (bytes_avail <= 0) {
		return bytes_avail;
	}

	bytes_recvd = laminar_readv(sock->fd, iov, 2);


	assert(sock->pipe_has_data == false);

	if (bytes_recvd <= 0) {
		/* Errors count as draining the socket data */
		if (sock->base.group_impl && sock->socket_has_data) {
			group = __laminar_group_impl(sock->base.group_impl);
			TAILQ_REMOVE(&group->socks_with_data, sock, link);
		}

		sock->socket_has_data = false;

		return bytes_recvd;
	}

	spdk_pipe_writer_advance(sock->recv_pipe, bytes_recvd);

#if DEBUG
	if (sock->base.group_impl) {
		assert(sock->socket_has_data == true);
	}
#endif

	sock->pipe_has_data = true;
	if (bytes_recvd < bytes_avail) {
		/* We drained the kernel socket entirely. */
		sock->socket_has_data = false;
	}

	return bytes_recvd;
}

static ssize_t
laminar_sock_readv(struct spdk_sock *_sock, struct iovec *iov, int iovcnt)
{
	struct spdk_laminar_sock *sock = __laminar_sock(_sock);
	struct spdk_laminar_sock_group_impl *group = __laminar_group_impl(sock->base.group_impl);
	int rc, i;
	size_t len;

	if (sock->recv_pipe == NULL) {
		assert(sock->pipe_has_data == false);
		if (group && sock->socket_has_data) {
			sock->socket_has_data = false;
			TAILQ_REMOVE(&group->socks_with_data, sock, link);
		}
		return laminar_readv(sock->fd, iov, iovcnt);
	}

	/* If the socket is not in a group, we must assume it always has
	 * data waiting for us because it is not epolled */
	if (!sock->pipe_has_data && (group == NULL || sock->socket_has_data)) {
		/* If the user is receiving a sufficiently large amount of data,
		 * receive directly to their buffers. */
		len = 0;
		for (i = 0; i < iovcnt; i++) {
			len += iov[i].iov_len;
		}

		if (len >= MIN_SOCK_PIPE_SIZE) {
			/* TODO: Should this detect if kernel socket is drained? */
			return laminar_readv(sock->fd, iov, iovcnt);
		}

		/* Otherwise, do a big read into our pipe */
		rc = laminar_sock_read(sock);
		if (rc <= 0) {
			return rc;
		}
	}

	return laminar_sock_recv_from_pipe(sock, iov, iovcnt);
}

static ssize_t
laminar_sock_recv(struct spdk_sock *sock, void *buf, size_t len)
{
	struct iovec iov[1];

	iov[0].iov_base = buf;
	iov[0].iov_len = len;

	return laminar_sock_readv(sock, iov, 1);
}

static ssize_t
laminar_sock_writev(struct spdk_sock *_sock, struct iovec *iov, int iovcnt)
{
	struct spdk_laminar_sock *sock = __laminar_sock(_sock);
	int rc;

	/* In order to process a writev, we need to flush any asynchronous writes
	 * first. */
	rc = _sock_flush(_sock);
	if (rc < 0) {
		return rc;
	}

	if (!TAILQ_EMPTY(&_sock->queued_reqs)) {
		/* We weren't able to flush all requests */
		errno = EAGAIN;
		return -1;
	}

	return laminar_writev(sock->fd, iov, iovcnt);
}

static int
laminar_sock_recv_next(struct spdk_sock *_sock, void **buf, void **ctx)
{
	struct spdk_laminar_sock *sock = __laminar_sock(_sock);
	struct iovec iov;
	ssize_t rc;

	if (sock->recv_pipe != NULL) {
		errno = ENOTSUP;
		return -1;
	}

	iov.iov_len = spdk_sock_group_get_buf(_sock->group_impl->group, &iov.iov_base, ctx);
	if (iov.iov_len == 0) {
		errno = ENOBUFS;
		return -1;
	}

	rc = laminar_sock_readv(_sock, &iov, 1);
	if (rc <= 0) {
		spdk_sock_group_provide_buf(_sock->group_impl->group, iov.iov_base, iov.iov_len, *ctx);
		return rc;
	}

	*buf = iov.iov_base;

	return rc;
}

static void
laminar_sock_writev_async(struct spdk_sock *sock, struct spdk_sock_request *req)
{
	int rc;

	spdk_sock_request_queue(sock, req);

	/* If there are a sufficient number queued, just flush them out immediately. */
	if (sock->queued_iovcnt >= IOV_BATCH_SIZE) {
		rc = _sock_flush(sock);
		if (rc < 0 && errno != EAGAIN) {
			spdk_sock_abort_requests(sock);
		}
	}
}

static int
laminar_sock_set_recvlowat(struct spdk_sock *_sock, int nbytes)
{
	struct spdk_laminar_sock *sock = __laminar_sock(_sock);
	int val;
	int rc;

	assert(sock != NULL);

	val = nbytes;
	rc = laminar_setsockopt(sock->fd, SOL_SOCKET, SO_RCVLOWAT, &val, sizeof val);
	if (rc != 0) {
		return -1;
	}
	return 0;
}

static bool
laminar_sock_is_ipv6(struct spdk_sock *_sock)
{
	struct spdk_laminar_sock *sock = __laminar_sock(_sock);
	struct sockaddr_storage sa;
	socklen_t salen;
	int rc;

	assert(sock != NULL);

	memset(&sa, 0, sizeof sa);
	salen = sizeof sa;
	rc = laminar_getsockname(sock->fd, (struct sockaddr *) &sa, &salen);
	if (rc != 0) {
		SPDK_ERRLOG("getsockname() failed (errno=%d)\n", errno);
		return false;
	}

	return (sa.ss_family == AF_INET6);
}

static bool
laminar_sock_is_ipv4(struct spdk_sock *_sock)
{
	struct spdk_laminar_sock *sock = __laminar_sock(_sock);
	struct sockaddr_storage sa;
	socklen_t salen;
	int rc;

	assert(sock != NULL);

	memset(&sa, 0, sizeof sa);
	salen = sizeof sa;
	rc = laminar_getsockname(sock->fd, (struct sockaddr *) &sa, &salen);
	if (rc != 0) {
		SPDK_ERRLOG("getsockname() failed (errno=%d)\n", errno);
		return false;
	}

	return (sa.ss_family == AF_INET);
}

static bool
laminar_sock_is_connected(struct spdk_sock *_sock)
{
	struct spdk_laminar_sock *sock = __laminar_sock(_sock);
	uint8_t byte;
	int rc;

	/* FIXME: MSG_PEEK is not supported! */
	rc = laminar_recv(sock->fd, &byte, 1, MSG_PEEK);
	if (rc == 0) {
		return false;
	}

	if (rc < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return true;
		}

		return false;
	}

	return true;
}

static struct spdk_sock_group_impl *
laminar_sock_group_impl_get_optimal(struct spdk_sock *_sock, struct spdk_sock_group_impl *hint)
{
	struct spdk_laminar_sock *sock = __laminar_sock(_sock);
	struct spdk_sock_group_impl *group_impl;

	if (sock->placement_id != -1) {
		spdk_sock_map_lookup(&g_map, sock->placement_id, &group_impl, hint);
		return group_impl;
	}

	return NULL;
}

static struct spdk_sock_group_impl *
_sock_group_impl_create(uint32_t enable_placement_id)
{
	struct spdk_laminar_sock_group_impl *group_impl;
	int fd;

	fd = laminar_epoll_create1(0);

	if (fd == -1) {
		return NULL;
	}

	group_impl = calloc(1, sizeof(*group_impl));
	if (group_impl == NULL) {
		SPDK_ERRLOG("group_impl allocation failed\n");
		laminar_close(fd);
		return NULL;
	}

	group_impl->pipe_group = spdk_pipe_group_create();
	if (group_impl->pipe_group == NULL) {
		SPDK_ERRLOG("pipe_group allocation failed\n");
		free(group_impl);
		laminar_close(fd);
		return NULL;
	}

	group_impl->fd = fd;
	TAILQ_INIT(&group_impl->socks_with_data);
	group_impl->placement_id = -1;

	if (enable_placement_id == PLACEMENT_CPU) {
		spdk_sock_map_insert(&g_map, spdk_env_get_current_core(), &group_impl->base);
		group_impl->placement_id = spdk_env_get_current_core();
	}

	return &group_impl->base;
}

static struct spdk_sock_group_impl *
laminar_sock_group_impl_create(void)
{
	return _sock_group_impl_create(g_laminar_impl_opts.enable_placement_id);
}

static int
laminar_sock_group_impl_add_sock(struct spdk_sock_group_impl *_group, struct spdk_sock *_sock)
{
	struct spdk_laminar_sock_group_impl *group = __laminar_group_impl(_group);
	struct spdk_laminar_sock *sock = __laminar_sock(_sock);
	int rc;

	struct epoll_event event;

	memset(&event, 0, sizeof(event));
	/* EPOLLERR is always on even if we don't set it, but be explicit for clarity */
	event.events = EPOLLIN | EPOLLERR;
	event.data.ptr = sock;

	rc = laminar_epoll_ctl(group->fd, EPOLL_CTL_ADD, sock->fd, &event);

	if (rc != 0) {
		return rc;
	}

	/* switched from another polling group due to scheduling */
	if (spdk_unlikely(sock->recv_pipe != NULL  &&
			  (spdk_pipe_reader_bytes_available(sock->recv_pipe) > 0))) {
		sock->pipe_has_data = true;
		sock->socket_has_data = false;
		TAILQ_INSERT_TAIL(&group->socks_with_data, sock, link);
	} else if (sock->recv_pipe != NULL) {
		rc = spdk_pipe_group_add(group->pipe_group, sock->recv_pipe);
		assert(rc == 0);
	}

	if (_sock->impl_opts.enable_placement_id == PLACEMENT_MARK) {
		/* TODO: How to handle this? */
		assert(false);
	} else if (sock->placement_id != -1) {
		rc = spdk_sock_map_insert(&g_map, sock->placement_id, &group->base);
		if (rc != 0) {
			SPDK_ERRLOG("Failed to insert sock group into map: %d\n", rc);
			/* Do not treat this as an error. The system will continue running. */
		}
	}

	return rc;
}

static int
laminar_sock_group_impl_remove_sock(struct spdk_sock_group_impl *_group, struct spdk_sock *_sock)
{
	struct spdk_laminar_sock_group_impl *group = __laminar_group_impl(_group);
	struct spdk_laminar_sock *sock = __laminar_sock(_sock);
	int rc;

	if (sock->pipe_has_data || sock->socket_has_data) {
		TAILQ_REMOVE(&group->socks_with_data, sock, link);
		sock->pipe_has_data = false;
		sock->socket_has_data = false;
	} else if (sock->recv_pipe != NULL) {
		rc = spdk_pipe_group_remove(group->pipe_group, sock->recv_pipe);
		assert(rc == 0);
	}

	if (sock->placement_id != -1) {
		spdk_sock_map_release(&g_map, sock->placement_id);
	}

	struct epoll_event event;

	/* Event parameter is ignored but some old kernel version still require it. */
	rc = laminar_epoll_ctl(group->fd, EPOLL_CTL_DEL, sock->fd, &event);
	spdk_sock_abort_requests(_sock);

	return rc;
}

static int
laminar_sock_group_impl_poll(struct spdk_sock_group_impl *_group, int max_events,
			   struct spdk_sock **socks)
{
	struct spdk_laminar_sock_group_impl *group = __laminar_group_impl(_group);
	struct spdk_sock *sock, *tmp;
	int num_events, i, rc;
	struct spdk_laminar_sock *psock, *ptmp;
	struct epoll_event events[MAX_EVENTS_PER_POLL];

	/* This must be a TAILQ_FOREACH_SAFE because while flushing,
	 * a completion callback could remove the sock from the
	 * group. */
	TAILQ_FOREACH_SAFE(sock, &_group->socks, link, tmp) {
		rc = _sock_flush(sock);
		if (rc < 0 && errno != EAGAIN) {
			spdk_sock_abort_requests(sock);
		}
	}

	assert(max_events > 0);

	num_events = laminar_epoll_wait(group->fd, events, max_events, 0);


	if (num_events == -1) {
		return -1;
	}

	for (i = 0; i < num_events; i++) {
		sock = events[i].data.ptr;
		psock = __laminar_sock(sock);

		if ((events[i].events & EPOLLIN) == 0) {
			continue;
		}

		/* If the socket is not already in the list, add it now */
		if (!psock->socket_has_data && !psock->pipe_has_data) {
			TAILQ_INSERT_TAIL(&group->socks_with_data, psock, link);
		}
		psock->socket_has_data = true;
	}

	num_events = 0;

	TAILQ_FOREACH_SAFE(psock, &group->socks_with_data, link, ptmp) {
		if (num_events == max_events) {
			break;
		}

		/* If the socket's cb_fn is NULL, just remove it from the
		 * list and do not add it to socks array */
		if (spdk_unlikely(psock->base.cb_fn == NULL)) {
			psock->socket_has_data = false;
			psock->pipe_has_data = false;
			TAILQ_REMOVE(&group->socks_with_data, psock, link);
			continue;
		}

		socks[num_events++] = &psock->base;
	}

	/* Cycle the has_data list so that each time we poll things aren't
	 * in the same order. Say we have 6 sockets in the list, named as follows:
	 * A B C D E F
	 * And all 6 sockets had epoll events, but max_events is only 3. That means
	 * psock currently points at D. We want to rearrange the list to the following:
	 * D E F A B C
	 *
	 * The variables below are named according to this example to make it easier to
	 * follow the swaps.
	 */
	if (psock != NULL) {
		struct spdk_laminar_sock *pa, *pc, *pd, *pf;

		/* Capture pointers to the elements we need */
		pd = psock;
		pc = TAILQ_PREV(pd, spdk_has_data_list, link);
		pa = TAILQ_FIRST(&group->socks_with_data);
		pf = TAILQ_LAST(&group->socks_with_data, spdk_has_data_list);

		/* Break the link between C and D */
		pc->link.tqe_next = NULL;

		/* Connect F to A */
		pf->link.tqe_next = pa;
		pa->link.tqe_prev = &pf->link.tqe_next;

		/* Fix up the list first/last pointers */
		group->socks_with_data.tqh_first = pd;
		group->socks_with_data.tqh_last = &pc->link.tqe_next;

		/* D is in front of the list, make tqe prev pointer point to the head of list */
		pd->link.tqe_prev = &group->socks_with_data.tqh_first;
	}

	return num_events;
}

static int
laminar_sock_group_impl_register_interrupt(struct spdk_sock_group_impl *_group, uint32_t events,
		spdk_interrupt_fn fn, void *arg, const char *name)
{
	struct spdk_laminar_sock_group_impl *group = __laminar_group_impl(_group);

	group->intr = spdk_interrupt_register_for_events(group->fd, events, fn, arg, name);

	return group->intr ? 0 : -1;
}

static void
laminar_sock_group_impl_unregister_interrupt(struct spdk_sock_group_impl *_group)
{
	struct spdk_laminar_sock_group_impl *group = __laminar_group_impl(_group);

	spdk_interrupt_unregister(&group->intr);
}

static int
_sock_group_impl_close(struct spdk_sock_group_impl *_group, uint32_t enable_placement_id)
{
	struct spdk_laminar_sock_group_impl *group = __laminar_group_impl(_group);
	int rc;

	if (enable_placement_id == PLACEMENT_CPU) {
		spdk_sock_map_release(&g_map, spdk_env_get_current_core());
	}

	spdk_pipe_group_destroy(group->pipe_group);
	rc = laminar_close(group->fd);
	free(group);
	return rc;
}

static int
laminar_sock_group_impl_close(struct spdk_sock_group_impl *_group)
{
	return _sock_group_impl_close(_group, g_laminar_impl_opts.enable_placement_id);
}

static struct spdk_net_impl g_laminar_net_impl = {
	.name		= "laminar",
	.getaddr	= laminar_sock_getaddr,
	.get_interface_name = laminar_sock_get_interface_name,
	.get_numa_id	= laminar_sock_get_numa_id,
	.connect	= laminar_sock_connect,
	.listen		= laminar_sock_listen,
	.accept		= laminar_sock_accept,
	.close		= laminar_sock_close,
	.recv		= laminar_sock_recv,
	.readv		= laminar_sock_readv,
	.writev		= laminar_sock_writev,
	.recv_next	= laminar_sock_recv_next,
	.writev_async	= laminar_sock_writev_async,
	.flush		= laminar_sock_flush,
	.set_recvlowat	= laminar_sock_set_recvlowat,
	.set_recvbuf	= laminar_sock_set_recvbuf,
	.set_sendbuf	= laminar_sock_set_sendbuf,
	.is_ipv6	= laminar_sock_is_ipv6,
	.is_ipv4	= laminar_sock_is_ipv4,
	.is_connected	= laminar_sock_is_connected,
	.group_impl_get_optimal	= laminar_sock_group_impl_get_optimal,
	.group_impl_create	= laminar_sock_group_impl_create,
	.group_impl_add_sock	= laminar_sock_group_impl_add_sock,
	.group_impl_remove_sock = laminar_sock_group_impl_remove_sock,
	.group_impl_poll	= laminar_sock_group_impl_poll,
	.group_impl_register_interrupt     = laminar_sock_group_impl_register_interrupt,
	.group_impl_unregister_interrupt  = laminar_sock_group_impl_unregister_interrupt,
	.group_impl_close	= laminar_sock_group_impl_close,
	.get_opts	= laminar_sock_impl_get_opts,
	.set_opts	= laminar_sock_impl_set_opts,
};

SPDK_NET_IMPL_REGISTER_DEFAULT(laminar, &g_laminar_net_impl);

__attribute__((constructor)) static void
net_impl_register_laminar(void)
{
	/* Check if we can connect with laminar group before we register
	 * it as a valid impl. */
	if (laminar_sockets_init() != 0) {
		return;
	}

	spdk_net_impl_register(&g_laminar_net_impl);
}