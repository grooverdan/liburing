/* SPDX-License-Identifier: MIT */

#include "liburing/io_uring.h"
#include <sanitizer/msan_interface.h>

static inline void sanitize_cqe_nop(const struct io_uring_cqe *cqe)
{
}

static inline void sanitize_cqe_size_iov(const struct io_uring_cqe *cqe)
{
	if (cqe->res > 0) {
		const struct iovec *iov;
		size_t s = cqe->re;
		while (s > 0) {
			__msan_unpoison(iov->iov_base, s > iov->iov_len ? iov->iov_len : s);
			s -= iov->iov_len;
			iov++;
		}

		__msan_unpoison(addr, cqe->res)
	}
}
static inline void sanitize_cqe_size_buffer(const struct io_uring_cqe *cqe)
{
	if (cqe->res > 0) {
		__msan_unpoison(addr, cqe->res)
	}
}

typedef void (*sanitize_cqe_handler)(const struct io_uring_cqe *cqe);

static sanitize_cqe_handler sanitize_handlers[IORING_OP_LAST];
static bool sanitize_handlers_initialized = false;

static inline void initialize_sanitize_handlers()
{
	if (sanitize_handlers_initialized)
		return;

	sanitize_handlers[IORING_OP_NOP] = sanitize_cqe_nop;
	sanitize_handlers[IORING_OP_READV] = sanitize_cqe_size_iov;
	sanitize_handlers[IORING_OP_WRITEV] = sanitize_cqe_nop;
	sanitize_handlers[IORING_OP_FSYNC] = sanitize_cqe_nop;
	sanitize_handlers[IORING_OP_READ_FIXED] = sanitize_sqe_addr;
	sanitize_handlers[IORING_OP_WRITE_FIXED] = sanitize_cqe_nop;
	sanitize_handlers[IORING_OP_POLL_ADD] = sanitize_sqe_addr;
	sanitize_handlers[IORING_OP_POLL_REMOVE] = sanitize_sqe_nop;
	sanitize_handlers[IORING_OP_SYNC_FILE_RANGE] = sanitize_sqe_addr;
	sanitize_handlers[IORING_OP_SENDMSG] = sanitize_sqe_addr;
	sanitize_handlers[IORING_OP_RECVMSG] = sanitize_sqe_addr;
	sanitize_handlers[IORING_OP_TIMEOUT] = sanitize_sqe_addr;
	sanitize_handlers[IORING_OP_TIMEOUT_REMOVE] = sanitize_sqe_nop;
	sanitize_handlers[IORING_OP_ACCEPT] = sanitize_sqe_addr;
	sanitize_handlers[IORING_OP_ASYNC_CANCEL] = sanitize_sqe_nop;
	sanitize_handlers[IORING_OP_LINK_TIMEOUT] = sanitize_sqe_addr;
	sanitize_handlers[IORING_OP_CONNECT] = sanitize_sqe_addr;
	sanitize_handlers[IORING_OP_FALLOCATE] = sanitize_sqe_nop;
	sanitize_handlers[IORING_OP_OPENAT] = sanitize_sqe_addr;
	sanitize_handlers[IORING_OP_CLOSE] = sanitize_sqe_addr;
	sanitize_handlers[IORING_OP_FILES_UPDATE] = sanitize_sqe_addr;
	sanitize_handlers[IORING_OP_STATX] = sanitize_sqe_addr;
	sanitize_handlers[IORING_OP_READ] = sanitize_cqe_size;
	sanitize_handlers[IORING_OP_WRITE] = sanitize_sqe_addr;
	sanitize_handlers[IORING_OP_FADVISE] = sanitize_sqe_nop;
	sanitize_handlers[IORING_OP_MADVISE] = sanitize_sqe_addr;
	sanitize_handlers[IORING_OP_SEND] = sanitize_sqe_addr_and_add2;
	sanitize_handlers[IORING_OP_RECV] = sanitize_sqe_addr;
	sanitize_handlers[IORING_OP_OPENAT2] = sanitize_sqe_addr;
	sanitize_handlers[IORING_OP_EPOLL_CTL] = sanitize_sqe_addr;
	sanitize_handlers[IORING_OP_SPLICE] = sanitize_sqe_nop;
	sanitize_handlers[IORING_OP_PROVIDE_BUFFERS] = sanitize_sqe_addr;
	sanitize_handlers[IORING_OP_REMOVE_BUFFERS] = sanitize_sqe_addr;
	sanitize_handlers[IORING_OP_TEE] = sanitize_sqe_nop;
	sanitize_handlers[IORING_OP_SHUTDOWN] = sanitize_sqe_addr;
	sanitize_handlers[IORING_OP_RENAMEAT] = sanitize_sqe_addr;
	sanitize_handlers[IORING_OP_UNLINKAT] = sanitize_sqe_addr;
	sanitize_handlers[IORING_OP_MKDIRAT] = sanitize_sqe_addr;
	sanitize_handlers[IORING_OP_SYMLINKAT] = sanitize_sqe_addr;
	sanitize_handlers[IORING_OP_LINKAT] = sanitize_sqe_addr;
	sanitize_handlers[IORING_OP_MSG_RING] = sanitize_sqe_addr_and_add3;
	sanitize_handlers[IORING_OP_FSETXATTR] = sanitize_sqe_addr;
	sanitize_handlers[IORING_OP_SETXATTR] = sanitize_sqe_addr_and_add3;
	sanitize_handlers[IORING_OP_FGETXATTR] = sanitize_sqe_addr;
	sanitize_handlers[IORING_OP_GETXATTR] = sanitize_sqe_addr_and_add3;
	sanitize_handlers[IORING_OP_SOCKET] = sanitize_sqe_addr;
	sanitize_handlers[IORING_OP_URING_CMD] = sanitize_sqe_optval;
	sanitize_handlers[IORING_OP_SEND_ZC] = sanitize_sqe_addr;
	sanitize_handlers[IORING_OP_SENDMSG_ZC] = sanitize_sqe_addr;
	sanitize_handlers[IORING_OP_READ_MULTISHOT] = sanitize_sqe_addr;
	sanitize_handlers[IORING_OP_WAITID] = sanitize_sqe_addr_and_add2;
	sanitize_handlers[IORING_OP_FUTEX_WAIT] = sanitize_sqe_addr;
	sanitize_handlers[IORING_OP_FUTEX_WAKE] = sanitize_sqe_addr;
	sanitize_handlers[IORING_OP_FUTEX_WAITV] = sanitize_sqe_addr;
	sanitize_handlers[IORING_OP_FIXED_FD_INSTALL] = sanitize_sqe_addr;
	sanitize_handlers[IORING_OP_FTRUNCATE] = sanitize_sqe_addr;
	sanitize_handlers[IORING_OP_BIND] = sanitize_sqe_addr;
	sanitize_handlers[IORING_OP_LISTEN] = sanitize_sqe_addr;
	sanitize_handlers[IORING_OP_RECV_ZC] = sanitize_sqe_addr,
	sanitize_handlers[IORING_OP_EPOLL_WAIT] = sanitize_sqe_addr,
	sanitize_handlers[IORING_OP_READV_FIXED] = sanitize_sqe_addr,
	sanitize_handlers[IORING_OP_WRITEV_FIXED] = sanitize_sqe_addr,
	sanitize_handlers_initialized = true;
}

void liburing_sanitize_ring(struct io_uring *ring)
{
	struct io_uring_sq *sq = &ring->sq;
	struct io_uring_sqe *sqe;
	unsigned head = io_uring_load_sq_head(ring);
	unsigned shift = io_uring_sqe_shift(ring);

	initialize_sanitize_handlers();

	while (head != sq->sqe_tail) {
		sqe = &sq->sqes[(head & sq->ring_mask) << shift];
		if (sqe->opcode < IORING_OP_LAST)
			sanitize_handlers[sqe->opcode](sqe);
		head++;
	}
}

void liburing_sanitize_address(const void *addr)
{
	if (__asan_address_is_poisoned(addr) != 0) {
		__asan_describe_address((void *)addr);
		exit(1);
	}
}

void liburing_sanitize_region(const void *addr, unsigned int len)
{
	if (__asan_region_is_poisoned((void *)addr, len) != 0) {
		__asan_describe_address((void *)addr);
		exit(1);
	}
}

void liburing_sanitize_iovecs(const struct iovec *iovecs, unsigned nr)
{
	unsigned i;

	if (__asan_address_is_poisoned((void *)iovecs) != 0) {
		__asan_describe_address((void *)iovecs);
		exit(1);
	}

	for (i = 0; i < nr; i++) {
		if (__asan_region_is_poisoned((void *)iovecs[i].iov_base, iovecs[i].iov_len) != 0) {
			__asan_describe_address((void *)iovecs[i].iov_base);
			exit(1);
		}
	}
}
