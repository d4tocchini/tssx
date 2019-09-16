#define _GNU_SOURCE

#include <assert.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "tssx/bridge.h"
#include "tssx/connection.h"
#include "tssx/session.h"
#include "tssx/socket-overrides.h"
#include "utility/utility.h"

#ifdef __linux__
#include "tssx/epoll-overrides.h"
#endif

/******************** REAL FUNCTIONS ********************/

// RTDL_NEXT = look in the symbol table of the *next* object file after this one
static real_write_t _real_write;
ssize_t real_write(int fd, const void* data, size_t size) {
	return (_real_write?_real_write:(_real_write=dlsym(RTLD_NEXT, "write")))(fd, data, size);
}

static real_read_t _real_read;
ssize_t real_read(int fd, void* data, size_t size) {
	return (_real_read?_real_read:(_real_read=dlsym(RTLD_NEXT, "read")))(fd, data, size);
}

static real_send_t _real_send;
ssize_t real_send(int fd, const void* buffer, size_t length, int flags) {
	return (_real_send?_real_send:(_real_send=dlsym(RTLD_NEXT, "send")))(fd, buffer, length, flags);
}

static real_recv_t _real_recv;
ssize_t real_recv(int fd, void* buffer, size_t length, int flags) {
	return (_real_recv?_real_recv:(_real_recv=dlsym(RTLD_NEXT, "recv")))(fd, buffer, length, flags);
}

static real_sendmsg_t _real_sendmsg;
ssize_t real_sendmsg(int fd, const struct msghdr* message, int flags) {
	return (_real_sendmsg?_real_sendmsg:(_real_sendmsg=dlsym(RTLD_NEXT, "sendmsg")))(fd, message, flags);
}

static real_recvmsg_t _real_recvmsg;
ssize_t real_recvmsg(int fd, struct msghdr* message, int flags) {
	return (_real_recvmsg?_real_recvmsg:(_real_recvmsg=dlsym(RTLD_NEXT, "recvmsg")))(fd, message, flags);
}

static real_sendto_t _real_sendto;
ssize_t real_sendto(int fd,
										const void* buffer,
										size_t length,
										int flags,
										const struct sockaddr* dest_addr,
										socklen_t dest_len) {
	// clang-format off
	return (_real_sendto?_real_sendto:(_real_sendto=dlsym(RTLD_NEXT, "sendto")))
            (fd, buffer, length, flags, dest_addr, dest_len);
	// clang-format on
}

static real_recvfrom_t _real_recvfrom;
ssize_t real_recvfrom(int fd,
											void* restrict buffer,
											size_t length,
											int flags,
											struct sockaddr* restrict address,
											socklen_t* restrict address_len) {
	// clang-format off
	return (_real_recvfrom?_real_recvfrom:(_real_recvfrom=dlsym(RTLD_NEXT, "recvfrom")))
            (fd, buffer, length, flags, address, address_len);
	// clang-format on
}

static real_accept_t _real_accept;
int real_accept(int fd, sockaddr* address, socklen_t* length) {
	return (_real_accept?_real_accept:(_real_accept=dlsym(RTLD_NEXT, "accept")))(fd, address, length);
}

static real_connect_t _real_connect;
int real_connect(int fd, const sockaddr* address, socklen_t length) {
	return (_real_connect ? _real_connect : (_real_connect = dlsym(RTLD_NEXT, "connect")))(fd, address, length);
}

static real_close_t _real_close;
int real_close(int fd) {
	return (_real_close ? _real_close : (_real_close = dlsym(RTLD_NEXT, "close")))(fd);
}

static real_getsockopt_t _real_getsockopt;
int real_getsockopt(int fd,
										int level,
										int option_name,
										void* restrict option_value,
										socklen_t* restrict option_len) {
	// Some nice lisp here
	// clang-format off
	return (_real_getsockopt ? _real_getsockopt : (_real_getsockopt =dlsym(RTLD_NEXT, "getsockopt")))
      (fd, level, option_name, option_value, option_len);
	// clang-format on
}

int real_setsockopt(int fd,
										int level,
										int option_name,
										const void* option_value,
										socklen_t option_len) {
	// Some nice lisp here
	// clang-format off
	return ((real_setsockopt_t)dlsym(RTLD_NEXT, "setsockopt"))
      (fd, level, option_name, option_value, option_len);
	// clang-format on
}

int real_getsockname(int fd, struct sockaddr* addr, socklen_t* addrlen) {
	// Some nice lisp here
	// clang-format off
	return ((real_getsockname_t)dlsym(RTLD_NEXT, "getsockname"))
			(fd, addr, addrlen);
	// clang-format on
}

/******************** COMMON OVERRIDES ********************/

int getsockopt(int fd,
							 int level,
							 int option_name,
							 void* restrict option_value,
							 socklen_t* restrict option_len) {
	// clang-format off
	return real_getsockopt(
			fd,
      level,
      option_name,
      option_value,
      option_len
  );
	// clang-format on
}

int getsockname(int fd, struct sockaddr* addr, socklen_t* addrlen) {
	return real_getsockname(fd, addr, addrlen);
}

int setsockopt(int fd,
							 int level,
							 int option_name,
							 const void* option_value,
							 socklen_t option_len) {
	// clang-format off
  return real_setsockopt(
     fd,
     level,
     option_name,
     option_value,
     option_len
  );
  // clang-fomat pm
}

int close(int fd) {
  // epoll is linux only
#ifdef __linux__
  // These two are definitely mutually exclusive
  if (has_epoll_instance_associated(fd)) {
    close_epoll_instance(fd);
  } else {
    bridge_erase(&bridge, fd);
  }
#else
  bridge_erase(&bridge, fd);
#endif
	return real_close(fd);
}

ssize_t send(int fd, const void* buffer, size_t length, int flags) {
// For now: We forward the call to write for a certain set of
// flags, which we chose to ignore. By putting them here explicitly,
// we make sure that we only ignore flags, which are not important.
// For production, we might wanna handle these flags
#ifdef __APPLE__
	if (flags == 0) {
#else
	if (flags == 0 || flags == MSG_NOSIGNAL) {
#endif
		return write(fd, buffer, length);
	} else {
    warn("Routing send to socket (unsupported flags)");
    return real_send(fd, buffer, length, flags);
  }
}

ssize_t recv(int fd, void *buffer, size_t length, int flags) {
#ifdef __APPLE__
	if (flags == 0) {
#else
	if (flags == 0 || flags == MSG_NOSIGNAL) {
#endif
		return read(fd, buffer, length);
	} else {
    warn("Routing recv to socket (unsupported flags)");
    return real_recv(fd, buffer, length, flags);
  }
}

ssize_t sendto(int fd,
							 const void *buffer,
							 size_t length,
							 int flags,
							 const struct sockaddr *dest_addr,
							 socklen_t addrlen) {
  // When the destination address is null, then this should be a stream socket
	if (dest_addr == NULL) {
    return send(fd, buffer, length, flags);
  } else {
    // Connection-less sockets (UDP) sockets never use TSSX anyway
    return real_sendto(fd, buffer, length, flags, dest_addr, addrlen);
  }
}

ssize_t recvfrom(int fd,
								 void *buffer,
								 size_t length,
								 int flags,
								 struct sockaddr *src_addr,
								 socklen_t *addrlen) {
  // When the destination address is null, then this should be a stream socket
  if (src_addr == NULL) {
   return recv(fd, buffer, length, flags);
  } else {
   // Connection-Less sockets (UDP) sockets never use TSSX anyway
   return real_recvfrom(fd, buffer, length, flags, src_addr, addrlen);
  }
}

ssize_t sendmsg(int fd, const struct msghdr *msg, int flags) {
    // This one is hard to implemenet because the `msghdr` struct contains
    // an iovec pointer, which points to an array of iovec structs. Each such
    // struct is then a vector with a starting address and length. The sendmsg
    // call then fills these vectors one by one until the stream is empty or
    // all the vectors have been filled. I don't know how many people use this
    // function, but right now we just support a single buffer and else route
    // the call to the socket itself.
    if (msg->msg_iovlen == 1) {
      return sendto(fd, msg->msg_iov[0].iov_base, msg->msg_iov[0].iov_len, flags, (struct sockaddr*)msg->msg_name, msg->msg_namelen);
    } else {
      warn("Routing sendmsg to socket (too many buffers)");
      return real_sendmsg(fd, msg, flags);
    }
}

ssize_t recvmsg(int fd, struct msghdr *msg, int flags) {
  if (msg->msg_iovlen == 1) {
    return recvfrom(fd, msg->msg_iov[0].iov_base, msg->msg_iov[0].iov_len, flags, (struct sockaddr*)msg->msg_name, &msg->msg_namelen);
  } else {
    warn("Routing recvmsg to socket (too many buffers)");
    return real_recvmsg(fd, msg, flags);
  }
}
