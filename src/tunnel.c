#define _GNU_SOURCE

#include "tunnel.h"

#include <errno.h>
#include <linux/if_addr.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define ADDRESS_REQUEST_SIZE 256u
#define NETLINK_RESPONSE_SIZE 4096u

struct address_request {
    _Alignas(struct nlmsghdr) uint8_t bytes[ADDRESS_REQUEST_SIZE];
    size_t length;
};

static _Atomic uint32_t next_sequence = 1;

static int validate_address(const struct tunnel_address *address)
{
    if (address->family == AF_INET && address->prefix_length <= 32) {
        return 0;
    }
    if (address->family == AF_INET6 && address->prefix_length <= 128) {
        return 0;
    }
    errno = EINVAL;
    return -1;
}

static int append_attribute(struct address_request *request, uint16_t type,
                            const void *data, size_t data_length)
{
    size_t offset = NLMSG_ALIGN(request->length);
    size_t attribute_length = sizeof(struct nlattr) + data_length;
    size_t aligned_length = NLA_ALIGN(attribute_length);
    if (data == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (attribute_length > UINT16_MAX || offset > sizeof(request->bytes) ||
        aligned_length > sizeof(request->bytes) - offset) {
        errno = EMSGSIZE;
        return -1;
    }

    memset(request->bytes + request->length, 0, offset - request->length);
    struct nlattr *attribute = (struct nlattr *)(request->bytes + offset);
    attribute->nla_len = (uint16_t)attribute_length;
    attribute->nla_type = type;
    memcpy((uint8_t *)attribute + sizeof(*attribute), data, data_length);

    request->length = offset + aligned_length;
    ((struct nlmsghdr *)request->bytes)->nlmsg_len = (uint32_t)request->length;
    return 0;
}

static int receive_ack(int fd, uint32_t sequence)
{
    _Alignas(struct nlmsghdr) uint8_t buffer[NETLINK_RESPONSE_SIZE];
    for (;;) {
        struct sockaddr_nl sender = { 0 };
        struct iovec vector = { .iov_base = buffer, .iov_len = sizeof(buffer) };
        struct msghdr packet = {
            .msg_name = &sender,
            .msg_namelen = sizeof(sender),
            .msg_iov = &vector,
            .msg_iovlen = 1,
        };
        ssize_t received;
        do {
            received = recvmsg(fd, &packet, 0);
        } while (received < 0 && errno == EINTR);
        if (received < 0) {
            return -1;
        }
        if ((packet.msg_flags & MSG_TRUNC) != 0 || sender.nl_pid != 0) {
            errno = EPROTO;
            return -1;
        }

        int remaining = (int)received;
        for (struct nlmsghdr *header = (struct nlmsghdr *)buffer;
             NLMSG_OK(header, remaining);
             header = NLMSG_NEXT(header, remaining)) {
            if (header->nlmsg_seq != sequence) {
                continue;
            }
            if (header->nlmsg_type != NLMSG_ERROR ||
                header->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
                errno = EPROTO;
                return -1;
            }
            const struct nlmsgerr *error = NLMSG_DATA(header);
            if (error->error != 0) {
                errno = -error->error;
                return -1;
            }
            return 0;
        }
        if (remaining != 0) {
            errno = EPROTO;
            return -1;
        }
    }
}

static int add_interface_address(const char *ifname,
                                 const struct tunnel_address *address)
{
    errno = 0;
    unsigned int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        if (errno == 0) {
            errno = ENODEV;
        }
        return -1;
    }

    size_t address_length = address->family == AF_INET
        ? sizeof(struct in_addr) : sizeof(struct in6_addr);
    struct address_request request = { 0 };
    request.length = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    struct nlmsghdr *header = (struct nlmsghdr *)request.bytes;
    header->nlmsg_len = (uint32_t)request.length;
    header->nlmsg_type = RTM_NEWADDR;
    header->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    header->nlmsg_seq = atomic_fetch_add(&next_sequence, 1);
    if (header->nlmsg_seq == 0) {
        header->nlmsg_seq = atomic_fetch_add(&next_sequence, 1);
    }

    struct ifaddrmsg *info = NLMSG_DATA(header);
    info->ifa_family = (uint8_t)address->family;
    info->ifa_prefixlen = address->prefix_length;
    info->ifa_scope = RT_SCOPE_UNIVERSE;
    info->ifa_index = ifindex;

    if ((address->family == AF_INET &&
         append_attribute(&request, IFA_LOCAL, address->address, address_length) < 0) ||
        append_attribute(&request, IFA_ADDRESS, address->address, address_length) < 0) {
        return -1;
    }

    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_nl local = { .nl_family = AF_NETLINK };
    struct sockaddr_nl kernel = { .nl_family = AF_NETLINK };
    struct timeval timeout = { .tv_sec = 5 };
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0 ||
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }

    socklen_t local_length = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &local_length) < 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    header->nlmsg_pid = local.nl_pid;

    ssize_t sent;
    do {
        sent = sendto(fd, request.bytes, request.length, 0,
                      (struct sockaddr *)&kernel, sizeof(kernel));
    } while (sent < 0 && errno == EINTR);
    int result;
    if (sent < 0) {
        result = -1;
    } else if ((size_t)sent != request.length) {
        errno = EIO;
        result = -1;
    } else {
        result = receive_ack(fd, header->nlmsg_seq);
    }
    int saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return result;
}

int tunnel_start(const struct tunnel_config *config)
{
    if (config == NULL || config->wireguard.ifname == NULL ||
        (config->address_count > 0 && config->addresses == NULL)) {
        errno = EINVAL;
        return -1;
    }
    for (size_t index = 0; index < config->address_count; ++index) {
        if (validate_address(&config->addresses[index]) < 0) {
            return -1;
        }
    }

    if (wg_link_create(config->wireguard.ifname) < 0) {
        return -1;
    }
    if (wg_device_configure(&config->wireguard) < 0) {
        goto rollback;
    }
    for (size_t index = 0; index < config->address_count; ++index) {
        if (add_interface_address(config->wireguard.ifname,
                                  &config->addresses[index]) < 0) {
            goto rollback;
        }
    }
    if (wg_link_set_up(config->wireguard.ifname) < 0) {
        goto rollback;
    }
    return 0;

rollback: {
        int saved_errno = errno;
        (void)wg_link_delete(config->wireguard.ifname);
        errno = saved_errno;
        return -1;
    }
}

int tunnel_stop(const char *ifname)
{
    return wg_link_delete(ifname);
}