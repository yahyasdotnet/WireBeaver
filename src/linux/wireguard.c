#define _GNU_SOURCE

#include "wireguard.h"

#include <errno.h>
#include <linux/genetlink.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/wireguard.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define NETLINK_BUFFER_SIZE 65536u

struct nl_builder {
    _Alignas(struct nlmsghdr) uint8_t bytes[NETLINK_BUFFER_SIZE];
    size_t length;
};

static _Atomic uint32_t next_sequence = 1;

static uint32_t allocate_sequence(void)
{
    uint32_t sequence = atomic_fetch_add(&next_sequence, 1);
    if (sequence == 0) {
        sequence = atomic_fetch_add(&next_sequence, 1);
    }
    return sequence;
}

static void wipe_bytes(void *memory, size_t length)
{
    volatile uint8_t *bytes = memory;
    while (length-- > 0) {
        *bytes++ = 0;
    }
}

static int validate_ifname(const char *ifname)
{
    if (ifname == NULL || ifname[0] == '\0' ||
        strnlen(ifname, IFNAMSIZ) >= IFNAMSIZ) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

static int builder_begin(struct nl_builder *builder, uint16_t type,
                         uint16_t flags, uint32_t sequence, uint32_t port_id,
                         size_t payload_length)
{
    const size_t header_length = NLMSG_HDRLEN + payload_length;
    if (header_length > sizeof(builder->bytes)) {
        errno = EMSGSIZE;
        return -1;
    }

    memset(builder->bytes, 0, header_length);
    builder->length = header_length;

    struct nlmsghdr *header = (struct nlmsghdr *)builder->bytes;
    header->nlmsg_len = (uint32_t)header_length;
    header->nlmsg_type = type;
    header->nlmsg_flags = flags;
    header->nlmsg_seq = sequence;
    header->nlmsg_pid = port_id;
    return 0;
}

static int builder_add_attr(struct nl_builder *builder, uint16_t type,
                            const void *data, size_t data_length)
{
    const size_t offset = NLMSG_ALIGN(builder->length);
    if (data_length > SIZE_MAX - sizeof(struct nlattr)) {
        errno = EMSGSIZE;
        return -1;
    }
    const size_t attribute_length = sizeof(struct nlattr) + data_length;
    if (data_length > 0 && data == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (attribute_length > UINT16_MAX) {
        errno = EMSGSIZE;
        return -1;
    }
    const size_t aligned_length = NLA_ALIGN(attribute_length);
    if (offset > sizeof(builder->bytes) ||
        aligned_length > sizeof(builder->bytes) - offset) {
        errno = EMSGSIZE;
        return -1;
    }

    memset(builder->bytes + builder->length, 0, offset - builder->length);
    struct nlattr *attribute = (struct nlattr *)(builder->bytes + offset);
    attribute->nla_len = (uint16_t)attribute_length;
    attribute->nla_type = type;
    if (data_length > 0) {
        memcpy((uint8_t *)attribute + sizeof(*attribute), data, data_length);
    }

    builder->length = offset + aligned_length;
    ((struct nlmsghdr *)builder->bytes)->nlmsg_len = (uint32_t)builder->length;
    return 0;
}

static int builder_start_nested(struct nl_builder *builder, uint16_t type,
                                size_t *nest_offset)
{
    const size_t offset = NLMSG_ALIGN(builder->length);
    if (offset > sizeof(builder->bytes) ||
        sizeof(struct nlattr) > sizeof(builder->bytes) - offset) {
        errno = EMSGSIZE;
        return -1;
    }

    memset(builder->bytes + builder->length, 0, offset - builder->length);
    struct nlattr *attribute = (struct nlattr *)(builder->bytes + offset);
    attribute->nla_len = sizeof(*attribute);
    attribute->nla_type = (uint16_t)(type | NLA_F_NESTED);
    builder->length = offset + sizeof(*attribute);
    ((struct nlmsghdr *)builder->bytes)->nlmsg_len = (uint32_t)builder->length;
    *nest_offset = offset;
    return 0;
}

static int builder_end_nested(struct nl_builder *builder, size_t nest_offset)
{
    if (nest_offset >= builder->length ||
        builder->length - nest_offset > UINT16_MAX) {
        errno = EMSGSIZE;
        return -1;
    }
    struct nlattr *attribute = (struct nlattr *)(builder->bytes + nest_offset);
    attribute->nla_len = (uint16_t)(builder->length - nest_offset);
    return 0;
}

static int open_netlink(int protocol, uint32_t *port_id)
{
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, protocol);
    if (fd < 0) {
        return -1;
    }

    struct sockaddr_nl local = { .nl_family = AF_NETLINK };
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }

    struct timeval receive_timeout = { .tv_sec = 5 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &receive_timeout,
                   sizeof(receive_timeout)) < 0) {
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
    *port_id = local.nl_pid;
    return fd;
}

static int send_request(int fd, const struct nl_builder *builder)
{
    struct sockaddr_nl kernel = { .nl_family = AF_NETLINK };
    ssize_t sent;
    do {
        sent = sendto(fd, builder->bytes, builder->length, 0,
                      (struct sockaddr *)&kernel, sizeof(kernel));
    } while (sent < 0 && errno == EINTR);

    if (sent < 0) {
        return -1;
    }
    if ((size_t)sent != builder->length) {
        errno = EIO;
        return -1;
    }
    return 0;
}

static int receive_matching_message(int fd, uint32_t sequence,
                                    struct nlmsghdr *message,
                                    size_t message_capacity)
{
    _Alignas(struct nlmsghdr) uint8_t buffer[NETLINK_BUFFER_SIZE];
    for (;;) {
        struct sockaddr_nl sender = { 0 };
        struct iovec iov = { .iov_base = buffer, .iov_len = sizeof(buffer) };
        struct msghdr packet = {
            .msg_name = &sender,
            .msg_namelen = sizeof(sender),
            .msg_iov = &iov,
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
            if (header->nlmsg_len > message_capacity) {
                errno = EMSGSIZE;
                return -1;
            }
            memcpy(message, header, header->nlmsg_len);
            return 0;
        }
        if (remaining != 0) {
            errno = EPROTO;
            return -1;
        }
    }
}

static int wait_for_ack(int fd, uint32_t sequence)
{
    _Alignas(struct nlmsghdr) uint8_t response[NETLINK_BUFFER_SIZE];
    for (;;) {
        struct nlmsghdr *header = (struct nlmsghdr *)response;
        if (receive_matching_message(fd, sequence, header, sizeof(response)) < 0) {
            return -1;
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
}

static int send_and_wait_for_ack(int protocol, struct nl_builder *builder)
{
    uint32_t port_id;
    int fd = open_netlink(protocol, &port_id);
    if (fd < 0) {
        return -1;
    }
    ((struct nlmsghdr *)builder->bytes)->nlmsg_pid = port_id;

    int result = send_request(fd, builder);
    if (result == 0) {
        result = wait_for_ack(fd, ((struct nlmsghdr *)builder->bytes)->nlmsg_seq);
    }
    int saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return result;
}

static int send_and_receive(int protocol, struct nl_builder *builder,
                            struct nlmsghdr *response, size_t response_capacity)
{
    uint32_t port_id;
    int fd = open_netlink(protocol, &port_id);
    if (fd < 0) {
        return -1;
    }
    ((struct nlmsghdr *)builder->bytes)->nlmsg_pid = port_id;

    int result = send_request(fd, builder);
    if (result == 0) {
        result = receive_matching_message(
            fd, ((struct nlmsghdr *)builder->bytes)->nlmsg_seq,
            response, response_capacity);
    }
    int saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return result;
}

static int add_link_name(struct nl_builder *builder, const char *ifname)
{
    return builder_add_attr(builder, IFLA_IFNAME, ifname, strlen(ifname) + 1);
}

int wg_link_create(const char *ifname)
{
    if (validate_ifname(ifname) < 0) {
        return -1;
    }

    struct nl_builder builder;
    uint32_t sequence = allocate_sequence();
    if (builder_begin(&builder, RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK |
                      NLM_F_CREATE | NLM_F_EXCL, sequence, 0,
                      sizeof(struct ifinfomsg)) < 0) {
        return -1;
    }

    struct ifinfomsg *info = (struct ifinfomsg *)(builder.bytes + NLMSG_HDRLEN);
    info->ifi_family = AF_UNSPEC;
    size_t link_info;
    if (add_link_name(&builder, ifname) < 0 ||
        builder_start_nested(&builder, IFLA_LINKINFO, &link_info) < 0 ||
        builder_add_attr(&builder, IFLA_INFO_KIND, "wireguard", sizeof("wireguard")) < 0) {
        return -1;
    }
    if (builder_end_nested(&builder, link_info) < 0) {
        return -1;
    }

    return send_and_wait_for_ack(NETLINK_ROUTE, &builder);
}

static int find_link_index(const char *ifname, unsigned int *ifindex)
{
    if (validate_ifname(ifname) < 0) {
        return -1;
    }
    errno = 0;
    unsigned int index = if_nametoindex(ifname);
    if (index == 0) {
        if (errno == 0) {
            errno = ENODEV;
        }
        return -1;
    }
    *ifindex = index;
    return 0;
}

static int change_link_state(const char *ifname, bool up, bool remove)
{
    unsigned int ifindex;
    if (find_link_index(ifname, &ifindex) < 0) {
        return -1;
    }

    struct nl_builder builder;
    uint32_t sequence = allocate_sequence();
    uint16_t type = remove ? RTM_DELLINK : RTM_NEWLINK;
    if (builder_begin(&builder, type, NLM_F_REQUEST | NLM_F_ACK, sequence, 0,
                      sizeof(struct ifinfomsg)) < 0) {
        return -1;
    }

    struct ifinfomsg *info = (struct ifinfomsg *)(builder.bytes + NLMSG_HDRLEN);
    info->ifi_family = AF_UNSPEC;
    info->ifi_index = (int)ifindex;
    if (!remove) {
        info->ifi_change = IFF_UP;
        info->ifi_flags = up ? IFF_UP : 0;
    }
    return send_and_wait_for_ack(NETLINK_ROUTE, &builder);
}

int wg_link_set_up(const char *ifname)
{
    return change_link_state(ifname, true, false);
}

int wg_link_delete(const char *ifname)
{
    return change_link_state(ifname, false, true);
}

static int resolve_wireguard_family(uint16_t *family_id)
{
    struct nl_builder request;
    uint32_t sequence = allocate_sequence();
    if (builder_begin(&request, GENL_ID_CTRL, NLM_F_REQUEST, sequence, 0,
                      GENL_HDRLEN) < 0) {
        return -1;
    }

    struct genlmsghdr *generic =
        (struct genlmsghdr *)(request.bytes + NLMSG_HDRLEN);
    generic->cmd = CTRL_CMD_GETFAMILY;
    generic->version = 1;
    if (builder_add_attr(&request, CTRL_ATTR_FAMILY_NAME,
                         WG_GENL_NAME, sizeof(WG_GENL_NAME)) < 0) {
        return -1;
    }

    _Alignas(struct nlmsghdr) uint8_t response[NETLINK_BUFFER_SIZE];
    if (send_and_receive(NETLINK_GENERIC, &request,
                         (struct nlmsghdr *)response, sizeof(response)) < 0) {
        return -1;
    }

    struct nlmsghdr *header = (struct nlmsghdr *)response;
    if (header->nlmsg_type == NLMSG_ERROR) {
        if (header->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
            errno = EPROTO;
            return -1;
        }
        const struct nlmsgerr *error = NLMSG_DATA(header);
        errno = error->error == 0 ? EPROTO : -error->error;
        return -1;
    }
    if (header->nlmsg_len < NLMSG_LENGTH(GENL_HDRLEN)) {
        errno = EPROTO;
        return -1;
    }

    size_t remaining = header->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);
    const uint8_t *cursor = (const uint8_t *)NLMSG_DATA(header) + GENL_HDRLEN;
    while (remaining >= sizeof(struct nlattr)) {
        const struct nlattr *attribute = (const struct nlattr *)cursor;
        if (attribute->nla_len < sizeof(*attribute) || attribute->nla_len > remaining) {
            errno = EPROTO;
            return -1;
        }
        if ((attribute->nla_type & NLA_TYPE_MASK) == CTRL_ATTR_FAMILY_ID &&
            attribute->nla_len == NLA_HDRLEN + sizeof(uint16_t)) {
            memcpy(family_id, cursor + NLA_HDRLEN, sizeof(*family_id));
            return 0;
        }
        size_t step = NLA_ALIGN(attribute->nla_len);
        if (step > remaining) {
            break;
        }
        cursor += step;
        remaining -= step;
    }

    errno = EPROTO;
    return -1;
}

static int validate_peer(const struct wg_peer_config *peer)
{
    if (peer->allowed_ip_count > 0 && peer->allowed_ips == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (peer->endpoint != NULL) {
           if ((peer->endpoint->sa_family == AF_INET &&
               peer->endpoint_len != sizeof(struct sockaddr_in)) ||
              (peer->endpoint->sa_family == AF_INET6 &&
               peer->endpoint_len != sizeof(struct sockaddr_in6)) ||
            (peer->endpoint->sa_family != AF_INET &&
             peer->endpoint->sa_family != AF_INET6)) {
            errno = EINVAL;
            return -1;
        }
    } else if (peer->endpoint_len != 0) {
        errno = EINVAL;
        return -1;
    }

    for (size_t index = 0; index < peer->allowed_ip_count; ++index) {
        const struct wg_allowed_ip *allowed = &peer->allowed_ips[index];
        if ((allowed->family == AF_INET && allowed->cidr > 32) ||
            (allowed->family == AF_INET6 && allowed->cidr > 128) ||
            (allowed->family != AF_INET && allowed->family != AF_INET6)) {
            errno = EINVAL;
            return -1;
        }
    }
    return 0;
}

static int append_allowed_ip(struct nl_builder *builder,
                             const struct wg_allowed_ip *allowed)
{
    size_t nested;
    uint16_t family = (uint16_t)allowed->family;
    size_t address_length = allowed->family == AF_INET
        ? sizeof(struct in_addr) : sizeof(struct in6_addr);
    if (builder_start_nested(builder, 1, &nested) < 0 ||
        builder_add_attr(builder, WGALLOWEDIP_A_FAMILY,
                         &family, sizeof(family)) < 0 ||
        builder_add_attr(builder, WGALLOWEDIP_A_IPADDR,
                         allowed->address, address_length) < 0 ||
        builder_add_attr(builder, WGALLOWEDIP_A_CIDR_MASK,
                         &allowed->cidr, sizeof(allowed->cidr)) < 0) {
        return -1;
    }
    return builder_end_nested(builder, nested);
}

static int append_peer(struct nl_builder *builder, uint16_t peer_number,
                       const struct wg_peer_config *peer)
{
    size_t peer_nest;
    if (builder_start_nested(builder, peer_number, &peer_nest) < 0 ||
        builder_add_attr(builder, WGPEER_A_PUBLIC_KEY,
                         peer->public_key, sizeof(peer->public_key)) < 0) {
        return -1;
    }
    if (peer->preshared_key != NULL &&
        builder_add_attr(builder, WGPEER_A_PRESHARED_KEY,
                         peer->preshared_key, WG_KEY_LEN) < 0) {
        return -1;
    }
    if (peer->endpoint != NULL &&
        builder_add_attr(builder, WGPEER_A_ENDPOINT,
                         peer->endpoint, peer->endpoint_len) < 0) {
        return -1;
    }
    if (peer->set_persistent_keepalive &&
        builder_add_attr(builder, WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL,
                         &peer->persistent_keepalive_interval,
                         sizeof(peer->persistent_keepalive_interval)) < 0) {
        return -1;
    }

    uint32_t peer_flags = peer->replace_allowed_ips
        ? WGPEER_F_REPLACE_ALLOWEDIPS : 0;
    if (peer_flags != 0 &&
        builder_add_attr(builder, WGPEER_A_FLAGS,
                         &peer_flags, sizeof(peer_flags)) < 0) {
        return -1;
    }

    if (peer->allowed_ip_count > 0) {
        size_t allowed_ips_nest;
        if (builder_start_nested(builder, WGPEER_A_ALLOWEDIPS,
                                 &allowed_ips_nest) < 0) {
            return -1;
        }
        for (size_t index = 0; index < peer->allowed_ip_count; ++index) {
            if (append_allowed_ip(builder, &peer->allowed_ips[index]) < 0) {
                return -1;
            }
        }
        if (builder_end_nested(builder, allowed_ips_nest) < 0) {
            return -1;
        }
    }
    return builder_end_nested(builder, peer_nest);
}

int wg_device_configure(const struct wg_device_config *config)
{
    unsigned int ifindex;
    if (config == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (validate_ifname(config->ifname) < 0 ||
        (config->peer_count > 0 && config->peers == NULL)) {
        return -1;
    }
    if (find_link_index(config->ifname, &ifindex) < 0) {
        return -1;
    }
    for (size_t index = 0; index < config->peer_count; ++index) {
        if (validate_peer(&config->peers[index]) < 0) {
            return -1;
        }
    }

    uint16_t family_id;
    if (resolve_wireguard_family(&family_id) < 0) {
        return -1;
    }

    struct nl_builder request;
    memset(&request, 0, sizeof(request));
    uint32_t sequence = allocate_sequence();
    if (builder_begin(&request, family_id, NLM_F_REQUEST | NLM_F_ACK,
                      sequence, 0, GENL_HDRLEN) < 0) {
        return -1;
    }
    struct genlmsghdr *generic =
        (struct genlmsghdr *)(request.bytes + NLMSG_HDRLEN);
    generic->cmd = WG_CMD_SET_DEVICE;
    generic->version = WG_GENL_VERSION;

    uint32_t device_flags = config->replace_peers ? WGDEVICE_F_REPLACE_PEERS : 0;
    if (builder_add_attr(&request, WGDEVICE_A_IFINDEX,
                         &ifindex, sizeof(ifindex)) < 0 ||
        (config->private_key != NULL &&
         builder_add_attr(&request, WGDEVICE_A_PRIVATE_KEY,
                          config->private_key, WG_KEY_LEN) < 0) ||
        (config->set_listen_port &&
         builder_add_attr(&request, WGDEVICE_A_LISTEN_PORT,
                          &config->listen_port, sizeof(config->listen_port)) < 0) ||
        (config->set_fwmark &&
         builder_add_attr(&request, WGDEVICE_A_FWMARK,
                          &config->fwmark, sizeof(config->fwmark)) < 0) ||
        (device_flags != 0 &&
         builder_add_attr(&request, WGDEVICE_A_FLAGS,
                          &device_flags, sizeof(device_flags)) < 0)) {
        wipe_bytes(request.bytes, sizeof(request.bytes));
        return -1;
    }

    if (config->peer_count > 0) {
        size_t peers_nest;
        if (builder_start_nested(&request, WGDEVICE_A_PEERS, &peers_nest) < 0) {
            wipe_bytes(request.bytes, sizeof(request.bytes));
            return -1;
        }
        for (size_t index = 0; index < config->peer_count; ++index) {
            if (index >= UINT16_MAX ||
                append_peer(&request, (uint16_t)(index + 1),
                            &config->peers[index]) < 0) {
                if (index >= UINT16_MAX) {
                    errno = E2BIG;
                }
                wipe_bytes(request.bytes, sizeof(request.bytes));
                return -1;
            }
        }
        if (builder_end_nested(&request, peers_nest) < 0) {
            wipe_bytes(request.bytes, sizeof(request.bytes));
            return -1;
        }
    }

    int result = send_and_wait_for_ack(NETLINK_GENERIC, &request);
    int saved_errno = errno;
    wipe_bytes(request.bytes, sizeof(request.bytes));
    errno = saved_errno;
    return result;
}