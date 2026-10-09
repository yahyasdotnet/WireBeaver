#ifndef WIREBEAVER_LINUX_WIREGUARD_H
#define WIREBEAVER_LINUX_WIREGUARD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <net/if.h>
#include <sys/socket.h>

struct wg_allowed_ip {
    /* Address bytes are in network order; only 4 bytes are used for AF_INET. */
    int family;
    uint8_t address[16];
    uint8_t cidr;
};

struct wg_peer_config {
    uint8_t public_key[32];
    const uint8_t *preshared_key;
    const struct sockaddr *endpoint;
    socklen_t endpoint_len;
    const struct wg_allowed_ip *allowed_ips;
    size_t allowed_ip_count;
    bool replace_allowed_ips;
    bool set_persistent_keepalive;
    uint16_t persistent_keepalive_interval;
};

struct wg_device_config {
    const char *ifname;
    const uint8_t *private_key;
    bool set_listen_port;
    uint16_t listen_port;
    bool set_fwmark;
    uint32_t fwmark;
    bool replace_peers;
    const struct wg_peer_config *peers;
    size_t peer_count;
};

/* Return 0 on success, or -1 with errno set. These operations require CAP_NET_ADMIN. */
int wg_link_create(const char *ifname);
int wg_link_set_up(const char *ifname);
int wg_link_delete(const char *ifname);
int wg_device_configure(const struct wg_device_config *config);

#endif