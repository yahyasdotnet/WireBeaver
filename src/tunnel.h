#ifndef WIREBEAVER_TUNNEL_H
#define WIREBEAVER_TUNNEL_H

#include "linux/wireguard.h"

struct tunnel_address {
    int family;
    uint8_t address[16];
    uint8_t prefix_length;
};

struct tunnel_config {
    struct wg_device_config wireguard;
    const struct tunnel_address *addresses;
    size_t address_count;
};

/*
 * Create and configure a kernel WireGuard interface, assign its addresses,
 * then bring it up. Returns 0 on success, or -1 with errno set. Requires
 * CAP_NET_ADMIN. On failure after creation, the newly created link is deleted.
 */
int tunnel_start(const struct tunnel_config *config);

/* Delete the WireGuard interface and its addresses. */
int tunnel_stop(const char *ifname);

#endif