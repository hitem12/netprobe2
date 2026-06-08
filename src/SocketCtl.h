//
// Created by tomaszp on 8.06.2026.
//

#ifndef NETLEARN_SOCETCTL_H
#define NETLEARN_SOCETCTL_H
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <expected>
#include <system_error>
#include <net/if.h>
#include <linux/if_ether.h>
#include <print>
#include <linux/net_tstamp.h>
#include<cstring>
#include <unistd.h>
#include <linux/ip.h>

#include "logger.hpp"

#include "ipv4_parser.h"


class SocketCtl
{
    struct ifreq ifr{};
    int fd_ {};
public:
    ~SocketCtl() {if (fd_ > 0) {close_socket();}}
    const int* get() const {return &fd_;}
    std::expected<bool, std::error_code> open_socket(const std::string_view interface)
    {
        fd_ = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (!fd_){ return std::unexpected{std::error_code{errno, std::generic_category()}};}


        strncpy(ifr.ifr_name, interface.data(), IFNAMSIZ - 1);
        ioctl(fd_, SIOCGIFINDEX, &ifr);

        // ── promiscuous mode ───────────────────────────────────
        struct packet_mreq mr{};
        mr.mr_ifindex = ifr.ifr_ifindex;
        mr.mr_type    = PACKET_MR_PROMISC;
        if (setsockopt(fd_, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
                       &mr, sizeof(mr)) < 0) {
            perror("PACKET_ADD_MEMBERSHIP");
                       }

        // ── receive buffer ─────────────────────────────────────
        int size = 4 * 1024 * 1024;  // 4MB
        setsockopt(fd_, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));

        int flags = SOF_TIMESTAMPING_RX_HARDWARE
          | SOF_TIMESTAMPING_RX_SOFTWARE
          | SOF_TIMESTAMPING_SOFTWARE
          | SOF_TIMESTAMPING_RAW_HARDWARE;
        if (setsockopt(fd_, SOL_SOCKET, SO_TIMESTAMPING, &flags, sizeof(flags)) != 0)
        {return  std::unexpected{std::error_code{errno, std::generic_category()}};}


        struct sockaddr_ll addr{};
        addr.sll_family   = AF_PACKET;
        addr.sll_protocol = htons(ETH_P_ALL);
        addr.sll_ifindex  = ifr.ifr_ifindex;

        if (bind(fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)))
        { return std::unexpected{std::error_code{errno, std::generic_category()}};}
        return true;
    }
    void close_socket()
    {
        const struct packet_mreq mr_end = {
            .mr_ifindex = ifr.ifr_ifindex,
            .mr_type = PACKET_MR_PROMISC,
        };
        setsockopt(fd_, SOL_PACKET, PACKET_DROP_MEMBERSHIP, &mr_end, sizeof(mr_end));
        close(fd_);
        fd_ = -1;
    }
};

#endif  // NETLEARN_SOCETCTL_H
