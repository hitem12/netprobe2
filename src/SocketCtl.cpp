//
// Created by tomaszp on 8.06.2026.
//

#include "SocketCtl.h"
std::expected<void, std::error_code> SocketCtl::open_socket(const std::string_view interface)
{
    fd_ = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (!fd_)
    {
        return std::unexpected{std::error_code{errno, std::generic_category()}};
    }
    if (auto status = get_interface_info(interface); !status) return status;

    // ── promiscuous mode ───────────────────────────────────
    struct packet_mreq mr{};
    mr.mr_ifindex = info.ifindex;
    mr.mr_type = PACKET_MR_PROMISC;
    if (setsockopt(fd_, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0)
    {
        return std::unexpected{std::error_code{errno, std::generic_category()}};
    }

    // ── receive buffer ─────────────────────────────────────
    int size = 4 * 1024 * 1024;  // 4MB
    setsockopt(fd_, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));

    int flags = SOF_TIMESTAMPING_RX_HARDWARE | SOF_TIMESTAMPING_RX_SOFTWARE |
                SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_RAW_HARDWARE;
    if (setsockopt(fd_, SOL_SOCKET, SO_TIMESTAMPING, &flags, sizeof(flags)) != 0)
    {
        return std::unexpected{std::error_code{errno, std::generic_category()}};
    }

    struct sockaddr_ll addr{};
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex = info.ifindex;

    if (bind(fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)))
    {
        return std::unexpected{std::error_code{errno, std::generic_category()}};
    }
    return {};
}
void SocketCtl::close_socket()
{
    const struct packet_mreq mr_end = {
        .mr_ifindex = info.ifindex,
        .mr_type = PACKET_MR_PROMISC,
    };
    setsockopt(fd_, SOL_PACKET, PACKET_DROP_MEMBERSHIP, &mr_end, sizeof(mr_end));
    close(fd_);
    fd_ = -1;
}