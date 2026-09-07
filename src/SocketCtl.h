//
// Created by tomaszp on 8.06.2026.
//

#ifndef NETLEARN_SOCETCTL_H
#define NETLEARN_SOCETCTL_H
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/net_tstamp.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <array>
#include <cstring>
#include <expected>
#include <format>
#include <print>
#include <system_error>
#include "Ipv4.h"
#include "PacketBuffer.h"
#include "Parsers.h"
#include "ipv4_parser.h"
#include "logger.hpp"
struct InterfaceInfo
{
    int ifindex;
    std::array<uint8_t,6> mac;
    int mtu;
    net::Ipv4 ipv4;
};
template<>
struct fmt::formatter<InterfaceInfo> : fmt::formatter<std::string_view>
{
    auto format(const InterfaceInfo& info, fmt::format_context& ctx) const
    {
        return fmt::format_to(ctx.out(), "ifindex: {} ip: {} mac: '{}' mtu: {}", info.ifindex, info.ipv4, parsers::parse_mac(info.mac), info.mtu);
    }
};
class SocketCtl
{
    InterfaceInfo info_;
    int fd_ {};
public:
    SocketCtl() = default;
    SocketCtl(const SocketCtl&) = delete;
    SocketCtl(SocketCtl&&) = delete;
    SocketCtl& operator=(const SocketCtl&) = delete;
    SocketCtl& operator=(SocketCtl&&) = delete;
    ~SocketCtl() {if (fd_ > 0) {close_socket();}}
    [[nodiscard]] int get() const {return fd_;}
    [[nodiscard]] std::expected<void, std::error_code> open_socket(std::string_view interface);
    std::optional<std::error_code> send(net::PacketBuffer buff)
    {
        if (fd_ < 0) return std::error_code(errno, std::system_category());
        if (info_.ifindex == 0) return std::make_error_code(std::errc::bad_address);
        sockaddr_ll addr{};
        addr.sll_family   = AF_PACKET;
        addr.sll_ifindex  = info_.ifindex;
        addr.sll_halen    = ETH_ALEN;
        addr.sll_protocol = htons(ETH_P_ARP);
        addr.sll_halen = 6;
        if (::sendto(fd_, buff.data(), buff.size(), 0, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != buff.size())
        {
            return std::error_code{errno, std::generic_category()};
        }
        return std::nullopt;
    }
    void close_socket();
    InterfaceInfo get_socker_info() const {return info_;}
private:
    [[nodiscard]] std::expected<void, std::error_code>  get_interface_info(const std::string_view interface)
    {
        struct ifreq ifr{};
        strncpy(ifr.ifr_name, interface.data(), IF_NAMESIZE - 1);
        auto status = get_if_index(ifr);
        if (!status) return status;
        status = get_mac_info(ifr);
        if (!status) return status;
        status = get_MTU_info(ifr);
        if (!status) return status;
        if (const auto error = get_ipv4_info(ifr))
        {
            return std::unexpected(error.value());
        }
        return {};
    }
    [[nodiscard]] std::expected<void, std::error_code> get_MTU_info(const ifreq &ifr)
    {
        if (ioctl(fd_, SIOCGIFMTU, &ifr) != 0)
        {
            return std::unexpected{std::error_code{errno, std::generic_category()}};
        }
        info_.mtu = ifr.ifr_mtu;
        return {};
    }
    [[nodiscard]] std::expected<void, std::error_code> get_mac_info(const ifreq &ifr)
    {
        if (ioctl(fd_, SIOCGIFHWADDR, &ifr) !=0 )
        {
            return std::unexpected{std::error_code{errno, std::generic_category()}};
        }
        std::copy_n(ifr.ifr_hwaddr.sa_data, std::size(info_.mac), std::begin(info_.mac));
        return {};
    }
    [[nodiscard]] std::expected<void, std::error_code> get_if_index(const ifreq &ifr)
    {
        if (ioctl(fd_, SIOCGIFINDEX, &ifr) != 0)
        {
            return std::unexpected{std::error_code{errno, std::generic_category()}};
        }
        info_.ifindex = ifr.ifr_ifindex;
        return {};
    }
    [[nodiscard]] std::optional<std::error_code> get_ipv4_info(const ifreq &ifr)
    {
        if (ioctl(fd_, SIOCGIFADDR, &ifr) != 0)
        {
            return  std::error_code{errno, std::system_category()};
        }
        const auto* sin = reinterpret_cast<const sockaddr_in*>(&ifr.ifr_addr);
        if (sin->sin_family != AF_INET) return std::make_error_code(std::errc::address_not_available);
        info_.ipv4 = net::Ipv4::from_network(sin->sin_addr.s_addr);
        return std::nullopt;
    }
};

#endif  // NETLEARN_SOCETCTL_H
