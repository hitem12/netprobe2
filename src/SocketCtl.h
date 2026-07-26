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
#include <linux/if_ether.h>
#include <print>
#include <linux/net_tstamp.h>
#include<cstring>
#include <unistd.h>
#include <linux/ip.h>
#include <array>
#include "logger.hpp"
#include "Parsers.h"
#include "ipv4_parser.h"
#include <format>
#include <net/if.h>

struct InterfaceInfo
{
    int ifindex;
    std::array<uint8_t,6> mac;
    int mtu;
};
template<>
struct fmt::formatter<InterfaceInfo> : fmt::formatter<std::string_view>
{
    auto format(const InterfaceInfo& info, fmt::format_context& ctx) const
    {
        return fmt::format_to(ctx.out(), "ifindex: {} mac: '{}' mtu: {}", info.ifindex, parsers::parse_mac(info.mac), info.mtu);
    }
};
class SocketCtl
{
    InterfaceInfo info;
    int fd_ {};
public:
    SocketCtl() =default;
    SocketCtl(const SocketCtl&) = delete;
    SocketCtl(SocketCtl&&) = delete;
    SocketCtl& operator=(const SocketCtl&) = delete;
    SocketCtl& operator=(SocketCtl&&) = delete;
    ~SocketCtl() {if (fd_ > 0) {close_socket();}}
    [[nodiscard]] int get() const {return fd_;}
    [[nodiscard]] std::expected<void, std::error_code> open_socket(std::string_view interface);
    void close_socket();
    InterfaceInfo get_socker_info() const {return info;}
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
        return {};
    }
    [[nodiscard]] std::expected<void, std::error_code> get_MTU_info(const ifreq &ifr)
    {
        if (ioctl(fd_, SIOCGIFMTU, &ifr) != 0)
        {
            return std::unexpected{std::error_code{errno, std::generic_category()}};
        }
        info.mtu = ifr.ifr_mtu;
        return {};
    }
    [[nodiscard]] std::expected<void, std::error_code> get_mac_info(const ifreq &ifr)
    {
        if (ioctl(fd_, SIOCGIFHWADDR, &ifr) !=0 )
        {
            return std::unexpected{std::error_code{errno, std::generic_category()}};
        }
        std::copy_n(ifr.ifr_hwaddr.sa_data, std::size(info.mac), std::begin(info.mac));
        return {};
    }
    [[nodiscard]] std::expected<void, std::error_code> get_if_index(const ifreq &ifr)
    {
        if (ioctl(fd_, SIOCGIFINDEX, &ifr) != 0)
        {
            return std::unexpected{std::error_code{errno, std::generic_category()}};
        }
        info.ifindex = ifr.ifr_ifindex;
        return {};
    }

};

#endif  // NETLEARN_SOCETCTL_H
