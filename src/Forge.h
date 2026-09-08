//
// Created by tomaszp on 8.06.2026.
//

#ifndef NETLEARN_FORGE_H
#define NETLEARN_FORGE_H
#pragma once
#include <expected>
#include <span>
#include <system_error>
#include <SocketCtl.h>
#include <netinet/if_ether.h>
#include "EthernetHeader.h"
#include "IPv4HeaderBuilder.h"
#include "ArpHeader.h"
namespace net {
struct ForgeArgs
{
    std::array<uint8_t, 6> dst_mac;
    EthernetType eth_type;
    Ipv4 ip4_addr;
    std::optional<Ipv4> target_ipv4;
};
class Forge
{

public:
    static std::expected<PacketBuffer, std::error_code> forge(const SocketCtl & socket,
       const ForgeArgs & args)
    {
        const auto log = Logger::get();
        const int fd = socket.get();
        auto info = socket.get_socker_info();
        log->info("{}", info);
        PacketBuffer buf;
        const EthernetHeader eth_header {
        .dst_mac = {args.dst_mac},
        .src_mac = {info.mac},
        .vlan_tag =  {std::nullopt},
        .type = args.eth_type,
        };
        eth_header.serialize(buf);
        switch (args.eth_type)
        {
            case EthernetType::ARP:
                {
                    ArpHeader arp_header {
                        .htype = arp_htype::ethernet,
                        .ptype = arp_ptype::ipv4,
                        .hlen = 6,
                        .plen = 4,
                        .oper = arp_oper::request,
                        .sha = {},
                        .spa = {},
                        .tha = {},
                        .tpa = {}
                    };
                    std::ranges::copy(args.dst_mac, arp_header.sha.begin());
                    std::ranges::copy(info.mac, arp_header.tha.begin());
                    Ipv4 target_ipv4 = info.ipv4;
                    if (args.target_ipv4.has_value())
                    {
                        target_ipv4 = *args.target_ipv4;
                    }
                    log->debug("self {} asking {}", target_ipv4, args.ip4_addr);
                    std::ranges::copy(target_ipv4.get_array(), arp_header.spa.begin()+2);
                    std::ranges::copy(args.ip4_addr.get_array(), arp_header.tpa.begin()+2);
                    arp_header.serialize(buf);
                }
                break;
            case EthernetType::IPv4:
                IPv4HeaderBuilder ipv4_header_builder;
                std::unexpected(std::make_error_code(std::errc::function_not_supported));
                break;
        }

        return buf;
    }
private:


};
}
#endif  // NETLEARN_FORGE_H
