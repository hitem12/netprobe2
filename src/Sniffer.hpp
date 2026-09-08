//
// Created by tomaszp on 8.05.2026.
//
#pragma once
#ifndef NETLEARN_DUMMY_AF_HPP
#define NETLEARN_DUMMY_AF_HPP

#include <net/if_arp.h>
#include <string>

#include <linux/ipv6.h>
#include <chrono>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include "control_massage_header.h"
#include "SocketCtl.h"
#include "Parsers.h"
#include "Epoll.h"
#include "RecvBuffer.h"
#include <PacketReader.h>
using namespace parsers;

using steady_clock = std::chrono::steady_clock;
struct EPB {
    uint32_t block_type        = 0x00000006;
    uint32_t block_length;
    uint32_t interface_id;
    uint32_t timestamp_high;
    uint32_t timestamp_low;
    uint32_t captured_len;
    uint32_t original_len;
    // uint8_t packet_data[captured_len]  (padded to 32-bit boundary)
    // [opcje]
    uint32_t block_length_end;
};

class Sniffer
{

   public:
    static  std::error_code poll(const SocketCtl &socket_ctl,const uint32_t max_events =16)
    {
        const auto log = Logger::get();
        auto epoll_ex = net::Epoll::create();
        if (!epoll_ex.has_value())
        {
            return epoll_ex.error();
        }
        net::Epoll epoll = std::move(epoll_ex.value());
        if (const auto status = epoll.add(socket_ctl.get());status)
        {
            return status;
        }
        log->debug("epoll created for {}", socket_ctl.get());
        net::RecvBuffer<1> recv_buffer;
        for (;;)
        {
            epoll_event events[max_events];
            const auto nfds = epoll.wait(events, 16, -1);
            if (nfds == -1)
            {
                return std::error_code{errno, std::generic_category()};
            }
            log->debug("receive poll size {}", nfds);
            for (size_t n = 0; n < nfds; ++n)
            {
                if (events[n].data.fd != socket_ctl.get())
                {
                    // do_use_fd(events[n].data.fd);
                    continue;
                }
                recv_buffer.reset();
                if (const ssize_t r = ::recvmsg(socket_ctl.get(), recv_buffer.get_msghdr(), 0); r == -1)
                {
                    if (EAGAIN == errno || EWOULDBLOCK == errno) break;
                    switch (errno)
                    {
                        case EINTR:
                            continue;
                        case ENETDOWN:
                        case ENODEV:
                        case ENXIO:
                            return std::error_code{errno, std::generic_category()};
                        default:
                            return std::error_code(errno, std::system_category());
                    }
                }
                parse_frame(recv_buffer.get_msghdr());
            }
        }
    }
    static void parse_frame(struct msghdr* msghdr)
    {
        const auto log = Logger::get();
        // metadata
        frame::control_massage_header::parse(msghdr);
        // header
        auto* bufs = msghdr->msg_iov->iov_base;
        const struct ethhdr* eth = static_cast<struct ethhdr*>(bufs);
        log->info("Header: \ndst: {}, src: {}", parse_mac(eth->h_source), parse_mac(eth->h_source));

        switch (uint16_t ethertype = ntohs(eth->h_proto))
        {
            case ETH_P_8021Q:
            {
                const struct vlan_hdr* vlan =
                    static_cast<struct vlan_hdr*>(bufs + sizeof(struct ethhdr));
                log->info(parse_vlan(vlan));
                break;
            }
            case ETH_P_IP:
            {
                const struct iphdr* ip4_hdr =
                    reinterpret_cast<struct iphdr*>(bufs + sizeof(struct ethhdr));
                log->info(frame::ipv4_parser::log_frame(ip4_hdr));
                net::PacketReader packet_reader(std::span<uint8_t>(static_cast<uint8_t*>(bufs)+sizeof(struct ethhdr), sizeof(struct iphdr) + sizeof(struct ethhdr)));
                net::IPv4Header iph;
                if (const auto err = iph.deserialize(packet_reader); err)
                {
                    log->error("Ipv4 Parsing error: {}", err.message());
                }
                log->info("FROM PACKET READER: {}", iph);
                break;
            }
            case (ETH_P_IPV6):
            {
                const struct ipv6hdr* ip6_hdr =
                    reinterpret_cast<struct ipv6hdr*>(bufs + sizeof(struct ethhdr));
                char src_str[INET_ADDRSTRLEN];
                char dst_str[INET_ADDRSTRLEN];

                inet_ntop(AF_INET, &ip6_hdr->saddr, src_str, sizeof(src_str));
                inet_ntop(AF_INET, &ip6_hdr->daddr, dst_str, sizeof(dst_str));
                log->info("ipv6 src: {}, dst: {}", src_str, dst_str);
                break;
            }
            case ETH_P_ARP:
            {
                const static ether_arp* arp =
                    reinterpret_cast<ether_arp*>(bufs + sizeof(struct ethhdr));
                uint16_t op = ntohs(arp->ea_hdr.ar_op);

                // sender
                char spa[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, arp->arp_spa, spa, sizeof(spa));

                // target
                char tpa[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, arp->arp_tpa, tpa, sizeof(tpa));

                switch (op)
                {
                    case ARPOP_REQUEST:
                    {
                        log->info("ARP request: who has {} tell {}\n sender MAC: {}", tpa, spa,
                                  parse_mac(arp->arp_sha));
                        break;
                    }
                    case ARPOP_REPLY:
                    {
                        log->info("ARP reply: {} is at {}", spa, parse_mac(arp->arp_sha));
                        break;
                    }
                    default:
                    {
                        log->info("ARP reply: unknown opcode: {}", op);
                    }
                }
                break;
            }
            default:
                log->info("Unknown ethernet type: {}", ethertype);
        }
    }
    static std::error_code sniff(const SocketCtl &socket_ctl, const size_t packet_count)
    {
        const auto log = Logger::get();
        const int fd = socket_ctl.get();
        if (fd==0)
        {
            return std::error_code{ std::make_error_code(std::errc::bad_address)};
        }
#define BATCH_SIZE 32
        net::RecvBuffer<BATCH_SIZE> recv_buffers;

        int received = recvmmsg(fd, recv_buffers.get_mmsghdr(), packet_count, 0, NULL);
            if (received < 0) { return std::error_code{errno, std::generic_category()};}
        log->debug("received {}", received);
        for (int i = 0; i < received; ++i)
        {
            parse_frame(recv_buffers.get_msghdr(i));
        }
        return {};
    }

};


#endif  // NETLEARN_DUMMY_AF_HPP
