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
    static auto reserveBuffer()
    {
        struct sockaddr_in name_buf;
        uint8_t      bufs[2048];
        char         cmsg_bufs[256];
        struct iovec iovecs;
        struct msghdr msg;
        iovecs.iov_base = bufs;
        iovecs.iov_len  = sizeof(bufs);

        memset(&msg, 0, sizeof(msg));
        msg.msg_name = &name_buf; // sockaddr_in
        msg.msg_namelen = sizeof(name_buf);
        msg.msg_iov        = &iovecs; //buffer_array (raw frame)
        msg.msg_iovlen     = 1; //number of iov entries
        msg.msg_control    = cmsg_bufs; //cmsghdr (timstamp, TTL)
        msg.msg_controllen = sizeof(cmsg_bufs);
        return msg;
    }
   public:
    static  std::error_code poll(const SocketCtl &socket_ctl,const uint32_t max_events =16)
    {
        auto epoll_ex = net::Epoll::create();
        if (!epoll_ex.has_value())
        {
            return epoll_ex.error();
        }
        net::Epoll epoll = std::move(epoll_ex.value());
        epoll.add(socket_ctl.get(), max_events);
        for (;;)
        {
            epoll_event events[max_events];
            const auto nfds = epoll.wait(events, 16, -1);
            if (nfds == -1)
            {
                return std::error_code{errno, std::generic_category()};
            }
            for (size_t n = 0; n < nfds; ++n)
            {
                if (events[n].data.fd != socket_ctl.get())
                {
                    // do_use_fd(events[n].data.fd);
                    continue;
                }
                auto buff = reserveBuffer();
                const ssize_t r = ::recvmsg(socket_ctl.get(), &buff,  0);
                if (r == -1)
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
            }
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
        // pre-allocate everything — no malloc in the hot path
        struct sockaddr_in name_buf[BATCH_SIZE];
        uint8_t      bufs[BATCH_SIZE][2048];
        char         cmsg_bufs[BATCH_SIZE][256];
        struct iovec iovecs[BATCH_SIZE];
        struct mmsghdr msgvec[BATCH_SIZE];

        // one-time setup
        for (int i = 0; i < BATCH_SIZE; i++) {
            iovecs[i].iov_base = bufs[i];
            iovecs[i].iov_len  = sizeof(bufs[i]);

            memset(&msgvec[i], 0, sizeof(msgvec[i]));
            msgvec[i].msg_hdr.msg_name = &name_buf[i]; // sockaddr_in
            msgvec[i].msg_hdr.msg_namelen = sizeof(name_buf[i]);
            msgvec[i].msg_hdr.msg_iov        = &iovecs[i]; //buffer_array (raw frame)
            msgvec[i].msg_hdr.msg_iovlen     = 1; //number of iov entries
            msgvec[i].msg_hdr.msg_control    = cmsg_bufs[i]; //cmsghdr (timstamp, TTL)
            msgvec[i].msg_hdr.msg_controllen = sizeof(cmsg_bufs[i]);
        }

        int received = recvmmsg(fd, msgvec, packet_count, 0, NULL);
            if (received < 0) { return std::error_code{errno, std::generic_category()};}
        log->debug("received {}", received);
        for (int i = 0; i < received; ++i)
        {
            // metadata
            frame::control_massage_header::parse(&msgvec[i].msg_hdr);
            // header
            const struct ethhdr *eth = reinterpret_cast<struct ethhdr*>(bufs[i]);
            log->info("Header: \ndst: {}, src: {}", parse_mac(eth->h_source), parse_mac(eth->h_source));

            switch (uint16_t ethertype = ntohs(eth->h_proto))
            {
                case ETH_P_8021Q:
                {
                    const struct vlan_hdr *vlan = reinterpret_cast<struct vlan_hdr *>(bufs[i] + sizeof(struct ethhdr));
                    log->info(parse_vlan(vlan));
                    break;
                }
                case ETH_P_IP:
                {
                    const struct iphdr *ip4_hdr = reinterpret_cast<struct iphdr *>(bufs[i] + sizeof(struct ethhdr));
                    log->info(frame::ipv4_parser::log_frame(ip4_hdr));
                    break;
                }
                case (ETH_P_IPV6):
                {
                    const struct ipv6hdr *ip6_hdr = reinterpret_cast<struct ipv6hdr *>(bufs[i] + sizeof(struct ethhdr));
                    char src_str[INET_ADDRSTRLEN];
                    char dst_str[INET_ADDRSTRLEN];

                    inet_ntop(AF_INET, &ip6_hdr->saddr, src_str, sizeof(src_str));
                    inet_ntop(AF_INET, &ip6_hdr->daddr, dst_str, sizeof(dst_str));
                    log->info("ipv6 src: {}, dst: {}", src_str, dst_str);
                    break;
                }
                case ETH_P_ARP:
                {
                    const static ether_arp * arp = reinterpret_cast<ether_arp *>(bufs[i] + sizeof(struct ethhdr));
                    uint16_t op = ntohs(arp->ea_hdr.ar_op);

                    // sender
                    char spa[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, arp->arp_spa, spa, sizeof(spa));

                    // target
                    char tpa[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, arp->arp_tpa, tpa, sizeof(tpa));

                    switch(op)
                    {
                        case ARPOP_REQUEST: {
                            log->info("ARP request: who has {} tell {}\n sender MAC: {}", tpa, spa, parse_mac(arp->arp_sha) );
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
        return {};
    }
private:

};


#endif  // NETLEARN_DUMMY_AF_HPP
