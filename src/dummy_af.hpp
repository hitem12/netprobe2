//
// Created by tomaszp on 8.05.2026.
//
#pragma once
#ifndef NETLEARN_DUMMY_AF_HPP
#define NETLEARN_DUMMY_AF_HPP
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <unistd.h>

#include <expected>
#include <system_error>
#include <print>
#include <string>
#include <chrono>
#include "logger.hpp"
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

class dummy_af
{
    static std::string print_mac(std::span<uint8_t> mac)
    {
        return std::format("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
public:
    static std::expected<bool, std::error_code> ala(const std::string_view interface, const size_t packet_count)
    {
        const auto log = Logger::get();
        const int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (!fd){ return std::unexpected{std::error_code{errno, std::generic_category()}};}

        struct ifreq ifr{};
        strncpy(ifr.ifr_name, interface.data(), IFNAMSIZ - 1);
        ioctl(fd, SIOCGIFINDEX, &ifr);

        struct sockaddr_ll addr{};
        addr.sll_family   = AF_PACKET;
        addr.sll_protocol = htons(ETH_P_ALL);
        addr.sll_ifindex  = ifr.ifr_ifindex;

        if (bind(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)))
        { return std::unexpected{std::error_code{errno, std::generic_category()}};}
        // uint8_t buf[2048];

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
            msgvec[i].msg_hdr.msg_name = &name_buf[i];
            msgvec[i].msg_hdr.msg_namelen = sizeof(name_buf[i]);
            msgvec[i].msg_hdr.msg_iov        = &iovecs[i];
            msgvec[i].msg_hdr.msg_iovlen     = 1;
            msgvec[i].msg_hdr.msg_control    = cmsg_bufs[i];
            msgvec[i].msg_hdr.msg_controllen = sizeof(cmsg_bufs[i]);
        }

            int received = recvmmsg(fd, msgvec, packet_count, 0, NULL);
            if (received < 0) { return std::unexpected{std::error_code{errno, std::generic_category()}};}
            log->debug("received {}", received);
            for (int i = 0; i < received; ++i)
            {

                sockaddr_ll* name = reinterpret_cast<sockaddr_ll*>(msgvec[i].msg_hdr.msg_name);
                log->info("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                    name->sll_addr[0], name->sll_addr[1], name->sll_addr[2],
                    name->sll_addr[3], name->sll_addr[4], name->sll_addr[5]);
            }

        const struct packet_mreq mr = {
            .mr_ifindex = ifr.ifr_ifindex,
            .mr_type    = PACKET_MR_PROMISC,
        };
        setsockopt(fd, SOL_PACKET, PACKET_DROP_MEMBERSHIP, &mr, sizeof(mr));
        close(fd);
        return true;
    }
};
#endif  // NETLEARN_DUMMY_AF_HPP
