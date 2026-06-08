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
    [[nodiscard]] const int* get() const {return &fd_;}
    [[nodiscard]] std::expected<bool, std::error_code> open_socket(std::string_view interface);
    void close_socket();
};

#endif  // NETLEARN_SOCETCTL_H
