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



class Forge
{
public:
    static std::expected<void, std::error_code> forge(const SocketCtl & socket)
    {
        const auto log = Logger::get();
        const int fd = socket.get();


        auto info = socket.get_socker_info();
        log->info("{}", info);
        return {};
    }


};

#endif  // NETLEARN_FORGE_H
