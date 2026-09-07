//
// Created by tomaszp on 7.09.2026.
//

#include "Epoll.h"
std::error_code net::Epoll::add(const int fd, const uint32_t events)
{
    epoll_event ev{};
    ev.events = events;
    ev.data.fd = fd;
    if (epoll_ctl(epfd_, EPOLL_CTL_ADD, fd, &ev) < 0)
    {
        return std::error_code(errno, std::system_category());
    }
    return {};
}
int net::Epoll::wait(epoll_event* events, const int max, const int timeout)
{
    return epoll_wait(epfd_, events, max, timeout);
}