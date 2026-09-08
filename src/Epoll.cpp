//
// Created by tomaszp on 7.09.2026.
//

#include "Epoll.h"
std::expected<net::Epoll, std::error_code> net::Epoll::create() noexcept
{
    int fd = ::epoll_create1(EPOLL_CLOEXEC);
    if (fd == -1)
    {
        return std::unexpected(std::error_code(errno, std::system_category()));
    }
    return Epoll{fd};
}
std::error_code net::Epoll::add(const int fd)
{
    epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.fd = fd;
    if (epoll_ctl(epfd_, EPOLL_CTL_ADD, fd, &ev) < 0)
    {
        return {errno, std::system_category()};
    }
    return {};
}
int net::Epoll::wait(epoll_event* events, const int max, const int timeout)
{
    return epoll_wait(epfd_, events, max, timeout);
}