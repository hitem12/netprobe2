//
// Created by tomaszp on 7.09.2026.
//

#pragma once
#include <sys/epoll.h>
#include <unistd.h>
#include  <expected>
#include <system_error>
namespace net
{

class Epoll
{
    int epfd_ {-1};
    explicit Epoll(int epfd) noexcept: epfd_(epfd) { }
public:
    static std::expected<Epoll, std::error_code> create() noexcept
    {
        int fd = ::epoll_create1(EPOLL_CLOEXEC);
        if (fd == -1)
        {
            return std::unexpected(std::error_code(errno, std::system_category()));
        }
        return Epoll{fd};
    }
    ~Epoll() {if (epfd_ != -1) close(epfd_);}
    Epoll(const Epoll&) = delete;
    Epoll& operator=(const Epoll&) = delete;
    Epoll(Epoll&& o) noexcept : epfd_(o.epfd_) { o.epfd_ = -1; }
    Epoll& operator=(Epoll&& o) noexcept {
        if (this != &o) { if (epfd_ >= 0) ::close(epfd_); epfd_ = o.epfd_; o.epfd_ = -1; }
        return *this;
    }
    std::error_code add(const int fd,const uint32_t events);
    int wait(epoll_event* events, const int max, const int timeout);
};

}  // namespace net
