//
// Created by tomaszp on 27.05.2026.
//

#ifndef NETLEARN_CONTROL_MASSAGE_HEADER_H
#define NETLEARN_CONTROL_MASSAGE_HEADER_H
#include <sys/socket.h>

#include <cstdint>
#include <print>
#include <chrono>
namespace frame
{

class control_massage_header
{
public:
    control_massage_header() = default;
    control_massage_header(const control_massage_header&) = delete;
    control_massage_header(control_massage_header&&) = delete;
    control_massage_header& operator=(const control_massage_header&) = delete;
    control_massage_header& operator=(control_massage_header&&) = delete;
    ~control_massage_header() = default;
    static void parse(struct msghdr *msg)
    {
        for (struct cmsghdr *cm = CMSG_FIRSTHDR(msg);
             cm != nullptr;
             cm = CMSG_NXTHDR(msg, cm))
        {
            if (cm->cmsg_level == SOL_SOCKET &&
            cm->cmsg_type  == SO_TIMESTAMPING)
            {
                struct timespec *ts =
                reinterpret_cast<struct timespec*>(CMSG_DATA(cm));
                struct timespec *best = (ts[2].tv_sec || ts[2].tv_nsec)
                                  ? &ts[2]   // hardware
                                  : &ts[0];  // software — fallback

                auto ts_ns = std::chrono::system_clock::time_point(std::chrono::seconds(ts->tv_sec) + std::chrono::nanoseconds(ts->tv_nsec));
                auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                              ts_ns.time_since_epoch()) % 1'000'000'000;

                std::print("[{:%H:%M:%S}.{:09d}] packet received\n",
                std::chrono::zoned_time{
                    std::chrono::locate_zone("Europe/Warsaw") ,ts_ns},
                    ns.count());
            }
            std::println("agawa");
        }
    }
};

}  // namespace frame

#endif  // NETLEARN_CONTROL_MASSAGE_HEADER_H
