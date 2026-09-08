//
// Created by tomaszp on 7.09.2026.
//

#pragma once
#include <arpa/inet.h>
#include <cstddef>
#include <array>
namespace net
{
template <size_t N>
class RecvBuffer
{
        std::array<std::array<uint8_t, 2048>,N> data_{};
        alignas(struct cmsghdr) std::array<std::array<char,256>, N> ctrl_{};
        std::array<struct iovec, N>       iov_{};
        std::array<struct sockaddr_in, N> name_buf_ {};
        std::array<struct mmsghdr, N> msgvec_;

    public:
    RecvBuffer() {rebind();}
    RecvBuffer(const RecvBuffer&) = delete;
    RecvBuffer& operator=(const RecvBuffer&) = delete;
    void rebind() {
        for (size_t i = 0; i <N; ++i)
        {
            iov_[i] = { data_[i].data(), data_[i].size() };
            msgvec_[i].msg_hdr = {};
            msgvec_[i].msg_hdr.msg_name       = &name_buf_[i];
            msgvec_[i].msg_hdr.msg_iov        = &iov_[i];
            msgvec_[i].msg_hdr.msg_iovlen     = 1;
            msgvec_[i].msg_hdr.msg_control    = ctrl_[i].data();
            reset(i);
        }

    }
    void reset()
    {
        for (size_t i = 0; i <N; ++i)
        {
            reset(i);
        }
    }
    void reset(const size_t index) {
        msgvec_[index].msg_hdr.msg_namelen    = sizeof(name_buf_[index]);
        msgvec_[index].msg_hdr.msg_controllen = ctrl_[index].size();
        msgvec_[index].msg_hdr.msg_flags      = 0;
    }
    msghdr* get_msghdr(const size_t index = 0) {return &msgvec_[index].msg_hdr;}
    mmsghdr* get_mmsghdr() {return msgvec_.data();}
};

}  // namespace net
