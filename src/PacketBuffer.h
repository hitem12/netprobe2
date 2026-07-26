//
// Created by tomaszp on 26.07.2026.
//

#ifndef NETLEARN_PACKETBUFFER_H
#define NETLEARN_PACKETBUFFER_H
#pragma once

#include "endians.h"
#include <span>
#include <vector>
namespace net
{

class PacketBuffer
{
    std::vector<uint8_t> buffer_;
public:
    explicit PacketBuffer(const size_t reserve = 1518) { buffer_.reserve(reserve); }

    void u8(const uint8_t v);
    void be16(const uint16_t v);
    void be32(const uint32_t v);
    void be64(const uint64_t v);
    void mac(const std::span<const uint8_t, 6> addr);
    void bytes(const std::span<const uint8_t> src);
    const uint8_t* data() const noexcept { return buffer_.data(); }
    size_t size() const noexcept { return buffer_.size(); }
    std::span<const uint8_t> view() const noexcept { return buffer_; }
    void clear() noexcept { buffer_.clear(); }
};

}  // namespace net

#endif  // NETLEARN_PACKETBUFFER_H
