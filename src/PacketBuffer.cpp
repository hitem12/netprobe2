//
// Created by tomaszp on 26.07.2026.
//

#include "PacketBuffer.h"

namespace net {
void PacketBuffer::u8(const uint8_t v)
{
    buffer_.push_back(v);
}
void PacketBuffer::be16(const uint16_t v)
{
    const size_t off = buffer_.size();
    buffer_.resize(off + 2);
    put_be16(buffer_.data() + off, v);
}
void PacketBuffer::be32(const uint32_t v)
{
    const size_t off = buffer_.size();
    buffer_.resize(off + 4);
    put_be32(buffer_.data() + off, v);
}
void PacketBuffer::be64(const uint64_t v)
{
    const size_t off = buffer_.size();
    buffer_.resize(off + 8);
    put_be64(buffer_.data() + off, v);
}
void PacketBuffer::mac(const std::span<const uint8_t, 6> addr)
{
    buffer_.insert(buffer_.end(), addr.begin(), addr.end());
}
void PacketBuffer::bytes(const std::span<const uint8_t> src)
{
    buffer_.insert(buffer_.end(), src.begin(), src.end());
}
} // net