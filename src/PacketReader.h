//
// Created by tomaszp on 8.09.2026.
//

#pragma once
#include <span>
#include <format>
#include <cstdint>
namespace net
{

class PacketReader
{
    std::span<const uint8_t> data_;
    size_t pos_ {0};
public:
    explicit PacketReader(const std::span<const uint8_t> data) noexcept : data_(data) {}

    size_t remaining() const noexcept { return data_.size() - pos_; }
    size_t position()  const noexcept { return pos_; }
    bool   empty()     const noexcept { return pos_ >= data_.size(); }

    std::optional<uint8_t> u8() noexcept {
        if (pos_ + 1 > data_.size()) return std::nullopt;
        return data_[pos_++];
    }

    std::optional<uint16_t> be16() noexcept {
        if (pos_ + 2 > data_.size()) return std::nullopt;
        uint16_t v = (static_cast<uint16_t>(data_[pos_]) << 8) | data_[pos_ + 1];
        pos_ += 2;
        return v;
    }

    std::optional<uint32_t> be32() noexcept {
        if (pos_ + 4 > data_.size()) return std::nullopt;
        uint32_t v = (static_cast<uint32_t>(data_[pos_])     << 24) |
                     (static_cast<uint32_t>(data_[pos_ + 1]) << 16) |
                     (static_cast<uint32_t>(data_[pos_ + 2]) <<  8) |
                      static_cast<uint32_t>(data_[pos_ + 3]);
        pos_ += 4;
        return v;
    }

    std::optional<std::span<const uint8_t>> bytes(const size_t n) noexcept {
        if (pos_ + n > data_.size()) return std::nullopt;
        auto s = data_.subspan(pos_, n);
        pos_ += n;
        return s;
    }

     std::optional<std::span<const uint8_t>> mac() noexcept {
        auto s = bytes(6);
        if (!s) return std::nullopt;
        return s;
    }

    bool skip(const size_t n) noexcept {
        if (pos_ + n > data_.size()) return false;
        pos_ += n;
        return true;
    }
};

}  // namespace net
