//
// Created by tomaszp on 29.07.2026.
//

#pragma once

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <iomanip>

struct Hex {
    uint8_t v;
    friend bool operator==(Hex, Hex) = default;
};
// GoogleTest finds this via ADL and uses it for every element:
inline void PrintTo(Hex h, std::ostream* os) {
    *os << "0x" << std::uppercase << std::hex
        << std::setw(2) << std::setfill('0') << unsigned(h.v);
}
inline std::vector<Hex> AsHex(std::span<const uint8_t> b) {
    return {b.begin(), b.end()};  // Hex is aggregate-constructible from uint8_t
}