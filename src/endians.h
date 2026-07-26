//
// Created by tomaszp on 26.07.2026.
//

#ifndef NETLEARN_ENDIANS_H
#define NETLEARN_ENDIANS_H
#include <cstdint>
namespace net
{
    inline void put_be16(uint8_t* p, uint16_t v)
    {
        p[0] = static_cast<uint8_t>(v>>8);
        p[1] = static_cast<uint8_t>(v);

    }
    inline void put_be32(uint8_t* p, uint32_t v)
    {
        p[0] = static_cast<uint8_t>(v>>24);
        p[1] = static_cast<uint8_t>(v>>16);
        p[2] = static_cast<uint8_t>(v>>8);
        p[3] = static_cast<uint8_t>(v);
    }
inline void put_be64(uint8_t* p, uint64_t v)
    {
        p[0] = static_cast<uint8_t>(v>>56);
        p[1] = static_cast<uint8_t>(v>>48);
        p[2] = static_cast<uint8_t>(v>>40);
        p[3] = static_cast<uint8_t>(v>>32);
        p[4] = static_cast<uint8_t>(v>>24);
        p[5] = static_cast<uint8_t>(v>>16);
        p[6] = static_cast<uint8_t>(v>>8);
        p[7] = static_cast<uint8_t>(v);
    }
inline uint16_t get_be16(const uint8_t* p)
    {
        return static_cast<uint16_t>(p[0]) << 8| p[1];
    }
inline uint32_t get_be32(const uint8_t* p)
    {
        return  static_cast<uint32_t>(p[0] << 24) |
                static_cast<uint32_t>(p[1]) << 16 |
                static_cast<uint32_t> (p[2]) << 8
                | p[3];
    }
inline uint64_t get_be64(const uint8_t* p)
    {
        return  static_cast<uint64_t>(p[0]) << 56 |
                static_cast<uint64_t>(p[1]) << 48 |
                static_cast<uint64_t>(p[2]) << 40 |
                static_cast<uint64_t>(p[3]) << 32 |
                static_cast<uint64_t>(p[4]) << 24 |
                static_cast<uint64_t>(p[5]) << 16 |
                static_cast<uint64_t>(p[6]) << 8 |
                p[7];
    }
}
#endif  // NETLEARN_ENDIANS_H
