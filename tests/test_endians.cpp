//
// Created by tomaszp on 26.07.2026.
//
#include "endians.h"
#include <gtest/gtest.h>

TEST(Endian, put16)
{
    uint8_t out[2];
    uint16_t in {0x0121};
    net::put_be16(out, in);
    EXPECT_EQ(out[0], 0x01u);
    EXPECT_EQ(out[1], 0x21u);
}
TEST(Endian, put32)
{
    uint8_t out[4];
    uint32_t in {0x01213144};
    net::put_be32(out, in);
    EXPECT_EQ(out[0], 0x01u);
    EXPECT_EQ(out[1], 0x21u);
    EXPECT_EQ(out[2], 0x31u);
    EXPECT_EQ(out[3], 0x44u);
}

TEST(Endian, put64)
{
    uint8_t out[8];
    uint64_t in {0x0121314455667788};
    net::put_be64(out, in);
    EXPECT_EQ(out[0], 0x01u);
    EXPECT_EQ(out[1], 0x21u);
    EXPECT_EQ(out[2], 0x31u);
    EXPECT_EQ(out[3], 0x44u);
    EXPECT_EQ(out[4], 0x55u);
    EXPECT_EQ(out[5], 0x66u);
    EXPECT_EQ(out[6], 0x77u);
    EXPECT_EQ(out[7], 0x88u);
}

TEST(Endian, get16)
{
    uint8_t in[2] = {0x01, 0x21};
    EXPECT_EQ(net::get_be16(in), 0x0121);
}

TEST(Endian, get32)
{
    uint8_t in[4] = {0x01, 0x21, 0x33, 0x44};
    EXPECT_EQ(net::get_be32(in), 0x01213344);
}
TEST(Endian, get64)
{
    uint8_t in[8] = {0x01, 0x21, 0x33, 0x44, 0x55, 0x66,0x77, 0x88};
    EXPECT_EQ(net::get_be64(in), 0x0121334455667788);
}