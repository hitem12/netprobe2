//
// Created by tomaszp on 26.07.2026.
//
#include <gtest/gtest.h>
#include "PacketBuffer.h"
#include <gmock/gmock.h>
using namespace net;
using ::testing::ElementsAre;

TEST(PacketBuffer, base)
{
    PacketBuffer pb;
    pb.u8(0x12);
    EXPECT_THAT(pb.view(), ElementsAre(0x12));
}

TEST(PacketBuffer, base16)
{
    PacketBuffer pb;
    pb.be16(0x1234);
    EXPECT_THAT(pb.view(), ElementsAre(0x12, 0x34));
}

TEST(PacketBuffer, base32)
{
    PacketBuffer pb;
    pb.be32(0x12345678);
    EXPECT_THAT(pb.view(), ElementsAre(0x12, 0x34,0x56,0x78));
}
TEST(PacketBuffer, base64)
{
    PacketBuffer pb;
    pb.be64(0x123456789ABCDEF0);
    EXPECT_THAT(pb.view(), ElementsAre(0x12, 0x34,0x56,0x78, 0x9A, 0xBC, 0xDE, 0xF0));
}
TEST(PacketBuffer, few_inserts)
{
    PacketBuffer pb;
    pb.be16(0x1234);
    pb.be32(0x12345678);
    EXPECT_THAT(pb.view(), ElementsAre(0x12, 0x34, 0x12, 0x34,0x56,0x78));
}