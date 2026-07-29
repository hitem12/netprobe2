//
// Created by tomaszp on 29.07.2026.
//
#include <gtest/gtest.h>
#include "IPv4Header.h"
#include "helpers/AsHex.h"
using namespace net;
using ::testing::ElementsAreArray;

IPv4Header baseHeader()
{
    IPv4Header ip4h;
    ip4h.hlen = 0x5;
    ip4h.typeOfService = 0x00;
    ip4h.totalLength = 0x003c;
    ip4h.packetId = 0x1c46;
    ip4h.ttl = 0x40;
    ip4h.protocol = 0x06;
    ip4h.sourceIP = 0xc0a8010a;
    ip4h.destinationIP = 0xc0a80101;
    return ip4h;
}

TEST(IPv4Header, base)
{
    PacketBuffer buf;
    IPv4Header ip4h;

    ip4h.hlen = 0x5;
    ip4h.typeOfService = 0x00;
    ip4h.totalLength = 0x003c;
    ip4h.packetId = 0x1c46;
    ip4h.flags.df = 0x1;
    ip4h.flags.mf = 0x0;
    ip4h.flags.res = 0x0;
    ip4h.flags.fragmentOffset = 0x0;
    ip4h.ttl = 0x40;
    ip4h.protocol = 0x06;
    ip4h.headerChecksum = 0x9b1a;
    ip4h.sourceIP = 0xc0a8010a;
    ip4h.destinationIP = 0xc0a80101;
    ip4h.serialize(buf);
    EXPECT_EQ(buf.view().size(), 20);
    std::vector<uint8_t> expected = {
        0x45, 0x00, 0x00, 0x3c,
        0x1c, 0x46, 0x40, 0x00,
        0x40, 0x06, 0x9b, 0x1a,
        0xc0, 0xa8, 0x01, 0x0a,
        0xc0, 0xa8, 0x01, 0x01,
    };
    EXPECT_THAT(AsHex(buf.view()), ElementsAreArray(AsHex(expected)));
}



TEST(IPv4Header, flagsMoreFragmentsOnly)
{
    PacketBuffer buf;
    IPv4Header ip4h = baseHeader();
    ip4h.flags.res = 0x0;
    ip4h.flags.df = 0x0;
    ip4h.flags.mf = 0x1;
    ip4h.flags.fragmentOffset = 0x0000;
    ip4h.headerChecksum = 0xbb1a;
    ip4h.serialize(buf);
    EXPECT_EQ(buf.view().size(), 20);
    std::vector<uint8_t> expected = {
        0x45, 0x00, 0x00, 0x3c,
        0x1c, 0x46, 0x20, 0x00,   // <- 0x2000: tylko bit MF
        0x40, 0x06, 0xbb, 0x1a,
        0xc0, 0xa8, 0x01, 0x0a,
        0xc0, 0xa8, 0x01, 0x01,
    };
    EXPECT_THAT(AsHex(buf.view()), ElementsAreArray(AsHex(expected)));
}

TEST(IPv4Header, flagsFragmentOffsetMax)
{
    PacketBuffer buf;
    IPv4Header ip4h = baseHeader();
    ip4h.flags.res = 0x0;
    ip4h.flags.df = 0x0;
    ip4h.flags.mf = 0x0;
    ip4h.flags.fragmentOffset = 0x1fff;   // wszystkie 13 bitów
    ip4h.headerChecksum = 0xbb1b;
    ip4h.serialize(buf);
    EXPECT_EQ(buf.view().size(), 20);
    std::vector<uint8_t> expected = {
        0x45, 0x00, 0x00, 0x3c,
        0x1c, 0x46, 0x1f, 0xff,   // <- 0x1FFF: offset nie wchodzi w bity flag
        0x40, 0x06, 0xbb, 0x1b,
        0xc0, 0xa8, 0x01, 0x0a,
        0xc0, 0xa8, 0x01, 0x01,
    };
    EXPECT_THAT(AsHex(buf.view()), ElementsAreArray(AsHex(expected)));
}

    TEST(IPv4Header, flagsAllSetWithMaxOffset)
    {
        PacketBuffer buf;
        IPv4Header ip4h = baseHeader();
        ip4h.flags.res = 0x0;
        ip4h.flags.df = 0x1;
        ip4h.flags.mf = 0x1;
        ip4h.flags.fragmentOffset = 0x1fff;
        ip4h.headerChecksum = 0x5b1b;
        ip4h.serialize(buf);
        EXPECT_EQ(buf.view().size(), 20);
        std::vector<uint8_t> expected = {
            0x45, 0x00, 0x00, 0x3c,
            0x1c, 0x46, 0x7f, 0xff,   // <- 0x7FFF: DF|MF|offset, bit 15 (res) czysty
            0x40, 0x06, 0x5b, 0x1b,
            0xc0, 0xa8, 0x01, 0x0a,
            0xc0, 0xa8, 0x01, 0x01,
        };
        EXPECT_THAT(AsHex(buf.view()), ElementsAreArray(AsHex(expected)));
    }
    TEST(IPv4Header, flagsReservedBit)
    {
        PacketBuffer buf;
        IPv4Header ip4h = baseHeader();
        ip4h.flags.res = 0x1;
        ip4h.flags.df = 0x0;
        ip4h.flags.mf = 0x0;
        ip4h.flags.fragmentOffset = 0x0000;
        ip4h.headerChecksum = 0x5b1a;
        ip4h.serialize(buf);
        EXPECT_EQ(buf.view().size(), 20);
        std::vector<uint8_t> expected = {
            0x45, 0x00, 0x00, 0x3c,
            0x1c, 0x46, 0x80, 0x00,   // <- 0x8000: tylko bit rezerwowany
            0x40, 0x06, 0x5b, 0x1a,
            0xc0, 0xa8, 0x01, 0x0a,
            0xc0, 0xa8, 0x01, 0x01,
        };
        EXPECT_THAT(AsHex(buf.view()), ElementsAreArray(AsHex(expected)));
    }

TEST(IPv4Header, withRouterAlertOption)
{
    PacketBuffer buf;
    IPv4Header ip4h = baseHeader();
    ip4h.hlen = 0x6;              // 6 słów = 24 bajty nagłówka
    ip4h.totalLength = 0x0040;
    ip4h.flags.res = 0x0;
    ip4h.flags.df = 0x1;
    ip4h.flags.mf = 0x0;
    ip4h.flags.fragmentOffset = 0x0000;
    ip4h.headerChecksum = 0x0612;
    // Zakładam API dodania opcji; dostosuj do swojej reprezentacji Ipv4Options:
    const std::array<uint8_t, 4> routerAlert = {0x94, 0x04, 0x00, 0x00};
    ip4h.options.insert(ip4h.options.end(), routerAlert.begin(), routerAlert.end());   // <- lub odpowiednik w Twoim modelu

    ip4h.serialize(buf);
    EXPECT_EQ(buf.view().size(), 24);
    std::vector<uint8_t> expected = {
        0x46, 0x00, 0x00, 0x40,   // IHL=6
        0x1c, 0x46, 0x40, 0x00,
        0x40, 0x06, 0x06, 0x12,
        0xc0, 0xa8, 0x01, 0x0a,
        0xc0, 0xa8, 0x01, 0x01,
        0x94, 0x04, 0x00, 0x00,   // opcja Router Alert, wyrównana do słowa
    };
    EXPECT_THAT(AsHex(buf.view()), ElementsAreArray(AsHex(expected)));
}