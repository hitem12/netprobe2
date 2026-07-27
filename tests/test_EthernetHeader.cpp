//
// Created by tomaszp on 27.07.2026.
//
#include <gtest/gtest.h>
#include "EthernetHeader.h"
#include <gmock/gmock.h>
#include <iomanip>
using ::testing::ElementsAreArray;


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
using namespace net;
TEST(EthernerHeader, serialize)
{
    PacketBuffer buf;
    EthernetHeader eh;
    eh.dst_mac = parsers::serialize_mac("11:22:33:44:55:66").value();
    eh.src_mac = parsers::serialize_mac("aa:bb:cc:dd:ee:ff").value();
    eh.type = EthernetType::ARP;
    eh.serialize(buf);
    EXPECT_EQ(buf.view().size(), 14);
    std::vector<uint8_t> expected = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x08, 0x06};
    EXPECT_THAT(AsHex(buf.view()), ElementsAreArray(AsHex(expected)));
}
TEST(EthernerHeader, serializeWithTag)
{
    PacketBuffer buf;
    EthernetHeader eh;
    eh.dst_mac = parsers::serialize_mac("2e:7c:6c:19:7a:ae").value();
    eh.src_mac = parsers::serialize_mac("aa:7c:6c:ff:12:ea").value();
    VLAN_TAG tag;
    tag.tci.VID =  0xABC;
    tag.tci.PCP = 0b010;
    tag.tci.DEI = 0b0;
    eh.vlan_tag.emplace(tag);
    eh.type = EthernetType::ARP;
    eh.serialize(buf);
    EXPECT_EQ(buf.view().size(), 18);
    std::vector<uint8_t> expected = {0x2e, 0x7c, 0x6c, 0x19, 0x7a, 0xae,
        0xaa, 0x7c, 0x6c, 0xff, 0x12, 0xea,
        0x81, 0x00, 0x4A, 0xBC,
        0x08, 0x06};
    EXPECT_THAT(AsHex(buf.view()), ElementsAreArray(AsHex(expected)));
}

TEST(EthernerHeader, serializeWithTag_VIDMax)
{
    PacketBuffer buf;
    EthernetHeader eh;
    eh.dst_mac = parsers::serialize_mac("2e:7c:6c:19:7a:ae").value();
    eh.src_mac = parsers::serialize_mac("aa:7c:6c:ff:12:ea").value();
    VLAN_TAG tag;
    tag.tci.VID =  0xFFF;
    tag.tci.PCP = 0b0;
    tag.tci.DEI = 0b0;
    eh.vlan_tag.emplace(tag);
    eh.type = EthernetType::ARP;
    eh.serialize(buf);
    EXPECT_EQ(buf.view().size(), 18);
    std::vector<uint8_t> expected = {0x2e, 0x7c, 0x6c, 0x19, 0x7a, 0xae,
        0xaa, 0x7c, 0x6c, 0xff, 0x12, 0xea,
        0x81, 0x00, 0x0F, 0xFF,
        0x08, 0x06};
    EXPECT_THAT(AsHex(buf.view()), ElementsAreArray(AsHex(expected)));
}

TEST(EthernerHeader, serializeWithTag_PCPMax)
{
    PacketBuffer buf;
    EthernetHeader eh;
    eh.dst_mac = parsers::serialize_mac("2e:7c:6c:19:7a:ae").value();
    eh.src_mac = parsers::serialize_mac("aa:7c:6c:ff:12:ea").value();
    VLAN_TAG tag;
    tag.tci.VID =  0x0;
    tag.tci.PCP = 0b111;
    tag.tci.DEI = 0b0;
    eh.vlan_tag.emplace(tag);
    eh.type = EthernetType::ARP;
    eh.serialize(buf);
    EXPECT_EQ(buf.view().size(), 18);
    std::vector<uint8_t> expected = {0x2e, 0x7c, 0x6c, 0x19, 0x7a, 0xae,
        0xaa, 0x7c, 0x6c, 0xff, 0x12, 0xea,
        0x81, 0x00, 0xE0, 0x00,
        0x08, 0x06};
    EXPECT_THAT(AsHex(buf.view()), ElementsAreArray(AsHex(expected)));
}

TEST(EthernerHeader, serializeWithTag_TCIMAX)
{
    PacketBuffer buf;
    EthernetHeader eh;
    eh.dst_mac = parsers::serialize_mac("2e:7c:6c:19:7a:ae").value();
    eh.src_mac = parsers::serialize_mac("aa:7c:6c:ff:12:ea").value();
    VLAN_TAG tag;
    tag.tci.VID =  0xFFF;
    tag.tci.PCP = 0b111;
    tag.tci.DEI = 0b1;
    eh.vlan_tag.emplace(tag);
    eh.type = EthernetType::ARP;
    eh.serialize(buf);
    EXPECT_EQ(buf.view().size(), 18);
    std::vector<uint8_t> expected = {0x2e, 0x7c, 0x6c, 0x19, 0x7a, 0xae,
        0xaa, 0x7c, 0x6c, 0xff, 0x12, 0xea,
        0x81, 0x00, 0xFF, 0xFF,
        0x08, 0x06};
    EXPECT_THAT(AsHex(buf.view()), ElementsAreArray(AsHex(expected)));
}

TEST(EthernerHeader, serializeWithTag_TCIOVER)
{
    PacketBuffer buf;
    EthernetHeader eh;
    eh.dst_mac = parsers::serialize_mac("2e:7c:6c:19:7a:ae").value();
    eh.src_mac = parsers::serialize_mac("aa:7c:6c:ff:12:ea").value();
    VLAN_TAG tag;
    tag.tci.VID =  0xAAAF;
    tag.tci.PCP = 0b1011;
    tag.tci.DEI = 0b11;
    eh.vlan_tag.emplace(tag);
    eh.type = EthernetType::ARP;
    eh.serialize(buf);
    EXPECT_EQ(buf.view().size(), 18);
    std::vector<uint8_t> expected = {0x2e, 0x7c, 0x6c, 0x19, 0x7a, 0xae,
        0xaa, 0x7c, 0x6c, 0xff, 0x12, 0xea,
        0x81, 0x00, 0x7A, 0xAF,
        0x08, 0x06};
    EXPECT_THAT(AsHex(buf.view()), ElementsAreArray(AsHex(expected)));
}