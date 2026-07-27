//
// Created by tomaszp on 27.07.2026.
//
#include <gtest/gtest.h>
#include "EthernetHeader.h"

using namespace net;
TEST(EthernerHeader, serialize)
{
    PacketBuffer buf;
    EthernetHeader eh;
    eh.dst_mac = parsers::serialize_mac("2e:7c:6c:19:7a:ae").value();
    eh.src_mac = parsers::serialize_mac("2e:7c:6c:ff:12:ea").value();
    eh.type = EthernetType::ARP;
    eh.serialize(buf);
}