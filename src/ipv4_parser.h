//
// Created by dev on 5/21/26.
//

#ifndef NETLEARN_IPV4_PARSER_H
#define NETLEARN_IPV4_PARSER_H
#include <cstdint>
#include <string>
#include <netinet/in.h>
#include <linux/ip.h>
#include <arpa/inet.h>
#include <print>
#include <string>
#include <format>
namespace frame
{

class ipv4_parser
{
public:
    static std::string log_frame(const struct iphdr * hdr)
    {
        char src_str[INET_ADDRSTRLEN];
        char dst_str[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &hdr->saddr, src_str, sizeof(src_str));
        inet_ntop(AF_INET, &hdr->daddr, dst_str, sizeof(dst_str));

        return std::format("ihl: {}, version: {}, srd: {}, dst: {}, protocol: {}", hdr->ihl, hdr->version,
            src_str, dst_str, get_protocol_name(hdr->protocol));


    }
private:
    static constexpr std::string_view get_protocol_name(const uint8_t &protocol)
    {
        switch (protocol)
        {
            case IPPROTO_TCP: return "TCP";
            case IPPROTO_UDP: return "UDP";
            case IPPROTO_ICMP: return "ICMP";
            case IPPROTO_RAW: return "RAW";
            case IPPROTO_ICMPV6: return "ICMPV6";
            case IPPROTO_IPV6: return "IPV6";
            case IPPROTO_GRE: return "GRE";
            case IPPROTO_ROUTING: return "ROUTING";
                default: return "UNKNOWN";
        }
    }
};

}  // namespace frame

#endif  // NETLEARN_IPV4_PARSER_H
