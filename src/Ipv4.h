//
// Created by tomaszp on 20.08.2026.
//

#pragma once
#include <cstdint>
#include <string>
#include <format>
#include <arpa/inet.h>
#include <fmt/format.h>
namespace net
{

class Ipv4
{
    uint32_t host_order_;
    public:
    constexpr  explicit Ipv4() {host_order_ = 0;};
    static std::expected<Ipv4, std::error_code> from_string(std::string_view s)
    {
        uint32_t result = 0;
        int count = 0;

        while (!s.empty())
        {
            if (count == 4)
            {
                return std::unexpected(
                    std::make_error_code(std::errc::invalid_argument));
                //("Too many octets")));
            }
            const size_t dot = s.find('.');
            const std::string_view part = s.substr(0, dot);
            if (part.empty())
            {
                return std::unexpected(
                std::make_error_code(std::errc::invalid_argument));
                //("empty octet")));
            }
            unsigned value;
            auto [ptr, ec] = std::from_chars(part.begin(), part.end(), value);
            if (ec != std::errc{} || ptr != part.end() || value > 255)
            {
                return std::unexpected(
                 std::make_error_code(std::errc::invalid_argument));
                //("Unrecognized character")));
            }

            result = (result << 8) | value;
            ++count;

            if (dot == std::string_view::npos) break;
            s.remove_prefix(dot + 1);
            if (s.empty())
            {
                return std::unexpected(
                std::make_error_code(std::errc::invalid_argument));
                //("1.2.3. ")));
            }
        }
        if(count != 4)
        {
            return std::unexpected(
            std::make_error_code(std::errc::invalid_argument));
            //("")));
        }
        return Ipv4(result);
    }
    constexpr explicit Ipv4(const uint32_t host) : host_order_(host) {}
    static Ipv4 from_octets(const uint8_t a,const uint8_t b,const uint8_t c, uint8_t d) {
        return Ipv4((a<<24)|(b<<16)|(c<<8)|d);
    }
    static Ipv4 from_network(const uint32_t be) { return Ipv4(ntohs(be)); }  // from SIOCGIFADDR
    std::array<uint8_t, 4> get_array() const { return std::array<uint8_t, 4>{
        static_cast<uint8_t>(host_order_>>24),
        static_cast<uint8_t>(host_order_>>16),
        static_cast<uint8_t>(host_order_>>8),
        static_cast<uint8_t>(host_order_)};
    }
    uint32_t host() const { return host_order_; }
    Ipv4 operator+(const uint32_t n) const { return Ipv4(host_order_ + n); }
};

}  // namespace net
template<>
struct fmt::formatter<net::Ipv4> : fmt::formatter<std::string_view>
{
    auto format(const net::Ipv4& ip, fmt::format_context& ctx) const
    {
        const auto num_addr = ip.host();
        return fmt::format_to(ctx.out(), "{}.{}.{}.{}",
            (num_addr >> 24) & 0xff, (num_addr >> 16) & 0xff,
            (num_addr >> 8)  & 0xff,  num_addr        & 0xff);
    }
};