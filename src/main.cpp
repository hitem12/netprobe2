#include <spdlog/spdlog.h>
#include <CLI/CLI.hpp>

#include "EthernetHeader.h"
#include "Forge.h"
#include "Sniffer.hpp"
#include "SocketCtl.h"
#include "logger.hpp"

int main(int argc, char** argv)
{
    // Initialize logger
    auto logger = Logger::get();

    logger->info("NetLearn application started");

    // Setup CLI
    CLI::App app{"NetLearn - Network Packet Analysis Tool"};
    app.require_subcommand(1);

    const auto sniffer_app = app.add_subcommand("sniff", "Capture packet tool");
    const auto forge_app = app.add_subcommand("forge", "Create packet and send tool");

    sniffer_app->fallthrough();
    forge_app->fallthrough();

    std::string interface;
    app.add_option("-i,--interface", interface, "Network interface to capture on");


    int packet_count = 1;
    app.add_option("-c,--count", packet_count, "Number of packets to capture");

    bool verbose = false;
    app.add_flag("-v,--verbose", verbose, "Enable verbose output");
    net::ForgeArgs forge_args;

    const std::map<std::string, net::EthernetType> ether_type_map{
            {"ARP", net::EthernetType::ARP},
            {"IPv4", net::EthernetType::IPv4},
        };
    forge_app->add_option_function<std::string>("--dst-mac",
        [&forge_args](const std::string &s)
        {
            const auto result = serialize_mac(s);
            if (!result.has_value())
            {
                throw CLI::ValidationError("--dst-mac", "invalid MAC '" + s + "', expected xx:xx:xx:xx:xx:xx");
            }
            forge_args.dst_mac = result.value();
        }, "Destination MAC address")
    ->required();
    forge_app->add_option("--ethertype", forge_args.eth_type
        , "Ethernet type" )
        ->required()
        ->transform(CLI::CheckedTransformer(ether_type_map, CLI::ignore_case));
    forge_app->add_option_function<std::string>("--ip4", [&forge_args](const std::string & s)
    {
        const auto result =  net::Ipv4::from_string(s);
        if (!result.has_value())
        {
                throw CLI::ValidationError("--ip4", result.error().message());
        }
        forge_args.ip4_addr = result.value();
    }, "Destination ip adress" )
        ->required();
    bool dry_run = false;
    forge_app->add_flag("--dry-run", dry_run, "Print frame dont send it");
    sniffer_app->callback([&](){
        if (interface.empty()) {
            interface = "wlan0";
        }
        const auto socket_ctl = std::make_unique<SocketCtl>();
        if (const auto status = socket_ctl->open_socket(interface); !status)
        {
            logger->error("Failed to initialize: {}", status.error().message());

        }
        auto snif = Sniffer();
        if (const auto status = snif.sniff(*socket_ctl, packet_count); !status)
        {
            logger->error("Sniff fail: {}", status.message());
        }
        socket_ctl->close_socket();
    });
    forge_app->callback([&]()
    {
        if (interface.empty()) {
           interface = "wlan0";
       }
       const auto socket_ctl = std::make_unique<SocketCtl>();
       auto status = socket_ctl->open_socket(interface);
       if (!status) [[unlikely]]
       {
           logger->error("Failed to initialize: {}", status.error().message());
            return;
       }
        logger->debug("{}", socket_ctl->get_socker_info());
        logger->debug("ask {} about {}", parsers::
            parse_mac(forge_args.dst_mac), forge_args.ip4_addr);
        const auto s_forge = net::Forge::forge(*socket_ctl, forge_args);
       if (!s_forge) [[unlikely]]
        {
            logger->error("Failed to forge: {}", status.error().message());
        }
        logger->debug(s_forge.value().to_string());
        if (const auto error = socket_ctl->send(s_forge.value()))
        {
            auto er = error.value();
            std::string message;
            switch (er.value())
            {
                case EPERM:     // brak CAP_NET_RAW
                    message = "Missing CAP_NET_RAW";
                    break;
                case EMSGSIZE:  // ramka > MTU — walidacja z 1.2 powinna to złapać WCZEŚNIEJ
                    message = "Frame bigger then MTU";
                    break;
                case ENETDOWN:  // interfejs down
                    message = "Interface down";
                case ENXIO:     // zły ifindex
                    message = "bad ifindex";
                case ENOBUFS:
                    message = "ENOBUFS";
                default:
                    message = std::to_string(er.value());
            }
           logger->error("Failed to send: {} {}", message, er.message());
        }
    });
    CLI11_PARSE(app, argc, argv);
    logger->info("Interface: {}", interface);

    if (verbose) {
        logger->set_level(spdlog::level::trace);
        logger->info("Verbose mode enabled");
    }

    if (interface.empty()) {
        interface = "wlan0";
    }




    return 0;
}
