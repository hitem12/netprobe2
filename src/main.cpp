#include <spdlog/spdlog.h>
#include <CLI/CLI.hpp>
#include "Sniffer.hpp"
#include  "Forge.h"
#include "SocketCtl.h"
#include "logger.hpp"

int main(int argc, char** argv) {
    // Initialize logger
    auto logger = Logger::get();

    logger->info("NetLearn application started");

    // Setup CLI
    CLI::App app{"NetLearn - Network Packet Analysis Tool"};
    app.require_subcommand(1);

    auto sniffer_app = app.add_subcommand("sniff", "Capture packet tool");
    auto forge_app = app.add_subcommand("forge", "Create packet and send tool");

    sniffer_app->fallthrough();
    forge_app->fallthrough();

    std::string interface;
    app.add_option("-i,--interface", interface, "Network interface to capture on");


    int packet_count = 1;
    app.add_option("-c,--count", packet_count, "Number of packets to capture");

    bool verbose = false;
    app.add_flag("-v,--verbose", verbose, "Enable verbose output");
    sniffer_app->callback([&](){
        if (interface.empty()) {
            interface = "wlan0";
        }
        const auto socket_ctl = std::make_unique<SocketCtl>();
        auto status = socket_ctl->open_socket(interface);
        if (!status)
        {
            logger->error("Failed to initialize: {}", status.error().message());

        }
        auto snif = Sniffer();
        status = snif.sniff(*socket_ctl, packet_count);
        if (!status)
        {
            logger->error("Sniff fail: {}", status.error().message());
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
        status = Forge::forge(*socket_ctl);
        if (!status) [[unlikely]]
        {
            logger->error("Failed to forge: {}", status.error().message());
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
