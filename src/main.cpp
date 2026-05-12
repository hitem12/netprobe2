#include <CLI/CLI.hpp>
#include <spdlog/spdlog.h>
#include "logger.hpp"
#include "dummy_af.hpp"
int main(int argc, char** argv) {
    // Initialize logger
    auto logger = Logger::get();

    logger->info("NetLearn application started");

    // Setup CLI
    CLI::App app{"NetLearn - Network Packet Analysis Tool"};

    std::string interface;
    app.add_option("-i,--interface", interface, "Network interface to capture on");

    int packet_count = 1;
    app.add_option("-c,--count", packet_count, "Number of packets to capture");

    bool verbose = false;
    app.add_flag("-v,--verbose", verbose, "Enable verbose output");
    bool z = false;
    app.add_option("-z",z,  "zupa");

    CLI11_PARSE(app, argc, argv);

    if (verbose) {
        logger->set_level(spdlog::level::trace);
        logger->info("Verbose mode enabled");
    }

    if (interface.empty()) {
        interface = "wlan0";
    }
    logger->info("Interface: {}", interface);
    auto status = dummy_af::ala(interface, packet_count);
    if (!status)
    {
        logger->error("Failed to initialize: {}", status.error().message());
    }

    logger->info("Packet count: {}", packet_count);

    return 0;
}
