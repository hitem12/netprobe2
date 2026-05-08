#include <CLI/CLI.hpp>
#include <spdlog/spdlog.h>
#include "logger.hpp"

int main(int argc, char** argv) {
    // Initialize logger
    auto logger = Logger::get();
    logger->info("NetLearn application started");

    // Setup CLI
    CLI::App app{"NetLearn - Network Packet Analysis Tool"};

    std::string interface;
    app.add_option("-i,--interface", interface, "Network interface to capture on");

    int packet_count = 0;
    app.add_option("-c,--count", packet_count, "Number of packets to capture");

    bool verbose = false;
    app.add_flag("-v,--verbose", verbose, "Enable verbose output");

    CLI11_PARSE(app, argc, argv);

    if (verbose) {
        logger->set_level(spdlog::level::trace);
        logger->info("Verbose mode enabled");
    }

    if (interface.empty()) {
        logger->warn("No interface specified, using default: eth0");
        interface = "eth0";
    }

    logger->info("Interface: {}", interface);
    logger->info("Packet count: {}", packet_count);
    logger->info("Application finished successfully");

    return 0;
}
