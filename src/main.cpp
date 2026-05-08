#include <CLI/CLI.hpp>
#include <string>

int main(int argc, char** argv) {
    // Setup CLI
    CLI::App app{"NetLearn - Network Packet Analysis Tool"};

    std::string interface;
    app.add_option("-i,--interface", interface, "Network interface to capture on");

    int packet_count = 0;
    app.add_option("-c,--count", packet_count, "Number of packets to capture");

    bool verbose = false;
    app.add_flag("-v,--verbose", verbose, "Enable verbose output");

    CLI11_PARSE(app, argc, argv);

    if (interface.empty()) {
        interface = "eth0";
    }

    return 0;
}
