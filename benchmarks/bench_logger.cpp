#include <benchmark/benchmark.h>
#include "logger.hpp"

// Benchmark logging performance
static void BenchmarkLogInfo(benchmark::State& state) {
    auto logger = Logger::get();
    for (auto _ : state) {
        logger->info("Benchmark test message");
    }
}
BENCHMARK(BenchmarkLogInfo);

// Benchmark formatted logging
static void BenchmarkLogFormatted(benchmark::State& state) {
    auto logger = Logger::get();
    int counter = 0;
    for (auto _ : state) {
        logger->info("Message with number: {}", counter++);
    }
}
BENCHMARK(BenchmarkLogFormatted);

// Benchmark error logging
static void BenchmarkLogError(benchmark::State& state) {
    auto logger = Logger::get();
    for (auto _ : state) {
        logger->error("Error message in benchmark");
    }
}
BENCHMARK(BenchmarkLogError);

BENCHMARK_MAIN();
