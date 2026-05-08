#include <gtest/gtest.h>
#include "logger.hpp"

class LoggerTest : public ::testing::Test {
protected:
    void SetUp() override {
        logger = Logger::get();
    }

    std::shared_ptr<spdlog::logger> logger;
};

TEST_F(LoggerTest, LoggerExists) {
    EXPECT_NE(logger, nullptr);
}

TEST_F(LoggerTest, LoggerName) {
    EXPECT_EQ(logger->name(), "netlearn");
}

TEST_F(LoggerTest, LoggerLevel) {
    EXPECT_EQ(logger->level(), spdlog::level::debug);
}

TEST_F(LoggerTest, CanLogInfoMessage) {
    EXPECT_NO_THROW({
        logger->info("Test message");
    });
}

TEST_F(LoggerTest, CanLogErrorMessage) {
    EXPECT_NO_THROW({
        logger->error("Error message");
    });
}

TEST_F(LoggerTest, CanLogWithFormat) {
    EXPECT_NO_THROW({
        logger->info("Test with number: {}", 42);
    });
}
