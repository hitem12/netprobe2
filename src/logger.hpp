#pragma once

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <memory>

class Logger {
public:
    static Logger& instance() {
        static Logger logger;
        return logger;
    }

    static std::shared_ptr<spdlog::logger> get() {
        return instance().logger_;
    }

private:
    Logger() {
        logger_ = spdlog::stdout_color_mt("netlearn");
        logger_->set_level(spdlog::level::debug);
        spdlog::set_default_logger(logger_);
    }

    std::shared_ptr<spdlog::logger> logger_;
};
