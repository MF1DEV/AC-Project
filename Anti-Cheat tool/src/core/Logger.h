#pragma once

#include <windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <mutex>
#include <chrono>
#include <iomanip>

// LogLevel enum definition
enum class LogLevel : int {
    DEBUG_LEVEL = 0,
    INFO_LEVEL = 1,
    WARNING_LEVEL = 2,
    ERROR_LEVEL = 3
};

class Logger {
private:
    mutable std::mutex logMutex;
    mutable std::ofstream logFile;
    LogLevel currentLevel;

    Logger() : currentLevel(LogLevel::INFO_LEVEL) {
        std::string logPath = "anticheat_" + std::to_string(GetCurrentProcessId()) + ".log";
        logFile.open(logPath, std::ios::app);
        if (!logFile.is_open()) {
            std::cerr << "Warning: Could not open log file: " << logPath << std::endl;
        }
    }

    std::string getCurrentTimestamp() const {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) % 1000;

        std::stringstream ss;
        ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
        ss << '.' << std::setfill('0') << std::setw(3) << ms.count();
        return ss.str();
    }

    std::string levelToString(LogLevel level) const {
        switch (level) {
        case LogLevel::DEBUG_LEVEL: return "DEBUG";
        case LogLevel::INFO_LEVEL: return "INFO";
        case LogLevel::WARNING_LEVEL: return "WARN";
        case LogLevel::ERROR_LEVEL: return "ERROR";
        default: return "UNKNOWN";
        }
    }

public:
    static Logger& getInstance() {
        static Logger instance;
        return instance;
    }

    void log(LogLevel level, const std::string& message) const {
        if (level < currentLevel) return;

        std::lock_guard<std::mutex> lock(logMutex);
        std::string logEntry = "[" + getCurrentTimestamp() + "] [" + levelToString(level) + "] " + message;

        if (logFile.is_open()) {
            logFile << logEntry << std::endl;
            logFile.flush();
        }

        std::cout << logEntry << std::endl;
    }

    void setLogLevel(LogLevel level) {
        currentLevel = level;
    }
};

// Simple logging macros
#define LOG_DEBUG(msg) do { Logger::getInstance().log(LogLevel::DEBUG_LEVEL, std::string(msg)); } while(0)
#define LOG_INFO(msg) do { Logger::getInstance().log(LogLevel::INFO_LEVEL, std::string(msg)); } while(0)
#define LOG_WARNING(msg) do { Logger::getInstance().log(LogLevel::WARNING_LEVEL, std::string(msg)); } while(0)
#define LOG_ERROR(msg) do { Logger::getInstance().log(LogLevel::ERROR_LEVEL, std::string(msg)); } while(0)